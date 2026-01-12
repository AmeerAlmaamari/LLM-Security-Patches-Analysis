"""
Tri-Axis Patch Evaluator
"""

import json
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from enum import Enum
from datetime import datetime
from loguru import logger

from failure_analyzer import classify_compilation_error, classify_patch, FailureClassification
from partial_scorer import score_patch, PatchScores


class PatchCategory(Enum):
    """Patch classification categories from paper Table 1."""
    CORRECT_AND_SECURE = "correct_and_secure"  # Secure=Yes, Functional=Yes
    INSECURE = "insecure"                       # Secure=No, Functional=Yes (DANGEROUS)
    BREAKING = "breaking"                       # Secure=Yes, Functional=No
    INSECURE_AND_BREAKING = "insecure_and_breaking"  # Secure=No, Functional=No
    COMPILE_ERROR = "compile_error"             # Failed to compile
    EVALUATION_ERROR = "evaluation_error"       # Error during evaluation


@dataclass
class SecurityResult:
    """Results from security evaluation (Axis 1)."""
    pov_test_passed: Optional[bool] = None  # True if vulnerability FIXED
    compile_success: bool = False
    compile_error: Optional[str] = None
    compile_error_type: Optional[str] = None  # Subcategory: syntax_error, missing_import, etc.
    pov_test_details: Dict = field(default_factory=dict)
    semgrep_cwe_warnings: List[Dict] = field(default_factory=list)
    semgrep_warnings_count: int = 0  # Count of Semgrep warnings on patched code
    vulnerability_fixed: bool = False
    error: Optional[str] = None


@dataclass
class FunctionalityResult:
    """Results from functionality evaluation (Axis 2)."""
    all_tests_passed: bool = False
    tests_run: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    tests_errored: int = 0
    tests_skipped: int = 0
    failed_test_names: List[str] = field(default_factory=list)
    pass_rate: float = 0.0
    error: Optional[str] = None


@dataclass
class RegressionResult:
    """Results from regression analysis (Axis 3)."""
    security_regressions: List[str] = field(default_factory=list)
    functional_regressions: List[str] = field(default_factory=list)
    has_regressions: bool = False
    new_vulnerability_count: int = 0
    broken_test_count: int = 0
    error: Optional[str] = None


@dataclass
class EvaluationResult:
    """Complete evaluation result for a patch."""
    vul_id: str
    model_name: str
    patch_index: int
    patch_file: str
    
    # Tri-axis results
    security: SecurityResult = field(default_factory=SecurityResult)
    functionality: FunctionalityResult = field(default_factory=FunctionalityResult)
    regression: RegressionResult = field(default_factory=RegressionResult)
    
    # Classification (hierarchical)
    category: str = PatchCategory.EVALUATION_ERROR.value
    subcategory: Optional[str] = None  # Detailed failure subcategory
    is_regressive: bool = False
    
    # Continuous scores (new metrics)
    security_score: float = 0.0        # 0.0 to 1.0
    functionality_score: float = 0.0   # 0.0 to 1.0
    srs: float = 0.0                   # Security Repair Score (0.0 to 1.0)
    
    # Metadata
    evaluation_time_ms: float = 0.0
    timestamp: str = ""
    human_baseline_compile_failed: bool = False  # True if human patch couldn't compile
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "vul_id": self.vul_id,
            "model_name": self.model_name,
            "patch_index": self.patch_index,
            "patch_file": self.patch_file,
            "security": asdict(self.security),
            "functionality": asdict(self.functionality),
            "regression": asdict(self.regression),
            "category": self.category,
            "subcategory": self.subcategory,
            "is_regressive": self.is_regressive,
            "security_score": round(self.security_score, 4),
            "functionality_score": round(self.functionality_score, 4),
            "srs": round(self.srs, 4),
            "evaluation_time_ms": self.evaluation_time_ms,
            "timestamp": self.timestamp,
            "human_baseline_compile_failed": self.human_baseline_compile_failed
        }


# CWE to Semgrep rule mapping
CWE_SEMGREP_RULES = {
    "CWE-20": ["p/java", "p/security-audit"],  # Input validation
    "CWE-22": ["p/java", "p/security-audit"],  # Path traversal
    "CWE-78": ["p/command-injection", "p/java"],  # OS command injection
    "CWE-79": ["p/xss", "p/java"],  # XSS
    "CWE-89": ["p/sql-injection", "p/java"],  # SQL injection
    "CWE-94": ["p/java", "p/security-audit"],  # Code injection
    "CWE-113": ["p/java"],  # HTTP response splitting
    "CWE-200": ["p/java", "p/security-audit"],  # Information exposure
    "CWE-264": ["p/java"],  # Permissions
    "CWE-284": ["p/java"],  # Access control
    "CWE-287": ["p/java"],  # Authentication
    "CWE-295": ["p/java"],  # Certificate validation
    "CWE-352": ["p/java"],  # CSRF
    "CWE-400": ["p/java"],  # Resource exhaustion
    "CWE-502": ["p/java", "p/security-audit"],  # Deserialization
    "CWE-611": ["p/java", "p/security-audit"],  # XXE
    "CWE-614": ["p/java"],  # Sensitive cookie
    "CWE-643": ["p/java"],  # XPath injection
    "CWE-674": ["p/java"],  # Uncontrolled recursion
    "CWE-755": ["p/java"],  # Exception handling
    "CWE-776": ["p/java"],  # XML entity expansion
    "CWE-918": ["p/java"],  # SSRF
}


class PatchEvaluator:
    """
    Evaluates patches using the tri-axis evaluation protocol.
    """
    
    def __init__(
        self,
        docker_container: str = "vul4j",
        vul4j_workdir: str = "/vul4j",
        timeout_compile: int = 7200,   # 2 hours - some projects take long to compile
        timeout_test: int = 3600,       # 1 hour - some projects have many tests
        timeout_semgrep: int = 300,     # 5 minutes
        custom_logger = None
    ):
        self.docker_container = docker_container
        self.vul4j_workdir = vul4j_workdir
        self.timeout_compile = timeout_compile
        self.timeout_test = timeout_test
        self.timeout_semgrep = timeout_semgrep
        # Use custom logger if provided, otherwise use default loguru with phase binding
        self.logger = custom_logger if custom_logger else logger.bind(context="EVAL")
    
    def run_docker_command(
        self,
        command: List[str],
        timeout: int = 300,
        cwd: Optional[str] = None
    ) -> Tuple[bool, str, str]:
        """Run a command inside the Docker container."""
        docker_cmd = ["docker", "exec"]
        if cwd:
            docker_cmd.extend(["-w", cwd])
        docker_cmd.append(self.docker_container)
        docker_cmd.extend(command)
        
        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def checkout_vulnerability(self, vul_id: str, checkout_dir: str) -> bool:
        """Checkout a vulnerability to a specific directory."""
        # First clean up any existing checkout
        self.run_docker_command(["rm", "-rf", checkout_dir], timeout=60)
        
        # Checkout the vulnerability
        success, stdout, stderr = self.run_docker_command(
            ["vul4j", "checkout", "--id", vul_id, "-d", checkout_dir],
            timeout=self.timeout_compile
        )
        
        if not success:
            self.logger.error(f"Failed to checkout {vul_id}: {stderr}")
            return False
        
        return True
    
    def apply_patch(
        self,
        patch_file: Path,
        checkout_dir: str,
        vulnerable_file_path: str
    ) -> Tuple[bool, str]:
        """
        Apply a generated patch to the checked-out vulnerability.
        
        The patch file contains the complete fixed Java file.
        We need to replace the vulnerable file with this patched version.
        """
        try:
            # Read the patch content
            patch_content = patch_file.read_text(encoding='utf-8')
            
            # Create a temp file in the container
            temp_patch_path = f"/tmp/patch_{patch_file.stem}.java"
            
            # Write patch to temp file using docker cp
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False, encoding='utf-8') as f:
                f.write(patch_content)
                temp_local_path = f.name
            
            # Copy to container
            copy_cmd = ["docker", "cp", temp_local_path, f"{self.docker_container}:{temp_patch_path}"]
            result = subprocess.run(copy_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return False, f"Failed to copy patch to container: {result.stderr}"
            
            # Move patch to target location
            target_path = f"{checkout_dir}/{vulnerable_file_path}"
            success, stdout, stderr = self.run_docker_command(
                ["cp", temp_patch_path, target_path],
                timeout=30
            )
            
            # Clean up temp files
            Path(temp_local_path).unlink(missing_ok=True)
            self.run_docker_command(["rm", "-f", temp_patch_path], timeout=10)
            
            if not success:
                return False, f"Failed to apply patch: {stderr}"
            
            return True, ""
            
        except Exception as e:
            return False, str(e)
    
    def apply_multi_file_patch(
        self,
        patch_dir: Path,
        checkout_dir: str,
        vulnerable_files: List[Dict]
    ) -> Tuple[bool, str]:
        """
        Apply a multi-file patch to the checked-out vulnerability.
        
        Args:
            patch_dir: Directory containing patch files (patch_0/, patch_1/, etc.)
            checkout_dir: Path to the checked-out vulnerability in container
            vulnerable_files: List of dicts with 'file_path' keys
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            # Load file mapping if it exists
            mapping_file = patch_dir / "_file_mapping.json"
            if mapping_file.exists():
                with open(mapping_file) as f:
                    mapping = json.load(f)
                    expected_files = mapping.get("files", [])
            else:
                expected_files = [f.get("file_path") for f in vulnerable_files]
            
            applied_count = 0
            errors = []
            
            for vuln_file in vulnerable_files:
                file_path = vuln_file.get("file_path", "")
                filename = Path(file_path).name
                
                # Look for the patch file
                patch_file = patch_dir / filename
                
                if not patch_file.exists():
                    errors.append(f"Missing patch for {filename}")
                    continue
                
                # Apply this patch
                success, error = self.apply_patch(patch_file, checkout_dir, file_path)
                if success:
                    applied_count += 1
                    self.logger.debug(f"    Applied patch to {filename}")
                else:
                    errors.append(f"{filename}: {error}")
            
            if applied_count == len(vulnerable_files):
                return True, ""
            elif applied_count > 0:
                return True, f"Partial: {applied_count}/{len(vulnerable_files)} files patched. Errors: {'; '.join(errors)}"
            else:
                return False, f"Failed to apply any patches: {'; '.join(errors)}"
                
        except Exception as e:
            return False, str(e)
    
    def compile_project(self, checkout_dir: str) -> Tuple[bool, str]:
        """Compile the project using vul4j."""
        success, stdout, stderr = self.run_docker_command(
            ["vul4j", "compile", "-d", checkout_dir],
            timeout=self.timeout_compile
        )
        
        if not success:
            return False, stderr or stdout
        
        return True, ""
    
    def run_pov_tests(self, checkout_dir: str) -> Tuple[bool, Dict]:
        """
        Run PoV (Proof of Vulnerability) tests.
        
        PoV tests are designed to:
        - FAIL on vulnerable code (exploit succeeds)
        - PASS on fixed code (exploit fails)
        """
        success, stdout, stderr = self.run_docker_command(
            ["vul4j", "test", "-d", checkout_dir, "-b", "povs"],
            timeout=self.timeout_test
        )
        
        # Read test results
        test_results_path = f"{checkout_dir}/VUL4J/testing_results.json"
        success_read, results_json, _ = self.run_docker_command(
            ["cat", test_results_path],
            timeout=30
        )
        
        if success_read and results_json:
            try:
                test_data = json.loads(results_json)
                metrics = test_data.get("tests", {}).get("overall_metrics", {})
                
                # PoV test PASSES means vulnerability is FIXED
                failing_count = metrics.get("number_failing", 0)
                error_count = metrics.get("number_error", 0)
                
                pov_passed = (failing_count == 0 and error_count == 0)
                
                return pov_passed, metrics
            except json.JSONDecodeError:
                pass
        
        return False, {"error": "Could not read test results"}
    
    def run_full_tests(self, checkout_dir: str) -> FunctionalityResult:
        """Run the full test suite."""
        result = FunctionalityResult()
        
        success, stdout, stderr = self.run_docker_command(
            ["vul4j", "test", "-d", checkout_dir, "-b", "all"],
            timeout=self.timeout_test
        )
        
        # Read test results
        test_results_path = f"{checkout_dir}/VUL4J/testing_results.json"
        success_read, results_json, _ = self.run_docker_command(
            ["cat", test_results_path],
            timeout=30
        )
        
        if success_read and results_json:
            try:
                test_data = json.loads(results_json)
                metrics = test_data.get("tests", {}).get("overall_metrics", {})
                
                result.tests_run = metrics.get("number_running", 0)
                result.tests_passed = metrics.get("number_passing", 0)
                result.tests_failed = metrics.get("number_failing", 0)
                result.tests_errored = metrics.get("number_error", 0)
                result.tests_skipped = metrics.get("number_skipped", 0)
                
                # Get failed test names
                failures = test_data.get("tests", {}).get("failures", [])
                for failure in failures:
                    test_name = f"{failure.get('test_class', '')}#{failure.get('test_method', '')}"
                    result.failed_test_names.append(test_name)
                
                # Calculate pass rate
                if result.tests_run > 0:
                    result.pass_rate = result.tests_passed / result.tests_run
                
                result.all_tests_passed = (
                    result.tests_failed == 0 and
                    result.tests_errored == 0
                )
                
            except json.JSONDecodeError:
                result.error = "Could not parse test results"
        else:
            result.error = "Could not read test results"
        
        return result
    
    def run_semgrep(
        self,
        checkout_dir: str,
        rules: List[str],
        target_file: Optional[str] = None
    ) -> List[Dict]:
        """
        Run Semgrep with specified rules inside the Docker container.
        """
        warnings = []
        
        # Build the target path
        if target_file:
            scan_target = f"{checkout_dir}/{target_file}"
        else:
            scan_target = checkout_dir
        
        # Build semgrep command with JSON output
        semgrep_cmd = ["semgrep", "--json", "--quiet"]
        
        # Add rules
        for rule in rules:
            semgrep_cmd.extend(["--config", rule])
        
        semgrep_cmd.append(scan_target)
        
        self.logger.debug(f"  Running Semgrep scan...")
        
        try:
            success, stdout, stderr = self.run_docker_command(
                semgrep_cmd,
                timeout=self.timeout_semgrep
            )
            
            if stdout:
                try:
                    result = json.loads(stdout)
                    results = result.get("results", [])
                    
                    for finding in results:
                        warning = {
                            "rule_id": finding.get("check_id", ""),
                            "message": finding.get("extra", {}).get("message", ""),
                            "severity": finding.get("extra", {}).get("severity", ""),
                            "path": finding.get("path", ""),
                            "line": finding.get("start", {}).get("line", 0)
                        }
                        warnings.append(warning)
                    
                    self.logger.debug(f"  Semgrep found {len(warnings)} warning(s)")
                    
                except json.JSONDecodeError:
                    self.logger.debug(f"  Semgrep: Could not parse output")
            else:
                self.logger.debug(f"  Semgrep: No output (may not be installed in container)")
                
        except Exception as e:
            self.logger.debug(f"  Semgrep error: {e}")
        
        return warnings
    
    def classify_patch(
        self,
        security: SecurityResult,
        functionality: FunctionalityResult,
        regression: RegressionResult,
        baseline_tests: Optional[FunctionalityResult] = None
    ) -> Tuple[str, bool]:
        """
        Classify the patch based on evaluation results
        """
        if security.compile_error:
            return PatchCategory.COMPILE_ERROR.value, False
        
        if security.error or functionality.error:
            return PatchCategory.EVALUATION_ERROR.value, False
        
        is_secure = security.vulnerability_fixed or security.pov_test_passed
        
        # Functional = no NEW test failures compared to baseline
        # If we have baseline, compare against it; otherwise use all_tests_passed
        if baseline_tests:
            # Get tests that failed in patch but passed in baseline
            baseline_failures = set(baseline_tests.failed_test_names)
            patch_failures = set(functionality.failed_test_names)
            new_failures = patch_failures - baseline_failures
            is_functional = len(new_failures) == 0
        else:
            # No baseline available - use simple check
            is_functional = functionality.all_tests_passed
        
        is_regressive = regression.has_regressions
        
        if is_secure and is_functional:
            return PatchCategory.CORRECT_AND_SECURE.value, is_regressive
        elif not is_secure and is_functional:
            return PatchCategory.INSECURE.value, is_regressive
        elif is_secure and not is_functional:
            return PatchCategory.BREAKING.value, is_regressive
        else:
            return PatchCategory.INSECURE_AND_BREAKING.value, is_regressive
    
    def evaluate_patch(
        self,
        vul_id: str,
        model_name: str,
        patch_index: int,
        patch_file: Path,
        vulnerable_file_path: str,
        cwe_id: str,
        baseline_tests: Optional[FunctionalityResult] = None
    ) -> EvaluationResult:
        """
        Perform full tri-axis evaluation on a single patch.
        """
        start_time = datetime.now()
        
        result = EvaluationResult(
            vul_id=vul_id,
            model_name=model_name,
            patch_index=patch_index,
            patch_file=str(patch_file),
            timestamp=start_time.isoformat()
        )
        
        # Create a unique checkout directory for this evaluation
        checkout_dir = f"{self.vul4j_workdir}/eval_{vul_id}_{model_name}_{patch_index}"
        
        try:
            # Step 1: Checkout the vulnerability
            self.logger.info(f"  [1/6] Checking out {vul_id}...")
            if not self.checkout_vulnerability(vul_id, checkout_dir):
                result.security.error = "Failed to checkout vulnerability"
                result.category = PatchCategory.EVALUATION_ERROR.value
                return result
            
            # Step 2: Apply the patch
            self.logger.info(f"  [2/6] Applying patch...")
            success, error = self.apply_patch(patch_file, checkout_dir, vulnerable_file_path)
            if not success:
                result.security.error = f"Failed to apply patch: {error}"
                result.category = PatchCategory.EVALUATION_ERROR.value
                return result
            
            # Step 3: Compile
            self.logger.info(f"  [3/6] Compiling project...")
            compile_success, compile_error = self.compile_project(checkout_dir)
            result.security.compile_success = compile_success
            
            if not compile_success:
                result.security.compile_error = compile_error
                # Classify compilation error type
                error_type, _ = classify_compilation_error(compile_error)
                result.security.compile_error_type = error_type.value
                result.category = PatchCategory.COMPILE_ERROR.value
                result.subcategory = error_type.value
                self.logger.info(f"  ✗ Compilation failed: {error_type.value}")
                return result
            self.logger.info(f"  ✓ Compilation successful")
            
            # Step 4: Security Evaluation (Axis 1) - Run PoV tests
            self.logger.info(f"  [4/6] Running PoV tests (security)...")
            pov_passed, pov_details = self.run_pov_tests(checkout_dir)
            result.security.pov_test_passed = pov_passed
            result.security.pov_test_details = pov_details
            result.security.vulnerability_fixed = pov_passed
            self.logger.info(f"  {'✓' if pov_passed else '✗'} PoV tests: {'PASSED (vuln fixed)' if pov_passed else 'FAILED (vuln remains)'}")
            
            # Run Semgrep for CWE-specific check
            self.logger.info(f"  [5/6] Running Semgrep scan...")
            cwe_rules = CWE_SEMGREP_RULES.get(cwe_id, ["p/java"])
            result.security.semgrep_cwe_warnings = self.run_semgrep(
                checkout_dir, cwe_rules, vulnerable_file_path
            )
            result.security.semgrep_warnings_count = len(result.security.semgrep_cwe_warnings)
            self.logger.info(f"  Semgrep: {result.security.semgrep_warnings_count} warning(s)")
            
            # Step 5: Functionality Evaluation (Axis 2) - Run full tests
            self.logger.info(f"  [6/6] Running full test suite (functionality)...")
            result.functionality = self.run_full_tests(checkout_dir)
            self.logger.info(f"  Tests: {result.functionality.tests_passed}/{result.functionality.tests_run} passed")
            
            # Step 6: Regression Analysis (Axis 3)
            self.logger.debug(f"  Analyzing regressions...")
            if baseline_tests:
                # Compare with baseline to find regressions
                baseline_failures = set(baseline_tests.failed_test_names)
                current_failures = set(result.functionality.failed_test_names)
                
                # Functional regressions = tests that passed before but fail now
                new_failures = current_failures - baseline_failures
                result.regression.functional_regressions = list(new_failures)
                result.regression.broken_test_count = len(new_failures)
            
            # Security regressions from Semgrep (if implemented)
            result.regression.new_vulnerability_count = len(result.regression.security_regressions)
            result.regression.has_regressions = (
                result.regression.broken_test_count > 0 or
                result.regression.new_vulnerability_count > 0
            )
            
            # Step 7: Classify the patch using hierarchical failure taxonomy
            tests_passed_human = baseline_tests.tests_passed if baseline_tests else result.functionality.tests_passed
            
            failure_classification = classify_patch(
                compilation_success=True,
                compilation_error=None,
                pov_passed=pov_passed,
                tests_passed=result.functionality.tests_passed,
                tests_passed_human=tests_passed_human,
                semgrep_warnings_before=0,  # Will be loaded from baselines
                semgrep_warnings_after=result.security.semgrep_warnings_count,
                tests_failed=result.functionality.tests_failed,
                failed_test_names=result.functionality.failed_test_names
            )
            
            result.category = failure_classification.primary_category
            result.subcategory = failure_classification.subcategory
            result.is_regressive = result.regression.has_regressions
            
            # Step 8: Calculate continuous scores
            scores = score_patch(
                compilation_success=True,
                pov_passed=pov_passed,
                tests_passed=result.functionality.tests_passed,
                tests_passed_human=tests_passed_human,
                semgrep_warnings_before=0,  # Will be loaded from baselines
                semgrep_warnings_after=result.security.semgrep_warnings_count
            )
            
            result.security_score = scores.security_score
            result.functionality_score = scores.functionality_score
            result.srs = scores.srs
            
        except Exception as e:
            result.security.error = str(e)
            result.category = PatchCategory.EVALUATION_ERROR.value
            self.logger.error(f"Evaluation error: {e}")
        
        finally:
            # Clean up checkout directory
            self.run_docker_command(["rm", "-rf", checkout_dir], timeout=60)
        
        # Calculate evaluation time
        end_time = datetime.now()
        result.evaluation_time_ms = (end_time - start_time).total_seconds() * 1000
        
        return result
    
    def get_baseline_tests(
        self, 
        vul_id: str,
        human_patch_code: Optional[str] = None,
        vulnerable_file_path: Optional[str] = None
    ) -> Optional[FunctionalityResult]:
        """
        Get baseline test results from the HUMAN PATCH.
        """
        checkout_dir = f"{self.vul4j_workdir}/baseline_{vul_id}"
        
        try:
            # Checkout vulnerable version
            if not self.checkout_vulnerability(vul_id, checkout_dir):
                return None
            
            # Apply human patch if provided
            if human_patch_code and vulnerable_file_path:
                self.logger.debug(f"Applying human patch for baseline...")
                
                # Write human patch to temp file
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False, encoding='utf-8') as f:
                    f.write(human_patch_code)
                    temp_local_path = f.name
                
                # Copy to container
                temp_container_path = f"/tmp/human_patch_{vul_id}.java"
                copy_cmd = ["docker", "cp", temp_local_path, f"{self.docker_container}:{temp_container_path}"]
                subprocess.run(copy_cmd, capture_output=True, timeout=30)
                
                # Apply patch
                target_path = f"{checkout_dir}/{vulnerable_file_path}"
                self.run_docker_command(["cp", temp_container_path, target_path], timeout=30)
                
                # Clean up
                Path(temp_local_path).unlink(missing_ok=True)
                self.run_docker_command(["rm", "-f", temp_container_path], timeout=10)
            
            # Compile
            compile_success, _ = self.compile_project(checkout_dir)
            if not compile_success:
                self.logger.error(f"Failed to compile baseline for {vul_id}")
                return None
            
            # Run tests on human-patched code
            result = self.run_full_tests(checkout_dir)
            
            return result
            
        finally:
            # Clean up
            self.run_docker_command(["rm", "-rf", checkout_dir], timeout=60)
    
    def evaluate_multi_file_patch(
        self,
        vul_id: str,
        model_name: str,
        patch_index: int,
        patch_dir: Path,
        vulnerable_files: List[Dict],
        cwe_id: str,
        baseline_tests: Optional[FunctionalityResult] = None
    ) -> EvaluationResult:
        """
        Perform full tri-axis evaluation on a multi-file patch.
        """
        start_time = datetime.now()
        
        result = EvaluationResult(
            vul_id=vul_id,
            model_name=model_name,
            patch_index=patch_index,
            patch_file=str(patch_dir),
            timestamp=start_time.isoformat()
        )
        
        checkout_dir = f"{self.vul4j_workdir}/eval_{vul_id}_{model_name}_{patch_index}"
        
        try:
            # Step 1: Checkout the vulnerability
            self.logger.info(f"  [1/6] Checking out {vul_id}...")
            if not self.checkout_vulnerability(vul_id, checkout_dir):
                result.security.error = "Failed to checkout vulnerability"
                result.category = PatchCategory.EVALUATION_ERROR.value
                return result
            
            # Step 2: Apply multi-file patch
            self.logger.info(f"  [2/6] Applying multi-file patch ({len(vulnerable_files)} files)...")
            success, error = self.apply_multi_file_patch(patch_dir, checkout_dir, vulnerable_files)
            if not success:
                result.security.error = f"Failed to apply multi-file patch: {error}"
                result.category = PatchCategory.EVALUATION_ERROR.value
                return result
            if error:  # Partial success
                self.logger.warning(f"    {error}")
            
            # Step 3: Compile
            self.logger.info(f"  [3/6] Compiling project...")
            compile_success, compile_error = self.compile_project(checkout_dir)
            result.security.compile_success = compile_success
            
            if not compile_success:
                result.security.compile_error = compile_error
                error_type, _ = classify_compilation_error(compile_error)
                result.security.compile_error_type = error_type.value
                result.category = PatchCategory.COMPILE_ERROR.value
                result.subcategory = error_type.value
                self.logger.info(f"  ✗ Compilation failed: {error_type.value}")
                return result
            self.logger.info(f"  ✓ Compilation successful")
            
            # Step 4: Security Evaluation - Run PoV tests
            self.logger.info(f"  [4/6] Running PoV tests (security)...")
            pov_passed, pov_details = self.run_pov_tests(checkout_dir)
            result.security.pov_test_passed = pov_passed
            result.security.pov_test_details = pov_details
            result.security.vulnerability_fixed = pov_passed
            self.logger.info(f"  {'✓' if pov_passed else '✗'} PoV tests: {'PASSED (vuln fixed)' if pov_passed else 'FAILED (vuln remains)'}")
            
            # Run Semgrep on all vulnerable files
            self.logger.info(f"  [5/6] Running Semgrep scan...")
            cwe_rules = CWE_SEMGREP_RULES.get(cwe_id, ["p/java"])
            all_warnings = []
            for vuln_file in vulnerable_files:
                file_path = vuln_file.get("file_path", "")
                warnings = self.run_semgrep(checkout_dir, cwe_rules, file_path)
                all_warnings.extend(warnings)
            result.security.semgrep_cwe_warnings = all_warnings
            result.security.semgrep_warnings_count = len(all_warnings)
            self.logger.info(f"  Semgrep: {result.security.semgrep_warnings_count} warning(s)")
            
            # Step 5: Functionality Evaluation - Run full tests
            self.logger.info(f"  [6/6] Running full test suite (functionality)...")
            result.functionality = self.run_full_tests(checkout_dir)
            self.logger.info(f"  Tests: {result.functionality.tests_passed}/{result.functionality.tests_run} passed")
            
            # Step 6: Regression Analysis
            self.logger.debug(f"  Analyzing regressions...")
            if baseline_tests:
                baseline_failures = set(baseline_tests.failed_test_names)
                current_failures = set(result.functionality.failed_test_names)
                new_failures = current_failures - baseline_failures
                result.regression.functional_regressions = list(new_failures)
                result.regression.broken_test_count = len(new_failures)
            
            result.regression.new_vulnerability_count = len(result.regression.security_regressions)
            result.regression.has_regressions = (
                result.regression.broken_test_count > 0 or
                result.regression.new_vulnerability_count > 0
            )
            
            # Classify the patch
            tests_passed_human = baseline_tests.tests_passed if baseline_tests else result.functionality.tests_passed
            
            failure_classification = classify_patch(
                compilation_success=True,
                compilation_error=None,
                pov_passed=pov_passed,
                tests_passed=result.functionality.tests_passed,
                tests_passed_human=tests_passed_human,
                patch_code="",  # Multi-file - skip NO_CHANGE detection
                vulnerable_code="",
                semgrep_warnings_before=0,
                semgrep_warnings_after=result.security.semgrep_warnings_count
            )
            
            result.category = failure_classification.primary_category
            result.subcategory = failure_classification.subcategory
            result.is_regressive = result.regression.has_regressions
            
        except Exception as e:
            result.security.error = str(e)
            result.category = PatchCategory.EVALUATION_ERROR.value
            self.logger.error(f"Evaluation error: {e}")
        
        finally:
            self.run_docker_command(["rm", "-rf", checkout_dir], timeout=60)
        
        end_time = datetime.now()
        result.evaluation_time_ms = (end_time - start_time).total_seconds() * 1000
        
        return result


def load_vulnerability_info(vul_id: str, data_dir: Path) -> Dict:
    """Load vulnerability information from data files."""
    # Load vulnerable code info
    vuln_code_file = data_dir / "vulnerable_code.json"
    metadata_file = data_dir / "vulnerability_metadata.json"
    
    vuln_info = {}
    
    if vuln_code_file.exists():
        with open(vuln_code_file, 'r', encoding='utf-8') as f:
            vuln_data = json.load(f)
            # Handle both dict format (keyed by vul_id) and list format
            if isinstance(vuln_data, dict):
                if vul_id in vuln_data:
                    vuln_info.update(vuln_data[vul_id])
            else:
                for v in vuln_data:
                    if v.get("vul_id") == vul_id:
                        vuln_info.update(v)
                        break
    
    if metadata_file.exists():
        with open(metadata_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
            # Handle both dict format and list format
            if isinstance(metadata, dict):
                if vul_id in metadata:
                    vuln_info["cwe_id"] = metadata[vul_id].get("cwe_id", "")
                    vuln_info["cwe_name"] = metadata[vul_id].get("cwe_name", "")
            else:
                for v in metadata:
                    if v.get("vul_id") == vul_id:
                        vuln_info["cwe_id"] = v.get("cwe_id", "")
                        vuln_info["cwe_name"] = v.get("cwe_name", "")
                        break
    
    return vuln_info
