"""
Human Patch Baseline Collection

Collects test results from human patches to establish baseline metrics.
Output: data/human_baselines.json
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from logger import init_phase_logger
from config import get_config

# Configuration
CONTAINER_NAME = "vul4j"
WORKSPACE_DIR = "/workspace"

# Generous timeouts for large projects
TIMEOUT_COMPILE = 2700  # 45 minutes for compilation
TIMEOUT_TEST = 1800     # 30 minutes for tests


def run_docker_command(command: List[str], timeout: int = 300) -> Tuple[bool, str, str]:
    """Run a command inside the Docker container."""
    full_command = ["docker", "exec", CONTAINER_NAME] + command
    
    try:
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def check_container_health() -> bool:
    """Check if the Docker container is healthy."""
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "ls", "/vul4j/dataset/vul4j_dataset.csv"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except:
        return False


def get_checkout_dir(vul_id: str) -> str:
    """Get the checkout directory for a vulnerability."""
    return f"{WORKSPACE_DIR}/data/vulnerabilities/{vul_id}"


def load_vulnerable_code_data(config) -> Dict:
    """Load vulnerable code data from JSON."""
    vuln_code_path = config.data_dir / "vulnerable_code.json"
    if not vuln_code_path.exists():
        return {}
    
    with open(vuln_code_path, 'r') as f:
        return json.load(f)


def apply_patch_file(checkout_dir: str, file_path: str, code_content: str, logger) -> bool:
    """
    Apply a patch by copying code content to the target file.
    """
    import tempfile
    
    try:
        # Write code to a temp file locally
        with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False, encoding='utf-8') as f:
            f.write(code_content)
            temp_local_path = f.name
        
        # Copy to container
        temp_container_path = "/tmp/patch_temp.java"
        copy_cmd = ["docker", "cp", temp_local_path, f"{CONTAINER_NAME}:{temp_container_path}"]
        result = subprocess.run(copy_cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            logger.warning(f"Failed to copy file to container: {result.stderr}")
            Path(temp_local_path).unlink(missing_ok=True)
            return False
        
        # Move to target location
        target_path = f"{checkout_dir}/{file_path}"
        success, stdout, stderr = run_docker_command(
            ["cp", temp_container_path, target_path],
            timeout=30
        )
        
        # Clean up
        Path(temp_local_path).unlink(missing_ok=True)
        run_docker_command(["rm", "-f", temp_container_path], timeout=10)
        
        if not success:
            logger.warning(f"Failed to apply patch to {file_path}: {stderr}")
            return False
        
        return True
        
    except Exception as e:
        logger.warning(f"Exception applying patch: {e}")
        return False


def apply_human_patch(vul_id: str, checkout_dir: str, vuln_data: Dict, logger) -> bool:
    """
    Apply the human patch by copying patched file content.
    """
    if vul_id not in vuln_data:
        logger.warning(f"{vul_id} not found in vulnerable_code.json")
        return False
    
    vuln_info = vuln_data[vul_id]
    vulnerable_files = vuln_info.get("vulnerable_files", [])
    
    if not vulnerable_files:
        logger.warning(f"{vul_id} has no vulnerable files")
        return False
    
    all_success = True
    for vf in vulnerable_files:
        file_path = vf.get("file_path", "")
        human_patch_code = vf.get("human_patch_code", "")
        
        if not file_path or not human_patch_code:
            logger.warning(f"{vul_id}: Missing file_path or human_patch_code")
            all_success = False
            continue
        
        if not apply_patch_file(checkout_dir, file_path, human_patch_code, logger):
            all_success = False
    
    return all_success


def reset_to_vulnerable(vul_id: str, checkout_dir: str, vuln_data: Dict, logger) -> bool:
    """
    Reset to vulnerable state by copying original vulnerable code.
    """
    if vul_id not in vuln_data:
        return False
    
    vuln_info = vuln_data[vul_id]
    vulnerable_files = vuln_info.get("vulnerable_files", [])
    
    all_success = True
    for vf in vulnerable_files:
        file_path = vf.get("file_path", "")
        vulnerable_code = vf.get("vulnerable_code", "")
        
        if not file_path or not vulnerable_code:
            all_success = False
            continue
        
        if not apply_patch_file(checkout_dir, file_path, vulnerable_code, logger):
            all_success = False
    
    return all_success


def compile_project(checkout_dir: str, logger) -> Tuple[bool, str, float]:
    """Compile the project using vul4j compile. Returns (success, error_msg, duration_seconds)."""
    start = time.time()
    
    success, stdout, stderr = run_docker_command(
        ["vul4j", "compile", "-d", checkout_dir],
        timeout=TIMEOUT_COMPILE
    )
    
    duration = time.time() - start
    
    if success:
        logger.info(f"  [OK] Compilation: SUCCESS ({duration:.1f}s)")
    else:
        if "timed out" in stderr.lower():
            logger.warning(f"  [FAIL] Compilation: TIMEOUT after {duration:.1f}s")
        else:
            logger.warning(f"  [FAIL] Compilation: FAILED ({duration:.1f}s) - {stderr[:100] if stderr else 'Unknown'}")
    
    return success, stderr, duration


def run_all_tests(checkout_dir: str, logger) -> Tuple[Dict, float]:
    """Run the full test suite. Returns (results_dict, duration_seconds)."""
    start = time.time()
    
    success, stdout, stderr = run_docker_command(
        ["vul4j", "test", "-d", checkout_dir, "-b", "all"],
        timeout=TIMEOUT_TEST
    )
    
    duration = time.time() - start
    
    # Read test results
    test_results_path = f"{checkout_dir}/VUL4J/testing_results.json"
    success_read, results_json, _ = run_docker_command(
        ["cat", test_results_path],
        timeout=30
    )
    
    all_tests = {
        "tests_run": 0,
        "tests_passed": 0,
        "tests_failed": 0,
        "tests_errored": 0,
        "tests_skipped": 0,
        "success": False
    }
    
    if success_read and results_json:
        try:
            test_data = json.loads(results_json)
            metrics = test_data.get("tests", {}).get("overall_metrics", {})
            
            all_tests = {
                "tests_run": metrics.get("number_running", 0),
                "tests_passed": metrics.get("number_passing", 0),
                "tests_failed": metrics.get("number_failing", 0),
                "tests_errored": metrics.get("number_error", 0),
                "tests_skipped": metrics.get("number_skipped", 0),
                "success": True
            }
        except json.JSONDecodeError:
            pass
    
    if all_tests["success"]:
        logger.info(f"  [OK] All Tests: {all_tests['tests_passed']}/{all_tests['tests_run']} passed ({duration:.1f}s)")
    else:
        logger.warning(f"  [FAIL] All Tests: FAILED ({duration:.1f}s)")
    
    return all_tests, duration


def run_pov_tests(checkout_dir: str, logger) -> Tuple[Dict, float]:
    """Run PoV tests and return detailed"""
    start = time.time()
    
    success, stdout, stderr = run_docker_command(
        ["vul4j", "test", "-d", checkout_dir, "-b", "povs"],
        timeout=TIMEOUT_TEST
    )
    
    duration = time.time() - start
    
    # Read test results
    test_results_path = f"{checkout_dir}/VUL4J/testing_results.json"
    success_read, results_json, _ = run_docker_command(
        ["cat", test_results_path],
        timeout=30
    )
    
    pov_result = {
        "pov_tests_run": 0,
        "pov_tests_passed": 0,
        "pov_tests_failed": 0,
        "pov_tests_errored": 0,
        "pov_tests_skipped": 0,
        "all_pov_passed": False,
        "success": False
    }
    
    if success_read and results_json:
        try:
            test_data = json.loads(results_json)
            metrics = test_data.get("tests", {}).get("overall_metrics", {})
            
            pov_run = metrics.get("number_running", 0)
            pov_passed = metrics.get("number_passing", 0)
            pov_failed = metrics.get("number_failing", 0)
            pov_errored = metrics.get("number_error", 0)
            pov_skipped = metrics.get("number_skipped", 0)
            
            pov_result = {
                "pov_tests_run": pov_run,
                "pov_tests_passed": pov_passed,
                "pov_tests_failed": pov_failed,
                "pov_tests_errored": pov_errored,
                "pov_tests_skipped": pov_skipped,
                "all_pov_passed": (pov_failed == 0 and pov_errored == 0 and pov_run > 0),
                "success": True
            }
        except json.JSONDecodeError:
            pass
    
    if pov_result["success"]:
        status = "PASS" if pov_result["all_pov_passed"] else "FAIL"
        logger.info(f"  [OK] PoV Tests: {pov_result['pov_tests_passed']}/{pov_result['pov_tests_run']} passed - {status} ({duration:.1f}s)")
    else:
        logger.warning(f"  [FAIL] PoV Tests: FAILED to run ({duration:.1f}s)")
    
    return pov_result, duration


def collect_human_baseline(vul_id: str, vuln_data: Dict, logger) -> Optional[Dict]:
    """Collect human patch baseline for a single vulnerability."""
    checkout_dir = get_checkout_dir(vul_id)
    total_start = time.time()
    
    logger.info(f"Processing {vul_id}...")
    
    # Step 1: Apply human patch
    logger.info("  [1/4] Applying human patch...")
    if not apply_human_patch(vul_id, checkout_dir, vuln_data, logger):
        logger.warning(f"  [FAIL] Apply Patch: FAILED")
        return {"error": "Failed to apply human patch", "vul_id": vul_id}
    logger.info(f"  [OK] Apply Patch: SUCCESS")
    
    # Step 2: Compile
    logger.info("  [2/4] Compiling...")
    compile_success, compile_error, compile_time = compile_project(checkout_dir, logger)
    if not compile_success:
        # Reset to vulnerable before returning
        logger.info("  [R] Resetting to vulnerable state...")
        reset_success = reset_to_vulnerable(vul_id, checkout_dir, vuln_data, logger)
        logger.info(f"  [OK] Reset: {'SUCCESS' if reset_success else 'FAILED'}")
        return {
            "vul_id": vul_id,
            "compile_success": False,
            "compile_error": compile_error[:500] if compile_error else "Unknown",
            "error": "Compilation failed"
        }
    
    # Step 3: Run all tests
    logger.info("  [3/4] Running all tests...")
    all_tests, tests_time = run_all_tests(checkout_dir, logger)
    
    # Step 4: Run PoV tests separately
    logger.info("  [4/4] Running PoV tests...")
    pov_tests, pov_time = run_pov_tests(checkout_dir, logger)
    
    # Step 5: Reset to vulnerable state (IMPORTANT!)
    logger.info("  [R] Resetting to vulnerable state...")
    reset_success = reset_to_vulnerable(vul_id, checkout_dir, vuln_data, logger)
    if reset_success:
        logger.info(f"  [OK] Reset: SUCCESS")
    else:
        logger.warning(f"  [FAIL] Reset: FAILED - Manual reset may be needed!")
    
    total_time = time.time() - total_start
    
    # Combine results
    result = {
        "vul_id": vul_id,
        "compile_success": True,
        "tests_run": all_tests.get("tests_run", 0),
        "tests_passed": all_tests.get("tests_passed", 0),
        "tests_failed": all_tests.get("tests_failed", 0),
        "tests_errored": all_tests.get("tests_errored", 0),
        "tests_skipped": all_tests.get("tests_skipped", 0),
        "pov_tests_run": pov_tests.get("pov_tests_run", 0),
        "pov_tests_passed": pov_tests.get("pov_tests_passed", 0),
        "pov_tests_failed": pov_tests.get("pov_tests_failed", 0),
        "pov_tests_errored": pov_tests.get("pov_tests_errored", 0),
        "pov_tests_skipped": pov_tests.get("pov_tests_skipped", 0),
        "all_pov_passed": pov_tests.get("all_pov_passed", False),
        "timestamp": datetime.now().isoformat()
    }
    
    # Final summary for this vulnerability
    logger.success(f"  ══ {vul_id} COMPLETE: tests={result['tests_passed']}/{result['tests_run']}, pov={'PASS' if result['all_pov_passed'] else 'FAIL'}, total={total_time:.1f}s ══")
    
    return result


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Collect human patch baselines")
    parser.add_argument("--retry-failed", action="store_true", 
                        help="Retry vulnerabilities that previously failed")
    parser.add_argument("--vul-ids", nargs="+", 
                        help="Only process specific vulnerability IDs")
    args = parser.parse_args()
    
    config = get_config()
    logger = init_phase_logger("BASELINE", "human_baseline.log", str(config.logs_dir))
    
    logger.info("=" * 60)
    logger.info("Human Patch Baseline Collection")
    logger.info("=" * 60)
    
    if args.retry_failed:
        logger.info("Mode: RETRY FAILED vulnerabilities")
    if args.vul_ids:
        logger.info(f"Mode: Processing specific IDs: {args.vul_ids}")
    
    # Check container health
    if not check_container_health():
        logger.error("Docker container is not healthy. Please start the vul4j container.")
        sys.exit(1)
    
    # Load vulnerability list
    vuln_list_path = config.data_dir / "vulnerability_list.json"
    if not vuln_list_path.exists():
        logger.error(f"Vulnerability list not found: {vuln_list_path}")
        sys.exit(1)
    
    with open(vuln_list_path, 'r') as f:
        vulnerabilities = json.load(f)
    
    logger.info(f"Found {len(vulnerabilities)} vulnerabilities to process")
    
    # Load vulnerable code data (contains human patches)
    vuln_data = load_vulnerable_code_data(config)
    if not vuln_data:
        logger.error("Could not load vulnerable_code.json")
        sys.exit(1)
    logger.info(f"Loaded vulnerable code data for {len(vuln_data)} vulnerabilities")
    
    # Load existing results for resume capability
    output_path = config.data_dir / "human_baselines.json"
    if output_path.exists():
        with open(output_path, 'r') as f:
            results = json.load(f)
        logger.info(f"Loaded {len(results)} existing results (resume mode)")
    else:
        results = {}
    
    # Filter vulnerabilities if specific IDs requested
    if args.vul_ids:
        vulnerabilities = [v for v in vulnerabilities if v in args.vul_ids]
        logger.info(f"Filtered to {len(vulnerabilities)} vulnerabilities")
    
    # Process each vulnerability
    start_time = datetime.now()
    processed = 0
    skipped = 0
    failed = 0
    
    for i, vul_id in enumerate(vulnerabilities):
        # Skip if already processed (including errors - don't retry failed ones)
        if vul_id in results:
            existing = results[vul_id]
            is_old_format = "pov_tests_run" not in existing and "error" not in existing
            has_error = "error" in existing
            
            if is_old_format:
                logger.info(f"[{i+1}/{len(vulnerabilities)}] Re-processing {vul_id} (old format)")
            elif has_error and args.retry_failed:
                logger.info(f"[{i+1}/{len(vulnerabilities)}] Retrying {vul_id} (previously failed: {existing.get('error', 'Unknown')[:50]})")
            else:
                # Skip - either successfully processed or has error (don't retry errors)
                logger.info(f"[{i+1}/{len(vulnerabilities)}] Skipping {vul_id} (already processed)")
                skipped += 1
                continue
        
        logger.info(f"[{i+1}/{len(vulnerabilities)}] Processing {vul_id}")
        
        try:
            result = collect_human_baseline(vul_id, vuln_data, logger)
            if result:
                results[vul_id] = result
                processed += 1
                
                if "error" in result:
                    failed += 1
            else:
                failed += 1
                results[vul_id] = {"error": "Unknown error", "vul_id": vul_id}
                
        except Exception as e:
            logger.error(f"Exception processing {vul_id}: {e}")
            results[vul_id] = {"error": str(e), "vul_id": vul_id}
            failed += 1
   
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
    
    # Final summary
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    logger.info("=" * 60)
    logger.info("Human Baseline Collection Complete")
    logger.info("=" * 60)
    logger.info(f"Total vulnerabilities: {len(vulnerabilities)}")
    logger.info(f"Processed: {processed}")
    logger.info(f"Skipped (already done): {skipped}")
    logger.info(f"Failed: {failed}")
    logger.info(f"Duration: {duration:.1f} seconds")
    logger.info(f"Output: {output_path}")
    
    # Summary statistics
    successful = [r for r in results.values() if "error" not in r]
    if successful:
        avg_tests = sum(r.get("tests_passed", 0) for r in successful) / len(successful)
        all_pov_pass_rate = sum(1 for r in successful if r.get("all_pov_passed", False)) / len(successful)
        logger.info(f"Average tests passed: {avg_tests:.1f}")
        logger.info(f"All PoV passed rate: {all_pov_pass_rate*100:.1f}%")


if __name__ == "__main__":
    main()
