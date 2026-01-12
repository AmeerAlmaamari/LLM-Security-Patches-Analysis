"""
Semgrep Baseline Collection

Runs Semgrep on vulnerable code to establish baseline warning counts.
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
TIMEOUT_SEMGREP = 300  # 5 minutes per vulnerability

# Semgrep rules to use
SEMGREP_CONFIGS = ["p/java", "p/owasp-top-ten"]


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


def check_semgrep_installed() -> bool:
    """Check if Semgrep is installed in the container."""
    success, stdout, stderr = run_docker_command(["which", "semgrep"], timeout=10)
    if success:
        return True
    
    # Try to check if it's available via pip
    success, stdout, stderr = run_docker_command(["python3", "-m", "semgrep", "--version"], timeout=10)
    return success


def install_semgrep(logger) -> bool:
    """Install Semgrep in the container if not present."""
    logger.info("Installing Semgrep in container...")
    success, stdout, stderr = run_docker_command(
        ["pip3", "install", "semgrep"],
        timeout=300
    )
    if success:
        logger.success("Semgrep installed successfully")
        return True
    else:
        logger.error(f"Failed to install Semgrep: {stderr}")
        return False


def get_checkout_dir(vul_id: str) -> str:
    """Get the checkout directory for a vulnerability."""
    return f"{WORKSPACE_DIR}/data/vulnerabilities/{vul_id}"


def get_vulnerable_file_paths(vul_id: str, config) -> List[str]:
    """Get the vulnerable file paths for a vulnerability from vulnerable_code.json."""
    vuln_code_path = config.data_dir / "vulnerable_code.json"
    if not vuln_code_path.exists():
        return []
    
    with open(vuln_code_path, 'r') as f:
        vuln_data = json.load(f)
    
    if vul_id not in vuln_data:
        return []
    
    vuln_info = vuln_data[vul_id]
    file_paths = []
    
    for vf in vuln_info.get("vulnerable_files", []):
        file_path = vf.get("file_path", "")
        if file_path:
            file_paths.append(file_path)
    
    return file_paths


def run_semgrep_on_file(checkout_dir: str, file_path: str, logger) -> Dict:
    """Run Semgrep on a specific file and return results."""
    full_path = f"{checkout_dir}/{file_path}"
    
    # Build Semgrep command with JSON output
    semgrep_cmd = ["semgrep", "--json", "--quiet"]
    for config in SEMGREP_CONFIGS:
        semgrep_cmd.extend(["--config", config])
    semgrep_cmd.append(full_path)
    
    success, stdout, stderr = run_docker_command(semgrep_cmd, timeout=TIMEOUT_SEMGREP)
    
    # Semgrep returns exit code 1 if findings exist, 0 if no findings
    if stdout:
        try:
            semgrep_output = json.loads(stdout)
            results = semgrep_output.get("results", [])
            errors = semgrep_output.get("errors", [])
            
            # Extract warning details
            warnings = []
            for result in results:
                warnings.append({
                    "rule_id": result.get("check_id", ""),
                    "message": result.get("extra", {}).get("message", ""),
                    "severity": result.get("extra", {}).get("severity", ""),
                    "line": result.get("start", {}).get("line", 0),
                    "path": result.get("path", "")
                })
            
            return {
                "warning_count": len(results),
                "warnings": warnings,
                "errors": len(errors),
                "success": True
            }
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse Semgrep JSON output for {file_path}")
    
    return {
        "warning_count": 0,
        "warnings": [],
        "errors": 0,
        "success": False,
        "error": stderr[:200] if stderr else "Unknown error"
    }


def run_semgrep_on_directory(checkout_dir: str, logger) -> Dict:
    """Run Semgrep on the entire checkout directory."""
    # Build Semgrep command with JSON output
    semgrep_cmd = ["semgrep", "--json", "--quiet"]
    for config in SEMGREP_CONFIGS:
        semgrep_cmd.extend(["--config", config])
    semgrep_cmd.append(checkout_dir)
    
    success, stdout, stderr = run_docker_command(semgrep_cmd, timeout=TIMEOUT_SEMGREP)
    
    if stdout:
        try:
            semgrep_output = json.loads(stdout)
            results = semgrep_output.get("results", [])
            errors = semgrep_output.get("errors", [])
            
            # Extract warning details
            warnings = []
            for result in results:
                warnings.append({
                    "rule_id": result.get("check_id", ""),
                    "message": result.get("extra", {}).get("message", ""),
                    "severity": result.get("extra", {}).get("severity", ""),
                    "line": result.get("start", {}).get("line", 0),
                    "path": result.get("path", "")
                })
            
            return {
                "warning_count": len(results),
                "warnings": warnings,
                "errors": len(errors),
                "success": True
            }
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse Semgrep JSON output")
    
    return {
        "warning_count": 0,
        "warnings": [],
        "errors": 0,
        "success": False,
        "error": stderr[:200] if stderr else "Unknown error"
    }


def collect_semgrep_baseline(vul_id: str, config, logger) -> Dict:
    """Collect Semgrep baseline for a single vulnerability."""
    checkout_dir = get_checkout_dir(vul_id)
    
    logger.info(f"Processing {vul_id}...")
    
    # Get vulnerable file paths
    file_paths = get_vulnerable_file_paths(vul_id, config)
    
    if not file_paths:
        logger.warning(f"{vul_id}: No vulnerable files found in metadata")
        # Fall back to scanning the entire directory
        dir_result = run_semgrep_on_directory(checkout_dir, logger)
        return {
            "vul_id": vul_id,
            "scan_type": "directory",
            "warning_count": dir_result.get("warning_count", 0),
            "warnings": dir_result.get("warnings", [])[:20],  # Limit stored warnings
            "file_count": 0,
            "success": dir_result.get("success", False),
            "timestamp": datetime.now().isoformat()
        }
    
    # Scan each vulnerable file
    total_warnings = 0
    all_warnings = []
    file_results = {}
    
    for file_path in file_paths:
        result = run_semgrep_on_file(checkout_dir, file_path, logger)
        file_results[file_path] = {
            "warning_count": result.get("warning_count", 0),
            "success": result.get("success", False)
        }
        total_warnings += result.get("warning_count", 0)
        all_warnings.extend(result.get("warnings", []))
    
    logger.success(f"{vul_id}: {total_warnings} warnings in {len(file_paths)} files")
    
    return {
        "vul_id": vul_id,
        "scan_type": "files",
        "warning_count": total_warnings,
        "warnings": all_warnings[:50],  # Limit stored warnings
        "file_count": len(file_paths),
        "file_results": file_results,
        "success": True,
        "timestamp": datetime.now().isoformat()
    }


def main():
    """Main function to collect Semgrep baselines for all vulnerabilities."""
    config = get_config()
    logger = init_phase_logger("SEMGREP", "semgrep_baseline.log", str(config.logs_dir))
    
    logger.info("=" * 60)
    logger.info("Semgrep Baseline Collection")
    logger.info("=" * 60)
    
    # Check container health
    if not check_container_health():
        logger.error("Docker container is not healthy. Please start the vul4j container.")
        sys.exit(1)
    
    # Check/install Semgrep
    if not check_semgrep_installed():
        logger.warning("Semgrep not found in container, attempting to install...")
        if not install_semgrep(logger):
            logger.error("Failed to install Semgrep. Please install manually.")
            sys.exit(1)
    else:
        logger.info("Semgrep is available in container")
    
    # Load vulnerability list
    vuln_list_path = config.data_dir / "vulnerability_list.json"
    if not vuln_list_path.exists():
        logger.error(f"Vulnerability list not found: {vuln_list_path}")
        sys.exit(1)
    
    with open(vuln_list_path, 'r') as f:
        vulnerabilities = json.load(f)
    
    logger.info(f"Found {len(vulnerabilities)} vulnerabilities to process")
    
    # Load existing results for resume capability
    output_path = config.data_dir / "semgrep_baselines.json"
    if output_path.exists():
        with open(output_path, 'r') as f:
            results = json.load(f)
        logger.info(f"Loaded {len(results)} existing results (resume mode)")
    else:
        results = {}
    
    # Process each vulnerability
    start_time = datetime.now()
    processed = 0
    skipped = 0
    failed = 0
    
    for i, vul_id in enumerate(vulnerabilities):
        # Skip if already processed
        if vul_id in results and results[vul_id].get("success", False):
            logger.info(f"[{i+1}/{len(vulnerabilities)}] Skipping {vul_id} (already processed)")
            skipped += 1
            continue
        
        logger.info(f"[{i+1}/{len(vulnerabilities)}] Processing {vul_id}")
        
        try:
            result = collect_semgrep_baseline(vul_id, config, logger)
            results[vul_id] = result
            processed += 1
            
            if not result.get("success", False):
                failed += 1
                
        except Exception as e:
            logger.error(f"Exception processing {vul_id}: {e}")
            results[vul_id] = {"error": str(e), "vul_id": vul_id, "success": False}
            failed += 1
        
        # Save progress after each vulnerability
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Small delay between vulnerabilities
        time.sleep(0.5)
    
    # Final summary
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    logger.info("=" * 60)
    logger.info("Semgrep Baseline Collection Complete")
    logger.info("=" * 60)
    logger.info(f"Total vulnerabilities: {len(vulnerabilities)}")
    logger.info(f"Processed: {processed}")
    logger.info(f"Skipped (already done): {skipped}")
    logger.info(f"Failed: {failed}")
    logger.info(f"Duration: {duration:.1f} seconds")
    logger.info(f"Output: {output_path}")
    
    # Summary statistics
    successful = [r for r in results.values() if r.get("success", False)]
    if successful:
        total_warnings = sum(r.get("warning_count", 0) for r in successful)
        avg_warnings = total_warnings / len(successful)
        vulns_with_warnings = sum(1 for r in successful if r.get("warning_count", 0) > 0)
        logger.info(f"Total warnings found: {total_warnings}")
        logger.info(f"Average warnings per vulnerability: {avg_warnings:.1f}")
        logger.info(f"Vulnerabilities with warnings: {vulns_with_warnings}/{len(successful)}")


if __name__ == "__main__":
    main()
