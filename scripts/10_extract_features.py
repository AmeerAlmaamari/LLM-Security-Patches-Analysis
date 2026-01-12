"""
Vulnerability Feature Extraction

Extracts code complexity features for difficulty analysis.
"""

import json
import subprocess
import sys
import re
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
TIMEOUT_LIZARD = 120  # 2 minutes per vulnerability


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


def check_lizard_installed() -> bool:
    """Check if Lizard is installed in the container."""
    success, stdout, stderr = run_docker_command(["which", "lizard"], timeout=10)
    if success:
        return True
    
    # Try via python module
    success, stdout, stderr = run_docker_command(["python3", "-m", "lizard", "--version"], timeout=10)
    return success


def install_lizard(logger) -> bool:
    """Install Lizard in the container if not present."""
    logger.info("Installing Lizard in container...")
    success, stdout, stderr = run_docker_command(
        ["pip3", "install", "lizard"],
        timeout=120
    )
    if success:
        logger.success("Lizard installed successfully")
        return True
    else:
        logger.error(f"Failed to install Lizard: {stderr}")
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


def count_lines(code: str) -> int:
    """Count non-empty lines in code."""
    if not code:
        return 0
    lines = [line for line in code.split('\n') if line.strip()]
    return len(lines)


def calculate_patch_size(vulnerable_code: str, human_patch_code: str) -> Dict:
    """Calculate the size of the human patch (lines changed)."""
    if not vulnerable_code or not human_patch_code:
        return {"added": 0, "removed": 0, "total": 0}
    
    vuln_lines = set(vulnerable_code.split('\n'))
    patch_lines = set(human_patch_code.split('\n'))
    
    added = len(patch_lines - vuln_lines)
    removed = len(vuln_lines - patch_lines)
    
    return {
        "added": added,
        "removed": removed,
        "total": added + removed
    }


def run_lizard_on_file(checkout_dir: str, file_path: str, logger) -> Dict:
    """Run Lizard on a specific file and return complexity metrics."""
    full_path = f"{checkout_dir}/{file_path}"
    
    # Run lizard with CSV output for easier parsing
    success, stdout, stderr = run_docker_command(
        ["lizard", "--csv", full_path],
        timeout=TIMEOUT_LIZARD
    )
    
    if not success or not stdout:
        # Try alternative: run lizard without CSV
        success, stdout, stderr = run_docker_command(
            ["lizard", full_path],
            timeout=TIMEOUT_LIZARD
        )
        
        if not success:
            return {
                "success": False,
                "error": stderr[:200] if stderr else "Lizard failed"
            }
        
        # Parse text output
        return parse_lizard_text_output(stdout, logger)
    
    # Parse CSV output
    return parse_lizard_csv_output(stdout, logger)


def parse_lizard_csv_output(output: str, logger) -> Dict:
    """Parse Lizard CSV output."""
    lines = output.strip().split('\n')
    
    if len(lines) < 2:
        return {"success": False, "error": "No data in Lizard output"}
    
    # CSV format: NLOC,CCN,token,PARAM,length,location,file,function,long_name,start,end
    total_nloc = 0
    total_ccn = 0
    total_tokens = 0
    total_params = 0
    function_count = 0
    max_ccn = 0
    
    for line in lines[1:]:  # Skip header
        if not line.strip():
            continue
        
        parts = line.split(',')
        if len(parts) >= 4:
            try:
                nloc = int(parts[0])
                ccn = int(parts[1])
                tokens = int(parts[2])
                params = int(parts[3])
                
                total_nloc += nloc
                total_ccn += ccn
                total_tokens += tokens
                total_params += params
                function_count += 1
                max_ccn = max(max_ccn, ccn)
            except ValueError:
                continue
    
    if function_count == 0:
        return {"success": False, "error": "No functions found"}
    
    return {
        "success": True,
        "nloc": total_nloc,
        "cyclomatic_complexity_total": total_ccn,
        "cyclomatic_complexity_avg": total_ccn / function_count,
        "cyclomatic_complexity_max": max_ccn,
        "token_count": total_tokens,
        "parameter_count": total_params,
        "function_count": function_count
    }


def parse_lizard_text_output(output: str, logger) -> Dict:
    """Parse Lizard text output (fallback)."""
    
    lines = output.strip().split('\n')
    
    # Find the totals section
    total_nloc = 0
    avg_ccn = 0
    function_count = 0
    
    for i, line in enumerate(lines):
        if "Total nloc" in line and i + 1 < len(lines):
            # Next line should have the values
            data_line = lines[i + 1].strip()
            parts = data_line.split()
            if len(parts) >= 5:
                try:
                    total_nloc = int(parts[0])
                    avg_ccn = float(parts[2])
                    function_count = int(parts[4])
                except (ValueError, IndexError):
                    pass
            break
    
    # Also try to find max CCN from individual function listings
    max_ccn = 0
    for line in lines:
        # Look for lines with function data
        match = re.search(r'^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)', line)
        if match:
            try:
                ccn = int(match.group(2))
                max_ccn = max(max_ccn, ccn)
            except ValueError:
                pass
    
    if total_nloc == 0 and function_count == 0:
        return {"success": False, "error": "Could not parse Lizard output"}
    
    return {
        "success": True,
        "nloc": total_nloc,
        "cyclomatic_complexity_avg": avg_ccn,
        "cyclomatic_complexity_max": max_ccn,
        "function_count": function_count
    }


def extract_features(vul_id: str, vuln_data: Dict, config, logger) -> Dict:
    """Extract all features for a single vulnerability."""
    checkout_dir = get_checkout_dir(vul_id)
    
    logger.info(f"Processing {vul_id}...")
    
    if vul_id not in vuln_data:
        return {
            "vul_id": vul_id,
            "error": "Vulnerability not found in vulnerable_code.json",
            "success": False
        }
    
    vuln_info = vuln_data[vul_id]
    vulnerable_files = vuln_info.get("vulnerable_files", [])
    
    # Basic counts
    num_files = len(vulnerable_files)
    total_loc = 0
    total_human_patch_size = 0
    
    # Complexity metrics (aggregated across files)
    total_nloc = 0
    total_ccn = 0
    max_ccn = 0
    total_functions = 0
    
    file_features = {}
    
    for vf in vulnerable_files:
        file_path = vf.get("file_path", "")
        vulnerable_code = vf.get("vulnerable_code", "")
        human_patch_code = vf.get("human_patch_code", "")
        
        # Count lines
        loc = count_lines(vulnerable_code)
        total_loc += loc
        
        # Calculate patch size
        patch_size = calculate_patch_size(vulnerable_code, human_patch_code)
        total_human_patch_size += patch_size["total"]
        
        # Run Lizard for complexity
        lizard_result = run_lizard_on_file(checkout_dir, file_path, logger)
        
        file_features[file_path] = {
            "loc": loc,
            "patch_size": patch_size,
            "lizard": lizard_result
        }
        
        if lizard_result.get("success", False):
            total_nloc += lizard_result.get("nloc", 0)
            total_ccn += lizard_result.get("cyclomatic_complexity_total", 0)
            max_ccn = max(max_ccn, lizard_result.get("cyclomatic_complexity_max", 0))
            total_functions += lizard_result.get("function_count", 0)
    
    # Calculate averages
    avg_ccn = total_ccn / total_functions if total_functions > 0 else 0
    
    result = {
        "vul_id": vul_id,
        "cve_id": vuln_info.get("cve_id", ""),
        "project": vuln_info.get("project", ""),
        
        # Basic metrics
        "num_files": num_files,
        "loc_vulnerable": total_loc,
        "human_patch_size": total_human_patch_size,
        
        # Complexity metrics
        "nloc": total_nloc,
        "cyclomatic_complexity_total": total_ccn,
        "cyclomatic_complexity_avg": round(avg_ccn, 2),
        "cyclomatic_complexity_max": max_ccn,
        "function_count": total_functions,
        
        # Per-file details
        "file_features": file_features,
        
        "success": True,
        "timestamp": datetime.now().isoformat()
    }
    
    logger.success(f"{vul_id}: LOC={total_loc}, patch_size={total_human_patch_size}, CCN_max={max_ccn}")
    
    return result


def main():
    """Main function to extract features for all vulnerabilities."""
    config = get_config()
    logger = init_phase_logger("FEATURES", "extract_features.log", str(config.logs_dir))
    
    logger.info("=" * 60)
    logger.info("Vulnerability Feature Extraction")
    logger.info("=" * 60)
    
    # Check container health
    if not check_container_health():
        logger.error("Docker container is not healthy. Please start the vul4j container.")
        sys.exit(1)
    
    # Check/install Lizard
    if not check_lizard_installed():
        logger.warning("Lizard not found in container, attempting to install...")
        if not install_lizard(logger):
            logger.warning("Lizard installation failed. Complexity metrics will be limited.")
    else:
        logger.info("Lizard is available in container")
    
    # Load vulnerability list
    vuln_list_path = config.data_dir / "vulnerability_list.json"
    if not vuln_list_path.exists():
        logger.error(f"Vulnerability list not found: {vuln_list_path}")
        sys.exit(1)
    
    with open(vuln_list_path, 'r') as f:
        vulnerabilities = json.load(f)
    
    logger.info(f"Found {len(vulnerabilities)} vulnerabilities to process")
    
    # Load vulnerable code data
    vuln_data = load_vulnerable_code_data(config)
    if not vuln_data:
        logger.error("Could not load vulnerable_code.json")
        sys.exit(1)
    
    logger.info(f"Loaded vulnerable code data for {len(vuln_data)} vulnerabilities")
    
    # Load existing results for resume capability
    output_path = config.data_dir / "vulnerability_features.json"
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
            result = extract_features(vul_id, vuln_data, config, logger)
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
    
    # Final summary
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    logger.info("=" * 60)
    logger.info("Feature Extraction Complete")
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
        avg_loc = sum(r.get("loc_vulnerable", 0) for r in successful) / len(successful)
        avg_patch_size = sum(r.get("human_patch_size", 0) for r in successful) / len(successful)
        avg_ccn = sum(r.get("cyclomatic_complexity_avg", 0) for r in successful) / len(successful)
        max_ccn = max(r.get("cyclomatic_complexity_max", 0) for r in successful)
        
        logger.info(f"Average LOC: {avg_loc:.1f}")
        logger.info(f"Average human patch size: {avg_patch_size:.1f} lines")
        logger.info(f"Average cyclomatic complexity: {avg_ccn:.2f}")
        logger.info(f"Max cyclomatic complexity: {max_ccn}")


if __name__ == "__main__":
    main()
