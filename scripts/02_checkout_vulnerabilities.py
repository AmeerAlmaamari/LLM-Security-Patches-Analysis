"""
Checkout Vulnerabilities Script

Checks out all 64 vulnerabilities using Docker exec commands.
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from logger import init_phase_logger
from config import get_config

# Configuration
WORKSPACE_PATH = "d:/Energy Forecasting/AI Software Quality/almaamari/replication"
DOCKER_IMAGE = "bqcuongas/vul4j:alldeps"
CONTAINER_NAME = "vul4j"
CHECKOUT_TIMEOUT = 1200  # in seconds


def run_docker_command(command: list, timeout: int = 300) -> tuple:
    """
    Run a command inside the Docker container.
    """
    full_command = ["docker", "exec", "vul4j"] + command
    
    try:
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        # Kill any hanging git processes inside the container
        subprocess.run(["docker", "exec", "vul4j", "pkill", "-9", "git"], capture_output=True)
        subprocess.run(["docker", "exec", "vul4j", "pkill", "-9", "vul4j"], capture_output=True)
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def check_container_health() -> bool:
    """Check if the Docker container is healthy and vul4j dataset is intact."""
    try:
        result = subprocess.run(
            ["docker", "exec", "vul4j", "ls", "/vul4j/dataset/vul4j_dataset.csv"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except:
        return False


def recreate_container() -> bool:
    """Recreate the Docker container to recover from corrupted state."""
    import time
    try:
        # Remove the old container
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=30)
        time.sleep(2)
        
        # Create a new container
        result = subprocess.run(
            ["docker", "run", "-d", "-it", "--name", CONTAINER_NAME,
             "-v", f"{WORKSPACE_PATH}:/workspace",
             DOCKER_IMAGE, "/bin/bash"],
            capture_output=True,
            timeout=60
        )
        if result.returncode != 0:
            print(f"Failed to create container: {result.stderr.decode() if result.stderr else 'Unknown error'}")
            return False
        
        time.sleep(5)  # Wait for container to be ready
        return check_container_health()
    except Exception as e:
        print(f"Exception recreating container: {e}")
        return False


def is_checkout_complete(docker_path: str) -> bool:
    """Check if a vulnerability is already fully checked out."""
    verify_cmd = ["ls", f"{docker_path}/VUL4J/vulnerability_info.json"]
    success, _, _ = run_docker_command(verify_cmd, timeout=10)
    return success


def checkout_vulnerability(vul_id: str, docker_path: str, logger) -> bool:
    """
    Checkout a single vulnerability using vul4j.
    """
    # Check container health before checkout
    if not check_container_health():
        logger.warning(f"Container unhealthy, recreating...")
        if not recreate_container():
            logger.error(f"FAILED: {vul_id} - Could not recreate container")
            return False
        logger.info(f"Container recreated successfully")
    
    # First, remove existing directory if it exists (to handle incomplete checkouts)
    rm_command = ["rm", "-rf", docker_path]
    run_docker_command(rm_command, timeout=60)
    
    command = [
        "vul4j", "checkout",
        "--id", vul_id,
        "-d", docker_path
    ]
    
    success, stdout, stderr = run_docker_command(command, timeout=CHECKOUT_TIMEOUT)
    
    if success:
        # Verify the checkout by checking for vulnerability_info.json
        verify_cmd = ["ls", f"{docker_path}/VUL4J/vulnerability_info.json"]
        verify_success, _, _ = run_docker_command(verify_cmd, timeout=10)
        if verify_success:
            logger.success(f"Checked out {vul_id}")
            return True
        else:
            logger.error(f"FAILED: {vul_id} - Checkout incomplete (missing vulnerability_info.json)")
            return False
    else:
        logger.error(f"FAILED: {vul_id} - {stderr[:200] if stderr else 'Unknown error'}")
        return False


def main():
    """Main function to checkout all vulnerabilities."""
    config = get_config()
    logger = init_phase_logger("CHECKOUT", "checkout.log", str(config.logs_dir))
    
    logger.info("Starting: Checkout Vulnerabilities")
    
    # Load vulnerability list
    vuln_list_file = config.data_dir / "vulnerability_list.json"
    with open(vuln_list_file, 'r') as f:
        vuln_ids = json.load(f)
    
    logger.info(f"Will checkout {len(vuln_ids)} vulnerabilities")
    
    # Track results
    checkout_status = {
        "total": len(vuln_ids),
        "successful": [],
        "failed": [],
        "timestamp": datetime.now().isoformat()
    }
    
    # Load existing status if resuming
    status_file = config.data_dir / "checkout_status.json"
    if status_file.exists():
        with open(status_file, 'r') as f:
            existing_status = json.load(f)
            checkout_status["successful"] = existing_status.get("successful", [])
            logger.info(f"Resuming: {len(checkout_status['successful'])} already completed")
    
    # Checkout each vulnerability
    for i, vul_id in enumerate(vuln_ids):
        # Docker path: /workspace/data/vulnerabilities/{VUL_ID}
        docker_path = f"/workspace/data/vulnerabilities/{vul_id}"
        
        # Skip if already completed
        if vul_id in checkout_status["successful"]:
            logger.info(f"[{i+1}/{len(vuln_ids)}] Skipping {vul_id} (already done)")
            continue
        
        # Check if already checked out but not in status file
        if is_checkout_complete(docker_path):
            logger.info(f"[{i+1}/{len(vuln_ids)}] {vul_id} already checked out")
            checkout_status["successful"].append(vul_id)
            continue
        
        logger.info(f"[{i+1}/{len(vuln_ids)}] Checking out {vul_id}...")
        
        success = checkout_vulnerability(vul_id, docker_path, logger)
        
        if success:
            checkout_status["successful"].append(vul_id)
        else:
            checkout_status["failed"].append(vul_id)
        
        # Save progress after each checkout
        with open(status_file, 'w') as f:
            json.dump(checkout_status, f, indent=2)
    
    # Save checkout status
    status_file = config.data_dir / "checkout_status.json"
    with open(status_file, 'w') as f:
        json.dump(checkout_status, f, indent=2)
    
    # Summary
    success_count = len(checkout_status["successful"])
    fail_count = len(checkout_status["failed"])
    
    logger.info("=" * 50)
    logger.info(f"Checkout complete: {success_count}/{len(vuln_ids)} successful")
    
    if fail_count > 0:
        logger.warning(f"Failed checkouts ({fail_count}): {checkout_status['failed']}")
    
    logger.success(f"Checkout status saved to {status_file}")
    
    return checkout_status


if __name__ == "__main__":
    status = main()
    print(f"\nCheckout complete: {len(status['successful'])}/{status['total']} successful")
    if status['failed']:
        print(f"Failed: {status['failed']}")
