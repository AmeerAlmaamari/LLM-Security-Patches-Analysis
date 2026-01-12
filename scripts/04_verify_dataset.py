"""
Verify Dataset Integrity Script

Verifies that all dataset deliverables are complete and generates a summary.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from logger import init_phase_logger
from config import get_config


def verify_dataset():
    """Verify dataset integrity and generate summary."""
    config = get_config()
    logger = init_phase_logger("VERIFY", "verify_dataset.log", str(config.logs_dir))
    
    logger.info("Starting: Verify Dataset Integrity")
    
    summary = {
        "timestamp": datetime.now().isoformat(),
        "step": "Dataset Preparation",
        "status": "PENDING",
        "deliverables": {},
        "statistics": {},
        "issues": []
    }
    
    # 1. Check vulnerability_list.json
    vuln_list_file = config.data_dir / "vulnerability_list.json"
    if vuln_list_file.exists():
        with open(vuln_list_file, 'r') as f:
            vuln_ids = json.load(f)
        summary["deliverables"]["vulnerability_list.json"] = {
            "exists": True,
            "count": len(vuln_ids)
        }
        summary["statistics"]["total_vulnerabilities"] = len(vuln_ids)
        logger.success(f"vulnerability_list.json: {len(vuln_ids)} vulnerabilities")
    else:
        summary["deliverables"]["vulnerability_list.json"] = {"exists": False}
        summary["issues"].append("vulnerability_list.json not found")
        logger.error("vulnerability_list.json not found")
    
    # 2. Check vulnerability_metadata.json
    metadata_file = config.data_dir / "vulnerability_metadata.json"
    if metadata_file.exists():
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        summary["deliverables"]["vulnerability_metadata.json"] = {
            "exists": True,
            "count": len(metadata)
        }
        
        # Count CWE types
        cwe_counts = {}
        for vul_id, info in metadata.items():
            cwe = info.get("cwe_id", "Unknown")
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        summary["statistics"]["cwe_distribution"] = cwe_counts
        
        logger.success(f"vulnerability_metadata.json: {len(metadata)} entries")
    else:
        summary["deliverables"]["vulnerability_metadata.json"] = {"exists": False}
        summary["issues"].append("vulnerability_metadata.json not found")
        logger.error("vulnerability_metadata.json not found")
    
    # 3. Check checkout_status.json
    status_file = config.data_dir / "checkout_status.json"
    if status_file.exists():
        with open(status_file, 'r') as f:
            checkout_status = json.load(f)
        
        successful = len(checkout_status.get("successful", []))
        failed = len(checkout_status.get("failed", []))
        
        summary["deliverables"]["checkout_status.json"] = {
            "exists": True,
            "successful": successful,
            "failed": failed
        }
        summary["statistics"]["successful_checkouts"] = successful
        summary["statistics"]["failed_checkouts"] = failed
        
        if failed > 0:
            summary["issues"].append(f"{failed} checkouts failed: {checkout_status.get('failed', [])}")
        
        logger.success(f"checkout_status.json: {successful} successful, {failed} failed")
    else:
        summary["deliverables"]["checkout_status.json"] = {"exists": False}
        summary["issues"].append("checkout_status.json not found")
        logger.error("checkout_status.json not found")
    
    # 4. Check vulnerable_code.json
    vuln_code_file = config.data_dir / "vulnerable_code.json"
    if vuln_code_file.exists():
        with open(vuln_code_file, 'r') as f:
            vuln_code = json.load(f)
        
        total_files = sum(v.get("file_count", 0) for v in vuln_code.values())
        
        summary["deliverables"]["vulnerable_code.json"] = {
            "exists": True,
            "vulnerabilities": len(vuln_code),
            "total_files": total_files
        }
        summary["statistics"]["vulnerabilities_with_code"] = len(vuln_code)
        summary["statistics"]["total_vulnerable_files"] = total_files
        
        logger.success(f"vulnerable_code.json: {len(vuln_code)} vulnerabilities, {total_files} files")
    else:
        summary["deliverables"]["vulnerable_code.json"] = {"exists": False}
        summary["issues"].append("vulnerable_code.json not found")
        logger.error("vulnerable_code.json not found")
    
    # 5. Check vulnerabilities directory
    vuln_dir = config.data_dir / "vulnerabilities"
    if vuln_dir.exists():
        checkout_dirs = [d for d in vuln_dir.iterdir() if d.is_dir()]
        summary["deliverables"]["vulnerabilities_directory"] = {
            "exists": True,
            "checkout_count": len(checkout_dirs)
        }
        logger.success(f"vulnerabilities/: {len(checkout_dirs)} checkout directories")
    else:
        summary["deliverables"]["vulnerabilities_directory"] = {"exists": False}
        summary["issues"].append("vulnerabilities/ directory not found")
        logger.error("vulnerabilities/ directory not found")
    
    # 6. Determine overall status
    all_deliverables_exist = all(
        d.get("exists", False) 
        for d in summary["deliverables"].values()
    )
    
    if all_deliverables_exist and len(summary["issues"]) == 0:
        summary["status"] = "SUCCESS"
        summary["ready"] = True
    elif all_deliverables_exist:
        summary["status"] = "SUCCESS_WITH_WARNINGS"
        summary["ready"] = True
    else:
        summary["status"] = "FAILED"
        summary["ready"] = False
    
    # Save summary
    summary_file = config.data_dir / "dataset_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info("=" * 60)
    logger.info("DATASET SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Status: {summary['status']}")
    logger.info(f"Total vulnerabilities: {summary['statistics'].get('total_vulnerabilities', 0)}")
    logger.info(f"Successful checkouts: {summary['statistics'].get('successful_checkouts', 0)}")
    logger.info(f"Failed checkouts: {summary['statistics'].get('failed_checkouts', 0)}")
    logger.info(f"Vulnerabilities with extracted code: {summary['statistics'].get('vulnerabilities_with_code', 0)}")
    logger.info(f"Total vulnerable files: {summary['statistics'].get('total_vulnerable_files', 0)}")
    
    if summary["issues"]:
        logger.warning(f"Issues found: {len(summary['issues'])}")
        for issue in summary["issues"]:
            logger.warning(f"  - {issue}")
    
    logger.info("=" * 60)
    logger.success(f"Dataset summary saved to {summary_file}")
    
    if summary["ready"]:
        logger.success("Dataset is ready for patch generation")
    else:
        logger.error("Dataset is NOT ready. Please fix issues above.")
    
    return summary


if __name__ == "__main__":
    summary = verify_dataset()
    
    print("\n" + "=" * 60)
    print("DATASET VERIFICATION COMPLETE")
    print("=" * 60)
    print(f"Status: {summary['status']}")
    print(f"Total vulnerabilities: {summary['statistics'].get('total_vulnerabilities', 0)}")
    print(f"Successful checkouts: {summary['statistics'].get('successful_checkouts', 0)}")
    print(f"Failed checkouts: {summary['statistics'].get('failed_checkouts', 0)}")
    print(f"Vulnerabilities with code: {summary['statistics'].get('vulnerabilities_with_code', 0)}")
    print(f"Total vulnerable files: {summary['statistics'].get('total_vulnerable_files', 0)}")
    print("=" * 60)
    
    if summary["ready"]:
        print("\n[OK] Dataset ready")
    else:
        print("\n[FAIL] NOT READY - Please fix issues listed above")
