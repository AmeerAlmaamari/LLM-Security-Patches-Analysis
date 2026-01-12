"""
Extract Vulnerable Code Script

Extracts the vulnerable Java code from each checked-out vulnerability.
The vulnerable code is the version BEFORE the human patch was applied.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from logger import init_phase_logger
from config import get_config


def extract_vulnerable_code_from_checkout(vul_dir: Path, vul_id: str, logger) -> dict:
    """
    Extract vulnerable code from a checked-out vulnerability.
    
    The vulnerable code is found by looking at the human_patch in vulnerability_info.json
    and reading the corresponding source file from the checkout (which is at the vulnerable commit).
    
    Args:
        vul_dir: Path to the vulnerability checkout directory
        vul_id: Vulnerability ID
        logger: Logger instance
        
    Returns:
        dict with vulnerable code info, or None if extraction failed
    """
    info_file = vul_dir / "VUL4J" / "vulnerability_info.json"
    
    if not info_file.exists():
        logger.error(f"{vul_id}: vulnerability_info.json not found")
        return None
    
    try:
        with open(info_file, 'r', encoding='utf-8') as f:
            info = json.load(f)
    except Exception as e:
        logger.error(f"{vul_id}: Failed to read vulnerability_info.json: {e}")
        return None
    
    # Get the file paths from human_patch
    human_patch = info.get("human_patch", [])
    if not human_patch:
        logger.error(f"{vul_id}: No human_patch found in vulnerability_info.json")
        return None
    
    vulnerable_files = []
    
    for patch_info in human_patch:
        file_path = patch_info.get("file_path")
        if not file_path:
            continue
        
        # The vulnerable file is in the checkout directory at the same relative path
        vulnerable_file = vul_dir / file_path
        
        if not vulnerable_file.exists():
            logger.warning(f"{vul_id}: Vulnerable file not found: {file_path}")
            continue
        
        try:
            with open(vulnerable_file, 'r', encoding='utf-8', errors='replace') as f:
                vulnerable_content = f.read()
            
            vulnerable_files.append({
                "file_path": file_path,
                "file_name": Path(file_path).name,
                "vulnerable_code": vulnerable_content,
                "human_patch_code": patch_info.get("content", "")
            })
            
        except Exception as e:
            logger.warning(f"{vul_id}: Failed to read {file_path}: {e}")
            continue
    
    if not vulnerable_files:
        logger.error(f"{vul_id}: No vulnerable files could be extracted")
        return None
    
    return {
        "vul_id": vul_id,
        "cve_id": info.get("cve_id", ""),
        "project": info.get("project", ""),
        "build_system": info.get("build_system", ""),
        "compile_cmd": info.get("compile_cmd", ""),
        "test_cmd": info.get("test_cmd", ""),
        "test_all_cmd": info.get("test_all_cmd", ""),
        "human_patch_url": info.get("human_patch_url", ""),
        "vulnerable_files": vulnerable_files,
        "file_count": len(vulnerable_files)
    }


def main():
    """Main function to extract vulnerable code from all checkouts."""
    config = get_config()
    logger = init_phase_logger("EXTRACT", "extract_code.log", str(config.logs_dir))
    
    logger.info("Starting: Extract Vulnerable Code")
    
    # Load vulnerability list
    vuln_list_file = config.data_dir / "vulnerability_list.json"
    with open(vuln_list_file, 'r') as f:
        vuln_ids = json.load(f)
    
    # Load checkout status to only process successful checkouts
    status_file = config.data_dir / "checkout_status.json"
    if status_file.exists():
        with open(status_file, 'r') as f:
            checkout_status = json.load(f)
        successful_checkouts = checkout_status.get("successful", [])
    else:
        successful_checkouts = vuln_ids
    
    logger.info(f"Processing {len(successful_checkouts)} successful checkouts")
    
    # Extract vulnerable code
    vulnerable_code = {}
    extraction_stats = {
        "total": len(successful_checkouts),
        "successful": 0,
        "failed": 0,
        "failed_ids": []
    }
    
    vulnerabilities_dir = config.data_dir / "vulnerabilities"
    
    for i, vul_id in enumerate(successful_checkouts):
        logger.info(f"[{i+1}/{len(successful_checkouts)}] Extracting {vul_id}...")
        
        vul_dir = vulnerabilities_dir / vul_id
        
        if not vul_dir.exists():
            logger.error(f"{vul_id}: Checkout directory not found")
            extraction_stats["failed"] += 1
            extraction_stats["failed_ids"].append(vul_id)
            continue
        
        result = extract_vulnerable_code_from_checkout(vul_dir, vul_id, logger)
        
        if result:
            vulnerable_code[vul_id] = result
            extraction_stats["successful"] += 1
            logger.success(f"{vul_id}: Extracted {result['file_count']} file(s)")
        else:
            extraction_stats["failed"] += 1
            extraction_stats["failed_ids"].append(vul_id)
    
    # Save vulnerable code
    output_file = config.data_dir / "vulnerable_code.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(vulnerable_code, f, indent=2, ensure_ascii=False)
    
    logger.info("=" * 50)
    logger.info(f"Extraction complete: {extraction_stats['successful']}/{extraction_stats['total']} successful")
    
    if extraction_stats["failed"] > 0:
        logger.warning(f"Failed extractions ({extraction_stats['failed']}): {extraction_stats['failed_ids']}")
    
    logger.success(f"Vulnerable code saved to {output_file}")
    
    return extraction_stats


if __name__ == "__main__":
    stats = main()
    print(f"\nExtraction complete: {stats['successful']}/{stats['total']} successful")
    if stats['failed_ids']:
        print(f"Failed: {stats['failed_ids']}")
