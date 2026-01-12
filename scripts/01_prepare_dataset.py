"""
Dataset Preparation Script

Loads vulnerability list and metadata from Vul4J dataset.
"""

import json
import csv
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from logger import init_phase_logger
from config import get_config


def load_vulnerability_list(vul4j_dir: Path) -> list:
    """
    Load the list of reproducible vulnerabilities from successful_vulns.txt in the dataset.
    
    Returns:
        List of vulnerability IDs
    """
    vulns_file = vul4j_dir / "reproduction" / "successful_vulns.txt"
    
    with open(vulns_file, 'r') as f:
        vulns = [line.strip() for line in f if line.strip()]
    
    return vulns


def load_vulnerability_metadata(vul4j_dir: Path, vuln_ids: list) -> dict:
    """
    Load metadata for each vulnerability from vul4j_dataset.csv.
    """
    csv_file = vul4j_dir / "dataset" / "vul4j_dataset.csv"
    metadata = {}
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            vul_id = row.get('vul_id')
            if vul_id in vuln_ids:
                metadata[vul_id] = {
                    'vul_id': vul_id,
                    'cve_id': row.get('cve_id', ''),
                    'cwe_id': row.get('cwe_id', ''),
                    'cwe_name': row.get('cwe_name', ''),
                    'repo_slug': row.get('repo_slug', ''),
                    'human_patch_url': row.get('human_patch', ''),
                    'failing_tests': row.get('failing_tests', ''),
                    'compile_cmd': row.get('compile_cmd', ''),
                    'test_all_cmd': row.get('test_all_cmd', ''),
                    'test_cmd': row.get('test_cmd', ''),
                    'build_system': row.get('build_system', ''),
                    'compliance_level': row.get('compliance_level', ''),
                }
    
    return metadata


def main():
    # Initialize
    config = get_config()
    logger = init_phase_logger("PREPARE", "prepare_dataset.log", str(config.logs_dir))
    
    logger.info("Starting: Dataset Preparation")
    
    # Load vulnerability list
    logger.info("Loading vulnerability list from successful_vulns.txt...")
    vuln_ids = load_vulnerability_list(config.vul4j_dir)
    logger.success(f"Loaded {len(vuln_ids)} reproducible vulnerabilities")
    
    # Save vulnerability list
    vuln_list_file = config.data_dir / "vulnerability_list.json"
    with open(vuln_list_file, 'w') as f:
        json.dump(vuln_ids, f, indent=2)
    logger.info(f"Saved vulnerability list to {vuln_list_file}")
    
    # Load vulnerability metadata
    logger.info("Loading vulnerability metadata from vul4j_dataset.csv...")
    metadata = load_vulnerability_metadata(config.vul4j_dir, vuln_ids)
    logger.success(f"Metadata loaded for {len(metadata)} vulnerabilities")
    
    # Save metadata
    metadata_file = config.data_dir / "vulnerability_metadata.json"
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"Saved metadata to {metadata_file}")
    
    # Print CWE distribution
    cwe_counts = {}
    for vul_id, meta in metadata.items():
        cwe = meta.get('cwe_id', 'Unknown')
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    
    logger.info("CWE Distribution:")
    for cwe, count in sorted(cwe_counts.items(), key=lambda x: -x[1]):
        logger.info(f"  {cwe}: {count} vulnerabilities")
    
    return vuln_ids, metadata


if __name__ == "__main__":
    vuln_ids, metadata = main()
    print(f"\nLoaded {len(vuln_ids)} vulnerabilities with metadata")
