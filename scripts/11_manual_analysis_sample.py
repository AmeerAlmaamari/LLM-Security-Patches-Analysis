"""
Manual Analysis Sample Selection
"""

import json
import csv
import sys
import random
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
from collections import defaultdict

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from logger import init_phase_logger
from config import get_config

# Configuration
SAMPLE_SIZE = 100  # Total patches to sample
RANDOM_SEED = 42   # For reproducibility


def load_evaluation_results(config) -> List[Dict]:
    """Load all evaluation results from the evaluations directory."""
    evaluations_dir = config.results_dir / "evaluations"
    all_results = []
    
    if not evaluations_dir.exists():
        return []
    
    for eval_file in evaluations_dir.glob("*.json"):
        try:
            with open(eval_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Handle both single result and list of results
            if isinstance(data, list):
                all_results.extend(data)
            elif isinstance(data, dict):
                # Check if it's a summary file or individual result
                if "patches" in data:
                    all_results.extend(data["patches"])
                elif "vul_id" in data:
                    all_results.append(data)
        except Exception as e:
            continue
    
    return all_results


def load_patches_from_directory(config) -> List[Dict]:
    """Load patch metadata from patches directory structure."""
    patches_dir = config.results_dir / "patches"
    all_patches = []
    
    if not patches_dir.exists():
        return []
    
    for vul_dir in patches_dir.iterdir():
        if not vul_dir.is_dir() or vul_dir.name.startswith('.'):
            continue
        
        vul_id = vul_dir.name
        
        for model_dir in vul_dir.iterdir():
            if not model_dir.is_dir():
                continue
            
            model_name = model_dir.name
            
            # Load generation metadata if exists
            metadata_file = model_dir / "generation_metadata.json"
            metadata = {}
            if metadata_file.exists():
                try:
                    with open(metadata_file, 'r', encoding='utf-8') as f:
                        metadata = json.load(f)
                except:
                    pass
            
            # Find all patch files
            for patch_file in model_dir.glob("patch_*.java"):
                patch_idx = patch_file.stem.replace("patch_", "")
                
                all_patches.append({
                    "vul_id": vul_id,
                    "model": model_name,
                    "patch_idx": patch_idx,
                    "patch_file": str(patch_file),
                    "cwe_id": metadata.get("cwe_id", ""),
                    "cwe_name": metadata.get("cwe_name", "")
                })
            
            # Handle multi-file patches (subdirectories)
            for subdir in model_dir.iterdir():
                if subdir.is_dir() and subdir.name.startswith("patch_"):
                    patch_idx = subdir.name.replace("patch_", "")
                    mapping_file = subdir / "_file_mapping.json"
                    
                    all_patches.append({
                        "vul_id": vul_id,
                        "model": model_name,
                        "patch_idx": patch_idx,
                        "patch_file": str(subdir),
                        "is_multi_file": True,
                        "cwe_id": metadata.get("cwe_id", ""),
                        "cwe_name": metadata.get("cwe_name", "")
                    })
    
    return all_patches


def load_vulnerability_metadata(config) -> Dict:
    """Load vulnerability metadata for CWE information."""
    metadata_file = config.data_dir / "vulnerability_metadata.json"
    if metadata_file.exists():
        with open(metadata_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def stratified_sample(
    patches: List[Dict],
    sample_size: int,
    vuln_metadata: Dict,
    logger
) -> List[Dict]:
    """
    Select a stratified sample of patches.
    
    Stratification strategy:
    1. Group by CWE type
    2. Within each CWE, sample proportionally
    3. Ensure at least 1 patch per CWE if possible
    """
    random.seed(RANDOM_SEED)
    
    # Enrich patches with CWE info
    for patch in patches:
        vul_id = patch.get("vul_id", "")
        if vul_id in vuln_metadata:
            meta = vuln_metadata[vul_id]
            patch["cwe_id"] = meta.get("cwe_id", patch.get("cwe_id", ""))
            patch["cwe_name"] = meta.get("cwe_name", patch.get("cwe_name", ""))
            patch["project"] = meta.get("project", "")
    
    # Group by CWE
    by_cwe = defaultdict(list)
    for patch in patches:
        cwe = patch.get("cwe_id", "unknown")
        by_cwe[cwe].append(patch)
    
    logger.info(f"Found {len(by_cwe)} unique CWE types")
    
    # Calculate proportional allocation
    total_patches = len(patches)
    sample = []
    
    # First pass: ensure at least 1 per CWE
    remaining_size = sample_size
    for cwe, cwe_patches in by_cwe.items():
        if remaining_size > 0 and cwe_patches:
            selected = random.choice(cwe_patches)
            sample.append(selected)
            cwe_patches.remove(selected)
            remaining_size -= 1
    
    # Second pass: proportional allocation of remaining slots
    if remaining_size > 0:
        # Flatten remaining patches
        remaining_patches = []
        for cwe_patches in by_cwe.values():
            remaining_patches.extend(cwe_patches)
        
        if remaining_patches:
            additional = random.sample(
                remaining_patches, 
                min(remaining_size, len(remaining_patches))
            )
            sample.extend(additional)
    
    logger.info(f"Selected {len(sample)} patches for manual review")
    
    # Log distribution
    sample_by_cwe = defaultdict(int)
    for patch in sample:
        sample_by_cwe[patch.get("cwe_id", "unknown")] += 1
    
    logger.info("Sample distribution by CWE:")
    for cwe, count in sorted(sample_by_cwe.items(), key=lambda x: -x[1]):
        logger.info(f"  {cwe}: {count} patches")
    
    return sample


def create_review_template(sample: List[Dict], config, logger) -> None:
    """Create a CSV template for manual review."""
    output_dir = config.results_dir / "analysis"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    csv_file = output_dir / "manual_sample.csv"
    
    fieldnames = [
        "vul_id",
        "model",
        "patch_idx",
        "cwe_id",
        "cwe_name",
        "project",
        "patch_file",
        "is_multi_file",
        # Manual review fields
        "actual_category",       # Manual classification category
        "actual_subcategory",    # Manual classification subcategory
        # Evaluation metrics (to be filled from evaluation results)
        "compile_success",       # Y/N - Did the patch compile?
        "pov_passed",            # Y/N - Did the patch fix the vulnerability?
        "tests_passed",          # Number of tests passed
        "tests_run",             # Total tests run
        "srs",                   # Security Repair Score
        "security_score",        # Security score (0-1)
        "functionality_score"    # Functionality score (0-1)
    ]
    
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for patch in sample:
            row = {
                "vul_id": patch.get("vul_id", ""),
                "model": patch.get("model", ""),
                "patch_idx": patch.get("patch_idx", ""),
                "cwe_id": patch.get("cwe_id", ""),
                "cwe_name": patch.get("cwe_name", ""),
                "project": patch.get("project", ""),
                "patch_file": patch.get("patch_file", ""),
                "is_multi_file": patch.get("is_multi_file", False),
                "actual_category": "",
                "actual_subcategory": "",
                "compile_success": "",
                "pov_passed": "",
                "tests_passed": "",
                "tests_run": "",
                "srs": "",
                "security_score": "",
                "functionality_score": ""
            }
            writer.writerow(row)
    
    logger.info(f"Created review template: {csv_file}")


def main():
    """Main function to select manual analysis sample."""
    config = get_config()
    logger = init_phase_logger("SAMPLE", "manual_sample.log", str(config.logs_dir))
    
    logger.info("=" * 60)
    logger.info("Manual Analysis Sample Selection")
    logger.info("=" * 60)
    logger.info(f"Target sample size: {SAMPLE_SIZE}")
    logger.info(f"Random seed: {RANDOM_SEED}")
    
    # Load patches
    logger.info("\n[1/4] Loading patches...")
    patches = load_patches_from_directory(config)
    logger.info(f"Found {len(patches)} patches")
    
    if not patches:
        logger.error("No patches found. Run patch generation first.")
        sys.exit(1)
    
    # Load vulnerability metadata
    logger.info("\n[2/4] Loading vulnerability metadata...")
    vuln_metadata = load_vulnerability_metadata(config)
    logger.info(f"Loaded metadata for {len(vuln_metadata)} vulnerabilities")
    
    # Select stratified sample
    logger.info("\n[3/4] Selecting stratified sample...")
    sample = stratified_sample(patches, SAMPLE_SIZE, vuln_metadata, logger)
    
    # Save sample
    logger.info("\n[4/4] Saving sample...")
    output_dir = config.results_dir / "analysis"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save JSON
    json_file = output_dir / "manual_sample.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump({
            "sample_size": len(sample),
            "random_seed": RANDOM_SEED,
            "timestamp": datetime.now().isoformat(),
            "patches": sample
        }, f, indent=2)
    logger.info(f"Saved JSON: {json_file}")
    
    # Create CSV template for review
    create_review_template(sample, config, logger)
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("Manual Sample Selection Complete")
    logger.info("=" * 60)
    logger.info(f"Selected {len(sample)} patches for manual review")
    logger.info(f"Output: {output_dir}")
    logger.info("\nNext steps:")
    logger.info("1. Open manual_sample.csv in a spreadsheet")
    logger.info("2. Review each patch and fill in the review columns")
    logger.info("3. Document any edge cases found")


if __name__ == "__main__":
    main()
