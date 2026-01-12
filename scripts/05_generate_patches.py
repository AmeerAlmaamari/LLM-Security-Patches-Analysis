"""
Patch Generation Script

Generates patches for all vulnerabilities using LLMs via OpenRouter API.
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from logger import init_phase_logger
from config import get_config
from patch_generator import PatchGenerator


def load_vulnerable_code(config, vul_id: str) -> dict:
    """
    Load vulnerable code data for a specific vulnerability.
    """
    vuln_code_file = config.data_dir / "vulnerable_code.json"
    with open(vuln_code_file, 'r', encoding='utf-8') as f:
        all_vuln_code = json.load(f)
    
    vuln_data = all_vuln_code.get(vul_id)
    
    if vuln_data:
        # Load CWE info from metadata file
        metadata_file = config.data_dir / "vulnerability_metadata.json"
        with open(metadata_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        
        meta = metadata.get(vul_id, {})
        vuln_data["cwe_id"] = meta.get("cwe_id", "Unknown")
        vuln_data["cwe_name"] = meta.get("cwe_name", "Unknown")
    
    return vuln_data


def run_generation(
    vuln_ids: list = None,
    model_names: list = None,
    n_patches: int = None,
    dry_run: bool = False
):
    """
    Run patch generation for specified vulnerabilities and models.
    """
    config = get_config()
    logger = init_phase_logger("GENERATE", "generation.log", str(config.logs_dir))
    
    logger.info("=" * 60)
    logger.info("Patch Generation")
    logger.info("=" * 60)
    
    # Load vulnerability list
    if vuln_ids is None:
        vuln_list_file = config.data_dir / "vulnerability_list.json"
        with open(vuln_list_file, 'r') as f:
            vuln_ids = json.load(f)
    
    # Get models to use
    if model_names is None:
        models = config.models
    else:
        models = [m for m in config.models if m.name in model_names]
    
    # Get number of patches
    if n_patches is None:
        n_patches = config.n_samples
    
    logger.info(f"Vulnerabilities: {len(vuln_ids)}")
    logger.info(f"Models: {[m.name for m in models]}")
    logger.info(f"Patches per vuln/model: {n_patches}")
    logger.info(f"Total patches to generate: {len(vuln_ids) * len(models) * n_patches}")
    
    if dry_run:
        logger.info("DRY RUN - No patches will be generated")
        return
    
    # Initialize generator
    generator = PatchGenerator(logger)
    
    # Check API connection first
    logger.info("Testing API connection...")
    for model in models:
        if not generator.client.test_connection(model):
            logger.error(f"Failed to connect with {model.name}. Check your API key.")
            return
    
    # Track progress
    progress = {
        "start_time": datetime.now().isoformat(),
        "total_vulns": len(vuln_ids),
        "total_models": len(models),
        "n_patches": n_patches,
        "completed": [],
        "skipped": [],
        "failed": []
    }
    
    # Load existing progress if resuming
    progress_file = config.results_dir / "generation_progress.json"
    if progress_file.exists():
        with open(progress_file, 'r') as f:
            existing_progress = json.load(f)
            progress["completed"] = existing_progress.get("completed", [])
            progress["skipped"] = existing_progress.get("skipped", [])
            logger.info(f"Resuming: {len(progress['completed'])} already completed")
    
    # Generate patches
    total_combinations = len(vuln_ids) * len(models)
    current = 0
    
    for vul_id in vuln_ids:
        # Load vulnerable code
        vuln_data = load_vulnerable_code(config, vul_id)
        
        if not vuln_data:
            logger.error(f"No vulnerable code found for {vul_id}")
            progress["failed"].append({"vul_id": vul_id, "error": "No vulnerable code"})
            continue
        
        # Get vulnerable files
        vulnerable_files = vuln_data.get("vulnerable_files", [])
        
        if not vulnerable_files:
            logger.error(f"No vulnerable files for {vul_id}")
            progress["failed"].append({"vul_id": vul_id, "error": "No vulnerable files"})
            continue
        
        # Determine if this is a multi-file vulnerability
        is_multi_file = len(vulnerable_files) > 1
        
        for model in models:
            current += 1
            combo_key = f"{vul_id}/{model.name}"
            
            # Check if already complete
            if combo_key in progress["completed"]:
                logger.info(f"[{current}/{total_combinations}] Skipping {combo_key} (already done)")
                continue
            
            # Check if patches already exist
            if generator.is_generation_complete(vul_id, model.name, n_patches):
                logger.info(f"[{current}/{total_combinations}] Skipping {combo_key} (patches exist)")
                progress["skipped"].append(combo_key)
                progress["completed"].append(combo_key)
                continue
            
            # Calculate total code size
            total_chars = sum(len(f.get('vulnerable_code', '')) for f in vulnerable_files)
            
            logger.info(f"\n[{current}/{total_combinations}] Generating patches for {combo_key}")
            logger.info(f"  Progress: {current/total_combinations*100:.1f}% complete")
            logger.info(f"  CWE: {vuln_data.get('cwe_id', 'Unknown')} - {vuln_data.get('cwe_name', 'Unknown')}")
            if is_multi_file:
                logger.info(f"  Multi-file: {len(vulnerable_files)} files, {total_chars:,} chars total")
            else:
                logger.info(f"  Code size: {total_chars:,} chars")
            
            # Get output directory
            output_dir = config.get_patch_dir(vul_id, model.name)
            
            # Generate patches - use appropriate method based on file count
            try:
                if is_multi_file:
                    # Multi-file vulnerability: generate coordinated patches
                    metadata = generator.generate_patches_for_multi_file_vulnerability(
                        vul_id=vul_id,
                        vulnerable_files=vulnerable_files,
                        cwe_id=vuln_data.get("cwe_id", "Unknown"),
                        cwe_name=vuln_data.get("cwe_name", "Unknown"),
                        model=model,
                        n_patches=n_patches,
                        output_dir=output_dir
                    )
                else:
                    # Single-file vulnerability: use original method
                    vulnerable_code = vulnerable_files[0].get("vulnerable_code", "")
                    metadata = generator.generate_patches_for_vulnerability(
                        vul_id=vul_id,
                        vulnerable_code=vulnerable_code,
                        cwe_id=vuln_data.get("cwe_id", "Unknown"),
                        cwe_name=vuln_data.get("cwe_name", "Unknown"),
                        model=model,
                        n_patches=n_patches,
                        output_dir=output_dir
                    )
                
                logger.info(f"  ┌─ Result: {metadata.successful_patches}/{n_patches} patches generated")
                logger.info(f"  ├─ Tokens: {metadata.total_tokens:,}")
                logger.info(f"  ├─ Time: {metadata.total_latency_ms/1000:.1f}s")
                logger.info(f"  └─ Saved to: {output_dir}")
                progress["completed"].append(combo_key)
                
            except Exception as e:
                logger.error(f"  Failed: {e}")
                progress["failed"].append({"vul_id": vul_id, "model": model.name, "error": str(e)})
            
            # Save progress after each combination
            progress["last_update"] = datetime.now().isoformat()
            with open(progress_file, 'w') as f:
                json.dump(progress, f, indent=2)
    
    # Final summary
    progress["end_time"] = datetime.now().isoformat()
    with open(progress_file, 'w') as f:
        json.dump(progress, f, indent=2)
    
    # Print API stats
    stats = generator.client.get_stats()
    
    logger.info("\n" + "=" * 60)
    logger.info("GENERATION COMPLETE")
    logger.info("=" * 60)
    
    logger.info(f"\n OVERVIEW")
    logger.info(f"  Vulnerabilities: {len(vuln_ids)}")
    logger.info(f"  Model: {models[0].name}")
    logger.info(f"  Patches per vulnerability: {n_patches}")
    
    logger.info(f"\n PROGRESS")
    logger.info(f"  Completed: {len(progress['completed'])}/{total_combinations}")
    logger.info(f"  Skipped (already done): {len(progress['skipped'])}")
    logger.info(f"  Failed: {len(progress['failed'])}")
    
    logger.info(f"\n API USAGE")
    logger.info(f"  Total requests: {stats['total_requests']}")
    logger.info(f"  Total tokens: {stats['total_tokens']:,}")
    logger.info(f"  Estimated cost: ${stats['estimated_cost_usd']:.4f}")
    
    logger.info(f"\n Patches saved to: {config.results_dir / 'patches'}")
    logger.info("=" * 60)


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description="Generate patches for vulnerabilities using LLM")
    
    parser.add_argument(
        "--vulns",
        nargs="+",
        help="Specific vulnerability IDs to process (default: all)"
    )
    parser.add_argument(
        "--n-patches",
        type=int,
        default=5,
        help="Number of patches per vulnerability (default: 5)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without generating"
    )
    parser.add_argument(
        "--pilot",
        action="store_true",
        help="Run pilot mode: 3 vulns, 3 patches each"
    )
    
    args = parser.parse_args()
    
    # Pilot mode configuration
    if args.pilot:
        pilot_vulns = ["VUL4J-10", "VUL4J-18", "VUL4J-42"]
        run_generation(
            vuln_ids=pilot_vulns,
            n_patches=3,
            dry_run=args.dry_run
        )
    else:
        run_generation(
            vuln_ids=args.vulns,
            n_patches=args.n_patches,
            dry_run=args.dry_run
        )


if __name__ == "__main__":
    main()
