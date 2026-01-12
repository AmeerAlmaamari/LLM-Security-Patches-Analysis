#!/usr/bin/env python3
"""
Patch Evaluation Pipeline

Evaluates generated patches using the tri-axis evaluation protocol.
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Union

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from loguru import logger
from config import ExperimentConfig
from evaluator import PatchEvaluator, EvaluationResult, load_vulnerability_info
from failure_analyzer import classify_patch, get_failure_distribution
from partial_scorer import score_patch, aggregate_scores


def load_human_baselines(data_dir: Path) -> Dict:
    """Load human baselines from JSON file."""
    baselines_file = data_dir / "human_baselines.json"
    if baselines_file.exists():
        with open(baselines_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def setup_logging(log_file: Path):
    """Configure logging."""
    logger.remove()
    logger.add(sys.stderr, level="INFO", format="[{time:YYYY-MM-DD HH:mm:ss}] [{level}] [EVAL] {message}")
    logger.add(log_file, level="DEBUG", format="[{time:YYYY-MM-DD HH:mm:ss}] [{level}] [EVAL] {message}")
    return logger


def load_patches_to_evaluate(
    patches_dir: Path,
    vulns: Optional[List[str]] = None,
    models: Optional[List[str]] = None
) -> List[Dict]:
    """
    Load list of patches to evaluate.
    """
    patches = []
    
    if not patches_dir.exists():
        logger.error(f"Patches directory not found: {patches_dir}")
        return patches
    
    # Iterate through vulnerability directories
    for vul_dir in sorted(patches_dir.iterdir()):
        if not vul_dir.is_dir():
            continue
        
        vul_id = vul_dir.name
        
        # Filter by vulnerability if specified
        if vulns and vul_id not in vulns:
            continue
        
        # Iterate through model directories
        for model_dir in sorted(vul_dir.iterdir()):
            if not model_dir.is_dir():
                continue
            
            model_name = model_dir.name
            
            # Filter by model if specified
            if models and model_name not in models:
                continue
            
            # Find single-file patches (patch_*.java)
            for patch_file in sorted(model_dir.glob("patch_*.java")):
                try:
                    patch_index = int(patch_file.stem.split("_")[1])
                except (IndexError, ValueError):
                    continue
                
                patches.append({
                    "vul_id": vul_id,
                    "model_name": model_name,
                    "patch_index": patch_index,
                    "patch_file": patch_file,
                    "is_multi_file": False
                })
            
            # Find multi-file patches (patch_*/ directories with _file_mapping.json)
            for patch_subdir in sorted(model_dir.glob("patch_*")):
                if not patch_subdir.is_dir():
                    continue
                
                # Check if this is a multi-file patch directory
                mapping_file = patch_subdir / "_file_mapping.json"
                if not mapping_file.exists():
                    continue
                
                try:
                    patch_index = int(patch_subdir.name.split("_")[1])
                except (IndexError, ValueError):
                    continue
                
                patches.append({
                    "vul_id": vul_id,
                    "model_name": model_name,
                    "patch_index": patch_index,
                    "patch_file": patch_subdir,  # Directory for multi-file
                    "is_multi_file": True
                })
    
    return patches


def load_evaluation_progress(progress_file: Path) -> Dict:
    """Load evaluation progress from file."""
    if progress_file.exists():
        with open(progress_file, 'r') as f:
            return json.load(f)
    return {"completed": [], "failed": []}


def save_evaluation_progress(progress_file: Path, progress: Dict):
    """Save evaluation progress to file."""
    with open(progress_file, 'w') as f:
        json.dump(progress, f, indent=2)


def get_evaluation_key(vul_id: str, model_name: str, patch_index: int) -> str:
    """Generate unique key for a patch evaluation."""
    return f"{vul_id}/{model_name}/patch_{patch_index}"


def save_evaluation_result(
    result: EvaluationResult,
    output_dir: Path
):
    """Save evaluation result to JSON file."""
    # Create output directory
    eval_dir = output_dir / result.vul_id / result.model_name
    eval_dir.mkdir(parents=True, exist_ok=True)
    
    # Save individual result
    result_file = eval_dir / f"eval_patch_{result.patch_index}.json"
    with open(result_file, 'w') as f:
        json.dump(result.to_dict(), f, indent=2)
    
    return result_file


def create_evaluation_summary(
    results: List[Union[EvaluationResult, Dict]],
    output_dir: Path
) -> Dict:
    """Create summary of all evaluation results."""
    summary = {
        "total_patches": len(results),
        "by_category": {},
        "by_model": {},
        "by_vulnerability": {},
        "overall_metrics": {
            "correct_and_secure": 0,
            "insecure": 0,
            "breaking": 0,
            "insecure_and_breaking": 0,
            "compile_error": 0,
            "evaluation_error": 0,
            "regressive": 0,
            "security_failure": 0
        }
    }
    
    for res in results:
        # Normalize result to dict
        if hasattr(res, "to_dict"):
            result = res.to_dict()
        else:
            result = res
            
        # Count by category
        category = result.get("category", "evaluation_error")
        summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
        summary["overall_metrics"][category] = summary["overall_metrics"].get(category, 0) + 1
        
        if result.get("is_regressive"):
            summary["overall_metrics"]["regressive"] += 1
        
        # Count by model
        model = result.get("model_name", "unknown")
        if model not in summary["by_model"]:
            summary["by_model"][model] = {
                "total": 0,
                "correct_and_secure": 0,
                "insecure": 0,
                "breaking": 0,
                "compile_error": 0,
                "evaluation_error": 0,
                "security_failure": 0
            }
        summary["by_model"][model]["total"] += 1
        summary["by_model"][model][category] = summary["by_model"][model].get(category, 0) + 1
        
        # Count by vulnerability
        vul_id = result.get("vul_id", "unknown")
        if vul_id not in summary["by_vulnerability"]:
            summary["by_vulnerability"][vul_id] = {
                "total": 0,
                "correct_and_secure": 0,
                "insecure": 0,
                "breaking": 0,
                "security_failure": 0
            }
        summary["by_vulnerability"][vul_id]["total"] += 1
        summary["by_vulnerability"][vul_id][category] = summary["by_vulnerability"][vul_id].get(category, 0) + 1
    
    # Calculate rates
    total = summary["total_patches"]
    if total > 0:
        summary["rates"] = {
            "vulnerability_fix_rate": summary["overall_metrics"]["correct_and_secure"] / total * 100,
            "compile_success_rate": (total - summary["overall_metrics"]["compile_error"]) / total * 100,
            "insecure_rate": summary["overall_metrics"]["insecure"] / total * 100,
            "breaking_rate": summary["overall_metrics"]["breaking"] / total * 100
        }
        
        # Per-model rates
        for model, stats in summary["by_model"].items():
            model_total = stats["total"]
            if model_total > 0:
                stats["vulnerability_fix_rate"] = stats.get("correct_and_secure", 0) / model_total * 100
                stats["compile_success_rate"] = (model_total - stats.get("compile_error", 0)) / model_total * 100
    
    # Save summary
    summary_file = output_dir / "evaluation_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    return summary


def load_all_results_from_disk(evaluations_dir: Path) -> List[Dict]:
    """Load all evaluation results from the evaluations directory."""
    results = []
    if not evaluations_dir.exists():
        return results
    
    # Nested: evaluations/VUL4J-*/model_name/eval_patch_*.json
    for eval_file in evaluations_dir.glob("**/eval_patch_*.json"):
        try:
            with open(eval_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict) and "vul_id" in data:
                results.append(data)
        except Exception:
            continue
            
    # Also check for flat structure if any
    for eval_file in evaluations_dir.glob("eval_patch_*.json"):
        try:
            with open(eval_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict) and "vul_id" in data:
                results.append(data)
        except Exception:
            continue
            
    return results


def main():
    parser = argparse.ArgumentParser(description="Evaluate generated patches")
    parser.add_argument("--vulns", type=str, help="Comma-separated vulnerability IDs to evaluate")
    parser.add_argument("--models", type=str, help="Comma-separated model names to evaluate")
    parser.add_argument("--resume", action="store_true", help="Resume from previous progress")
    parser.add_argument("--docker-container", type=str, default="vul4j", help="Docker container name")
    args = parser.parse_args()
    
    # Setup
    config = ExperimentConfig()
    log_file = config.logs_dir / "evaluation.log"
    log = setup_logging(log_file)
    
    # Parse filters
    vulns = args.vulns.split(",") if args.vulns else None
    models = args.models.split(",") if args.models else None
    
    # Directories
    patches_dir = config.results_dir / "patches"
    evaluations_dir = config.results_dir / "evaluations"
    evaluations_dir.mkdir(parents=True, exist_ok=True)
    
    progress_file = config.results_dir / "evaluation_progress.json"
    
    log.info("=" * 60)
    log.info("Patch Evaluation")
    log.info("=" * 60)
    
    # Load patches to evaluate
    patches = load_patches_to_evaluate(patches_dir, vulns, models)
    log.info(f"Found {len(patches)} patches to evaluate")
    
    if not patches:
        log.error("No patches found to evaluate")
        return 1
    
    # Load progress (always load if exists to avoid overwriting)
    progress = load_evaluation_progress(progress_file)
    
    # Filter out already completed if resuming
    if args.resume:
        completed_keys = set(progress["completed"])
        patches = [p for p in patches if get_evaluation_key(p["vul_id"], p["model_name"], p["patch_index"]) not in completed_keys]
        log.info(f"Resuming: {len(progress['completed'])} already completed, {len(patches)} remaining")
    else:
        log.info("Starting fresh evaluation (progress will be appended)")
    
    # Initialize evaluator
    evaluator = PatchEvaluator(docker_container=args.docker_container)
    
    # Track results
    all_results = []
    completed = 0
    failed = 0
    
    # Group patches by vulnerability for efficiency
    patches_by_vuln = {}
    for p in patches:
        vul_id = p["vul_id"]
        if vul_id not in patches_by_vuln:
            patches_by_vuln[vul_id] = []
        patches_by_vuln[vul_id].append(p)
    
    total_patches = len(patches)
    current = 0
    
    for vul_id, vuln_patches in patches_by_vuln.items():
        log.info(f"Evaluating {len(vuln_patches)} patches for {vul_id}")
        
        # Load vulnerability info
        vuln_info = load_vulnerability_info(vul_id, config.data_dir)
        
        if not vuln_info:
            log.error(f"Could not load vulnerability info for {vul_id}")
            continue
        
        # Get vulnerable file path
        vulnerable_files = vuln_info.get("vulnerable_files", [])
        if not vulnerable_files:
            log.error(f"No vulnerable files found for {vul_id}")
            continue
        
        # Determine if this is a multi-file vulnerability
        is_multi_file_vuln = len(vulnerable_files) > 1
        
        # Use first vulnerable file for single-file cases
        vulnerable_file_path = vulnerable_files[0].get("file_path", "")
        human_patch_code = vulnerable_files[0].get("human_patch_code", "")
        cwe_id = vuln_info.get("cwe_id", "")
        
        # Load human baseline from pre-computed file (faster than re-running)
        human_baselines = load_human_baselines(config.data_dir)
        human_baseline = human_baselines.get(vul_id, {})
        
        # Check if human patch failed to compile (infrastructure issue)
        human_compile_failed = not human_baseline.get("compile_success", True)
        if human_compile_failed:
            log.warning(f"  Human patch FAILED to compile for {vul_id}")
            log.warning(f"     Error: {human_baseline.get('compile_error', 'Unknown')}")
            log.warning(f"     LLM patches will still be evaluated - may succeed where human failed")
        
        # Create baseline_tests object from pre-computed data
        baseline_tests = None
        if human_baseline.get("compile_success"):
            from evaluator import FunctionalityResult
            baseline_tests = FunctionalityResult(
                all_tests_passed=human_baseline.get("tests_failed", 0) == 0,
                tests_run=human_baseline.get("tests_run", 0),
                tests_passed=human_baseline.get("tests_passed", 0),
                tests_failed=human_baseline.get("tests_failed", 0),
                tests_errored=human_baseline.get("tests_errored", 0),
                tests_skipped=human_baseline.get("tests_skipped", 0)
            )
            log.info(f"  Human patch baseline: {baseline_tests.tests_passed}/{baseline_tests.tests_run} tests passed")
        else:
            log.info(f"  No baseline tests available (human patch compile failed)")
        
        for patch_info in vuln_patches:
            current += 1
            patch_key = get_evaluation_key(
                patch_info["vul_id"],
                patch_info["model_name"],
                patch_info["patch_index"]
            )
            
            is_multi_file_patch = patch_info.get("is_multi_file", False)
            
            log.info(f"\n[{current}/{total_patches}] Evaluating {patch_key}")
            log.info(f"  Progress: {current/total_patches*100:.1f}% complete")
            if is_multi_file_patch:
                log.info(f"  Multi-file patch: {len(vulnerable_files)} files")
            
            try:
                # Use appropriate evaluation method based on patch type
                if is_multi_file_patch:
                    result = evaluator.evaluate_multi_file_patch(
                        vul_id=patch_info["vul_id"],
                        model_name=patch_info["model_name"],
                        patch_index=patch_info["patch_index"],
                        patch_dir=patch_info["patch_file"], 
                        vulnerable_files=vulnerable_files,
                        cwe_id=cwe_id,
                        baseline_tests=baseline_tests
                    )
                else:
                    result = evaluator.evaluate_patch(
                        vul_id=patch_info["vul_id"],
                        model_name=patch_info["model_name"],
                        patch_index=patch_info["patch_index"],
                        patch_file=patch_info["patch_file"],
                        vulnerable_file_path=vulnerable_file_path,
                        cwe_id=cwe_id,
                        baseline_tests=baseline_tests
                    )
                
                # Calculate scores
                # For compile-failed human baselines, use LLM's own test count as baseline
                # This allows fair comparison when human patch couldn't compile
                if human_compile_failed:
                    tests_passed_human = result.functionality.tests_passed  # Use LLM's own count
                else:
                    tests_passed_human = baseline_tests.tests_passed if baseline_tests else 0
                
                scores = score_patch(
                    compilation_success=result.security.compile_success,
                    pov_passed=result.security.pov_test_passed or False,
                    tests_passed=result.functionality.tests_passed,
                    tests_passed_human=tests_passed_human,
                    semgrep_warnings_before=0,  # From baseline
                    semgrep_warnings_after=result.security.semgrep_warnings_count
                )
                
                # Add flag for compile-failed human baseline
                result.human_baseline_compile_failed = human_compile_failed
                
                # Store scores in result
                result.security_score = scores.security_score
                result.functionality_score = scores.functionality_score
                result.srs = scores.srs
                
                # Save result
                save_evaluation_result(result, evaluations_dir)
                all_results.append(result)
                
                # Update progress
                progress["completed"].append(patch_key)
                completed += 1
                
                # Update summary incrementally after each evaluation
                all_evaluation_files = load_all_results_from_disk(evaluations_dir)
                create_evaluation_summary(all_evaluation_files, evaluations_dir)
                
                # Comprehensive logging
                log.info(f"  ┌─ Result: {result.category}")
                log.info(f"  ├─ Compile: {'✓' if result.security.compile_success else '✗'}")
                if result.security.compile_success:
                    log.info(f"  ├─ PoV Test: {'✓ FIXED' if result.security.pov_test_passed else '✗ VULNERABLE'}")
                    log.info(f"  ├─ Tests: {result.functionality.tests_passed}/{result.functionality.tests_run} passed")
                    log.info(f"  ├─ Semgrep: {result.security.semgrep_warnings_count} warnings")
                log.info(f"  ├─ SRS: {scores.srs:.4f} (S={scores.security_score:.4f}, F={scores.functionality_score:.4f})")
                log.info(f"  └─ Time: {result.evaluation_time_ms/1000:.1f}s")
                
            except Exception as e:
                log.error(f"  Failed: {e}")
                progress["failed"].append(patch_key)
                failed += 1
            
            # Save progress periodically
            if current % 5 == 0:
                save_evaluation_progress(progress_file, progress)
                # Also update summary periodically
                all_evaluation_files = load_all_results_from_disk(evaluations_dir)
                create_evaluation_summary(all_evaluation_files, evaluations_dir)
    
    # Final progress save
    save_evaluation_progress(progress_file, progress)
    
    # Create summary
    log.info("\n" + "=" * 60)
    log.info("Creating evaluation summary...")
    
    # Reload ALL results from directory to ensure summary is comprehensive
    all_evaluation_files = load_all_results_from_disk(evaluations_dir)
    summary = create_evaluation_summary(all_evaluation_files, evaluations_dir)
    
    # Compute aggregate scores from ALL reloaded results
    scores_list = []
    for res in all_evaluation_files:
        if isinstance(res, dict):
            scores_list.append({
                "security_score": res.get("security_score", 0),
                "functionality_score": res.get("functionality_score", 0),
                "srs": res.get("srs", 0),
                "compilation_success": res.get("security", {}).get("compile_success", False)
            })
    score_agg = aggregate_scores(scores_list)
    
    # Print comprehensive summary
    log.info("\n" + "=" * 60)
    log.info("EVALUATION COMPLETE")
    log.info("=" * 60)
    
    total_on_disk = len(all_evaluation_files)
    log.info(f"\n OVERVIEW (ALL ON DISK)")
    log.info(f"  Total evaluations found: {total_on_disk}")
    log.info(f"  Current session completed: {completed}")
    log.info(f"  Current session failed: {failed}")
    
    if summary.get("rates"):
        log.info(f"\n SUCCESS RATES")
        log.info(f"  Compile Success:     {summary['rates']['compile_success_rate']:.1f}%")
        log.info(f"  Vulnerability Fixed: {summary['rates']['vulnerability_fix_rate']:.1f}%")
    
    log.info(f"\n FAILURE DISTRIBUTION (RQ1)")
    for category, count in sorted(summary.get("by_category", {}).items()):
        pct = count / total_on_disk * 100 if total_on_disk > 0 else 0
        log.info(f"  {category}: {count} ({pct:.1f}%)")
    
    log.info(f"\n SCORE STATISTICS (RQ2)")
    srs_stats = score_agg.get("srs", {})
    log.info(f"  SRS Mean: {srs_stats.get('mean', 0):.4f} (std={srs_stats.get('std', 0):.4f})")
    log.info(f"  SRS Range: [{srs_stats.get('min', 0):.4f}, {srs_stats.get('max', 0):.4f}]")
    sec_stats = score_agg.get("security_score", {})
    log.info(f"  Security Score Mean: {sec_stats.get('mean', 0):.4f}")
    func_stats = score_agg.get("functionality_score", {})
    log.info(f"  Functionality Score Mean: {func_stats.get('mean', 0):.4f}")
    
    log.info(f"\n PATCH QUALITY")
    log.info(f"  Perfect (SRS=1.0):          {score_agg.get('perfect_patches', 0)}")
    log.info(f"  Near-success (0.8 <= SRS < 1): {score_agg.get('near_success_patches', 0)}")
    log.info(f"  Partial (0 < SRS < 0.8):    {score_agg.get('partial_success_patches', 0)}")
    log.info(f"  Failed (SRS=0):             {score_agg.get('complete_failure_patches', 0)}")
    
    log.info(f"\n Results saved to: {evaluations_dir}")
    log.info("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
