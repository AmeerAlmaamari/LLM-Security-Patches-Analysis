#!/usr/bin/env python3
"""
Results Analysis

Analyzes evaluation results and generates research metrics and reports.
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from loguru import logger

try:
    import pandas as pd
    import numpy as np
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("Warning: pandas/numpy not available. Some features will be limited.")


def setup_logging(log_file: Path):
    """Configure logging."""
    logger.remove()
    logger.add(sys.stderr, level="INFO", format="[{time:YYYY-MM-DD HH:mm:ss}] [{level}] [ANALYZE] {message}")
    logger.add(log_file, level="DEBUG", format="[{time:YYYY-MM-DD HH:mm:ss}] [{level}] [ANALYZE] {message}")
    return logger


def load_evaluation_results(evaluations_dir: Path) -> List[Dict]:
    """Load all evaluation result files."""
    results = []
    
    for eval_file in evaluations_dir.rglob("eval_patch_*.json"):
        try:
            with open(eval_file, 'r', encoding='utf-8') as f:
                result = json.load(f)
                results.append(result)
        except Exception as e:
            logger.warning(f"Failed to load {eval_file}: {e}")
    
    return results


def calculate_research_metrics(results: List[Dict]) -> Dict:
    """
    Calculate research metrics
    """
    metrics = {
        "total_patches": len(results),
        "rq1_vulnerability_fix_rate": 0.0,
        "rq2_correct_and_secure_rate": 0.0,
        "rq3_regression_rate": 0.0,
        "safe_at_k": {},
        "by_model": {},
        "by_vulnerability": {},
        "by_cwe": {}
    }
    
    if not results:
        return metrics
    
    # Count metrics
    pov_passed_count = 0
    correct_and_secure_count = 0
    regressive_count = 0
    
    # Group by model and vulnerability for SAFE@k
    by_model = defaultdict(list)
    by_vuln = defaultdict(list)
    by_cwe = defaultdict(list)
    
    for r in results:
        model = r.get("model_name", "unknown")
        vul_id = r.get("vul_id", "unknown")
        category = r.get("category", "")
        is_regressive = r.get("is_regressive", False)
        
        # Security check
        security = r.get("security", {})
        is_secure = security.get("pov_test_passed", False) or security.get("vulnerability_fixed", False)
        
        # Functionality check
        functionality = r.get("functionality", {})
        is_functional = functionality.get("all_tests_passed", False)
        
        # RQ1: Vulnerability Fix Rate
        if is_secure:
            pov_passed_count += 1
        
        # RQ2: Correct & Secure Rate
        if category == "correct_and_secure":
            correct_and_secure_count += 1
        
        # RQ3: Regression Rate
        if is_regressive:
            regressive_count += 1
        
        # Store for SAFE@k calculation
        by_model[model].append({
            "vul_id": vul_id,
            "patch_index": r.get("patch_index", 0),
            "is_secure": is_secure,
            "is_functional": is_functional,
            "category": category
        })
        
        by_vuln[vul_id].append({
            "model": model,
            "patch_index": r.get("patch_index", 0),
            "is_secure": is_secure,
            "is_functional": is_functional,
            "category": category
        })
    
    total = len(results)
    
    # Calculate rates
    metrics["rq1_vulnerability_fix_rate"] = (pov_passed_count / total * 100) if total > 0 else 0
    metrics["rq2_correct_and_secure_rate"] = (correct_and_secure_count / total * 100) if total > 0 else 0
    metrics["rq3_regression_rate"] = (regressive_count / total * 100) if total > 0 else 0
    
    # Calculate SAFE@k for each model
    for model, patches in by_model.items():
        model_metrics = calculate_model_metrics(patches)
        metrics["by_model"][model] = model_metrics
        metrics["safe_at_k"][model] = model_metrics["safe_at_k"]
    
    # Calculate per-vulnerability metrics
    for vul_id, patches in by_vuln.items():
        vuln_metrics = {
            "total": len(patches),
            "secure": sum(1 for p in patches if p["is_secure"]),
            "functional": sum(1 for p in patches if p["is_functional"]),
            "correct_and_secure": sum(1 for p in patches if p["category"] == "correct_and_secure")
        }
        vuln_metrics["fix_rate"] = (vuln_metrics["secure"] / vuln_metrics["total"] * 100) if vuln_metrics["total"] > 0 else 0
        metrics["by_vulnerability"][vul_id] = vuln_metrics
    
    return metrics


def calculate_model_metrics(patches: List[Dict]) -> Dict:
    """Calculate metrics for a single model."""
    total = len(patches)
    
    if total == 0:
        return {
            "total": 0,
            "secure": 0,
            "functional": 0,
            "correct_and_secure": 0,
            "insecure": 0,
            "breaking": 0,
            "insecure_and_breaking": 0,
            "vulnerability_fix_rate": 0.0,
            "correct_and_secure_rate": 0.0,
            "safe_at_k": 0.0
        }
    
    secure_count = sum(1 for p in patches if p["is_secure"])
    functional_count = sum(1 for p in patches if p["is_functional"])
    
    # Category counts
    categories = defaultdict(int)
    for p in patches:
        categories[p["category"]] += 1
    
    # SAFE@k calculation
    # Group by vulnerability, then calculate per-vulnerability SAFE@k
    by_vuln = defaultdict(list)
    for p in patches:
        by_vuln[p["vul_id"]].append(p)
    
    safe_at_k_values = []
    for vul_id, vuln_patches in by_vuln.items():
        k = len(vuln_patches)
        if k > 0:
            # SAFE@k = (1/k) * Σ(S_i * F_i)
            safe_sum = sum(1 for p in vuln_patches if p["is_secure"] and p["is_functional"])
            safe_at_k = safe_sum / k
            safe_at_k_values.append(safe_at_k)
    
    avg_safe_at_k = sum(safe_at_k_values) / len(safe_at_k_values) if safe_at_k_values else 0
    
    return {
        "total": total,
        "secure": secure_count,
        "functional": functional_count,
        "correct_and_secure": categories.get("correct_and_secure", 0),
        "insecure": categories.get("insecure", 0),
        "breaking": categories.get("breaking", 0),
        "insecure_and_breaking": categories.get("insecure_and_breaking", 0),
        "compile_error": categories.get("compile_error", 0),
        "evaluation_error": categories.get("evaluation_error", 0),
        "vulnerability_fix_rate": (secure_count / total * 100),
        "correct_and_secure_rate": (categories.get("correct_and_secure", 0) / total * 100),
        "safe_at_k": avg_safe_at_k
    }


def generate_statistics(results: List[Dict], metrics: Dict) -> Dict:
    """Generate statistical analysis."""
    stats = {
        "summary": {
            "total_patches": len(results),
            "total_vulnerabilities": len(set(r.get("vul_id") for r in results)),
            "total_models": len(set(r.get("model_name") for r in results)),
            "evaluation_date": datetime.now().isoformat()
        },
        "category_distribution": {},
        "model_comparison": {},
        "test_statistics": {}
    }
    
    # Category distribution
    categories = defaultdict(int)
    for r in results:
        categories[r.get("category", "unknown")] += 1
    
    total = len(results)
    for cat, count in categories.items():
        stats["category_distribution"][cat] = {
            "count": count,
            "percentage": (count / total * 100) if total > 0 else 0
        }
    
    # Model comparison
    stats["model_comparison"] = metrics.get("by_model", {})
    
    # Test statistics
    test_stats = {
        "avg_tests_run": 0,
        "avg_tests_passed": 0,
        "avg_pass_rate": 0,
        "compile_success_rate": 0
    }
    
    tests_run = []
    tests_passed = []
    pass_rates = []
    compile_success = 0
    
    for r in results:
        func = r.get("functionality", {})
        sec = r.get("security", {})
        
        if func.get("tests_run", 0) > 0:
            tests_run.append(func["tests_run"])
            tests_passed.append(func.get("tests_passed", 0))
            pass_rates.append(func.get("pass_rate", 0))
        
        if sec.get("compile_success", False):
            compile_success += 1
    
    if tests_run:
        test_stats["avg_tests_run"] = sum(tests_run) / len(tests_run)
        test_stats["avg_tests_passed"] = sum(tests_passed) / len(tests_passed)
        test_stats["avg_pass_rate"] = sum(pass_rates) / len(pass_rates) * 100
    
    test_stats["compile_success_rate"] = (compile_success / total * 100) if total > 0 else 0
    stats["test_statistics"] = test_stats
    
    return stats


def generate_latex_table(metrics: Dict) -> str:
    """Generate LaTeX table for paper."""
    latex = r"""
\begin{table}[h]
\centering
\caption{Patch Generation Results by Model}
\label{tab:results}
\begin{tabular}{lcccccc}
\toprule
\textbf{Model} & \textbf{Total} & \textbf{Fix Rate} & \textbf{C\&S Rate} & \textbf{SAFE@k} & \textbf{Compile} \\
\midrule
"""
    
    for model, stats in metrics.get("by_model", {}).items():
        latex += f"{model} & {stats['total']} & {stats['vulnerability_fix_rate']:.1f}\\% & "
        latex += f"{stats['correct_and_secure_rate']:.1f}\\% & {stats['safe_at_k']:.3f} & "
        compile_rate = 100 - (stats.get('compile_error', 0) / stats['total'] * 100) if stats['total'] > 0 else 0
        latex += f"{compile_rate:.1f}\\% \\\\\n"
    
    latex += r"""
\bottomrule
\end{tabular}
\end{table}
"""
    return latex


def generate_category_table(metrics: Dict) -> str:
    """Generate category breakdown table."""
    latex = r"""
\begin{table}[h]
\centering
\caption{Patch Categories by Model}
\label{tab:categories}
\begin{tabular}{lccccc}
\toprule
\textbf{Model} & \textbf{C\&S} & \textbf{Insecure} & \textbf{Breaking} & \textbf{I\&B} & \textbf{Error} \\
\midrule
"""
    
    for model, stats in metrics.get("by_model", {}).items():
        latex += f"{model} & {stats.get('correct_and_secure', 0)} & "
        latex += f"{stats.get('insecure', 0)} & {stats.get('breaking', 0)} & "
        latex += f"{stats.get('insecure_and_breaking', 0)} & "
        latex += f"{stats.get('compile_error', 0) + stats.get('evaluation_error', 0)} \\\\\n"
    
    latex += r"""
\bottomrule
\end{tabular}
\end{table}
"""
    return latex


def generate_summary_markdown(metrics: Dict, stats: Dict) -> str:
    """Generate final summary in Markdown format."""
    md = f"""# Patch Generation Experiment Results


"""
    
    for model, model_stats in metrics.get("by_model", {}).items():
        compile_rate = 100 - (model_stats.get('compile_error', 0) / model_stats['total'] * 100) if model_stats['total'] > 0 else 0
        md += f"| {model} | {model_stats['total']} | {model_stats['vulnerability_fix_rate']:.1f}% | "
        md += f"{model_stats['correct_and_secure_rate']:.1f}% | {model_stats['safe_at_k']:.3f} | {compile_rate:.1f}% |\n"
    
    md += """
## Category Distribution

| Category | Count | Percentage |
|----------|-------|------------|
"""
    
    for cat, cat_stats in stats.get("category_distribution", {}).items():
        md += f"| {cat} | {cat_stats['count']} | {cat_stats['percentage']:.1f}% |\n"
    
    md += f"""
## Test Statistics

- **Average Tests Run:** {stats['test_statistics']['avg_tests_run']:.1f}
- **Average Tests Passed:** {stats['test_statistics']['avg_tests_passed']:.1f}
- **Average Pass Rate:** {stats['test_statistics']['avg_pass_rate']:.1f}%
- **Compile Success Rate:** {stats['test_statistics']['compile_success_rate']:.1f}%

"""
    
    return md


def main():
    parser = argparse.ArgumentParser(description="Analyze evaluation results")
    parser.add_argument("--evaluations-dir", type=str, help="Directory containing evaluation results")
    parser.add_argument("--output-dir", type=str, help="Output directory for analysis")
    args = parser.parse_args()
    
    # Setup paths
    project_root = Path(__file__).parent.parent
    evaluations_dir = Path(args.evaluations_dir) if args.evaluations_dir else project_root / "results" / "evaluations"
    output_dir = Path(args.output_dir) if args.output_dir else project_root / "results" / "analysis"
    logs_dir = project_root / "logs"
    
    # Create directories
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "tables").mkdir(exist_ok=True)
    (output_dir / "figures").mkdir(exist_ok=True)
    logs_dir.mkdir(exist_ok=True)
    
    # Setup logging
    log_file = logs_dir / "analysis.log"
    log = setup_logging(log_file)
    
    log.info("=" * 60)
    log.info("Results Analysis")
    log.info("=" * 60)
    
    # Load results
    log.info(f"Loading evaluation results from {evaluations_dir}...")
    results = load_evaluation_results(evaluations_dir)
    log.info(f"Loaded {len(results)} evaluation results")
    
    if not results:
        log.error("No evaluation results found")
        return 1
    
    # Calculate research metrics
    log.info("Calculating research metrics...")
    metrics = calculate_research_metrics(results)
    
    # Save metrics
    metrics_file = output_dir / "research_metrics.json"
    with open(metrics_file, 'w') as f:
        json.dump(metrics, f, indent=2)
    log.info(f"Saved metrics to {metrics_file}")
    
    # Generate statistics
    log.info("Generating statistical analysis...")
    stats = generate_statistics(results, metrics)
    
    stats_file = output_dir / "statistics.json"
    with open(stats_file, 'w') as f:
        json.dump(stats, f, indent=2)
    log.info(f"Saved statistics to {stats_file}")
    
    # Generate LaTeX tables
    log.info("Generating LaTeX tables...")
    
    results_table = generate_latex_table(metrics)
    with open(output_dir / "tables" / "results_table.tex", 'w') as f:
        f.write(results_table)
    
    category_table = generate_category_table(metrics)
    with open(output_dir / "tables" / "category_table.tex", 'w') as f:
        f.write(category_table)
    
    log.info("Saved LaTeX tables")
    
    # Generate summary
    log.info("Generating final summary...")
    summary_md = generate_summary_markdown(metrics, stats)
    
    summary_file = output_dir / "final_summary.md"
    with open(summary_file, 'w') as f:
        f.write(summary_md)
    log.info(f"Saved summary to {summary_file}")
    
    # Print summary
    log.info("=" * 60)
    log.info("Analysis Complete")
    log.info("=" * 60)
    log.info(f"Total patches analyzed: {metrics['total_patches']}")
    log.info(f"RQ1 - Vulnerability Fix Rate: {metrics['rq1_vulnerability_fix_rate']:.1f}%")
    log.info(f"RQ2 - Correct & Secure Rate: {metrics['rq2_correct_and_secure_rate']:.1f}%")
    log.info(f"RQ3 - Regression Rate: {metrics['rq3_regression_rate']:.1f}%")
    
    log.info("SAFE@k by model:")
    for model, safe_k in metrics.get("safe_at_k", {}).items():
        log.info(f"  {model}: {safe_k:.3f}")
    
    log.info(f"Results saved to: {output_dir}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
