"""
Score Analysis
"""

import json
import csv
import sys
import math
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
from collections import defaultdict

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from logger import init_phase_logger
from config import get_config
from partial_scorer import aggregate_scores, aggregate_scores_by_model


def load_evaluation_results(config) -> List[Dict]:
    """Load all evaluation results."""
    evaluations_dir = config.results_dir / "evaluations"
    all_results = []
    
    if not evaluations_dir.exists():
        return []
    
    # Handle both flat and nested directory structures
    # Flat: evaluations/*.json
    # Nested: evaluations/VUL4J-*/model_name/eval_patch_*.json
    
    # First try flat structure
    for eval_file in evaluations_dir.glob("*.json"):
        if eval_file.name == "evaluation_summary.json":
            continue
        try:
            with open(eval_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                all_results.extend(data)
            elif isinstance(data, dict):
                if "patches" in data:
                    all_results.extend(data["patches"])
                elif "vul_id" in data:
                    all_results.append(data)
                elif "results" in data:
                    all_results.extend(data["results"])
        except Exception as e:
            continue
    
    # Then try nested structure
    for eval_file in evaluations_dir.glob("**/eval_patch_*.json"):
        try:
            with open(eval_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict) and "vul_id" in data:
                all_results.append(data)
        except Exception as e:
            continue
    
    return all_results


def compute_statistics(values: List[float]) -> Dict:
    """Compute comprehensive statistics for a list of values."""
    if not values:
        return {
            "count": 0,
            "mean": 0.0,
            "std": 0.0,
            "median": 0.0,
            "min": 0.0,
            "max": 0.0,
            "q1": 0.0,
            "q3": 0.0
        }
    
    n = len(values)
    sorted_values = sorted(values)
    
    # Mean
    mean = sum(values) / n
    
    # Standard deviation
    variance = sum((x - mean) ** 2 for x in values) / n
    std = math.sqrt(variance)
    
    # Median
    if n % 2 == 0:
        median = (sorted_values[n // 2 - 1] + sorted_values[n // 2]) / 2
    else:
        median = sorted_values[n // 2]
    
    # Quartiles
    q1_idx = n // 4
    q3_idx = 3 * n // 4
    q1 = sorted_values[q1_idx] if q1_idx < n else 0
    q3 = sorted_values[q3_idx] if q3_idx < n else 0
    
    return {
        "count": n,
        "mean": round(mean, 4),
        "std": round(std, 4),
        "median": round(median, 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "q1": round(q1, 4),
        "q3": round(q3, 4)
    }


def compute_pearson_correlation(x: List[float], y: List[float]) -> Tuple[float, float]:
    """
    Compute Pearson correlation coefficient and p-value.
    
    Returns:
        Tuple of (correlation, p_value)
    """
    if len(x) != len(y) or len(x) < 3:
        return 0.0, 1.0
    
    n = len(x)
    
    # Means
    mean_x = sum(x) / n
    mean_y = sum(y) / n
    
    # Covariance and standard deviations
    cov = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n)) / n
    std_x = math.sqrt(sum((xi - mean_x) ** 2 for xi in x) / n)
    std_y = math.sqrt(sum((yi - mean_y) ** 2 for yi in y) / n)
    
    if std_x == 0 or std_y == 0:
        return 0.0, 1.0
    
    # Correlation
    r = cov / (std_x * std_y)
    
    # P-value approximation using t-distribution
    if abs(r) == 1.0:
        p_value = 0.0
    else:
        t_stat = r * math.sqrt((n - 2) / (1 - r ** 2))
        # Approximate p-value (two-tailed)
        # Using a simple approximation for large n
        p_value = 2 * (1 - min(0.9999, abs(t_stat) / math.sqrt(n)))
    
    return round(r, 4), round(p_value, 4)


def extract_scores(results: List[Dict]) -> Dict[str, List[float]]:
    """Extract score lists from evaluation results."""
    security_scores = []
    functionality_scores = []
    srs_scores = []
    
    for r in results:
        # Try different field names
        sec = r.get("security_score", r.get("scores", {}).get("security_score"))
        func = r.get("functionality_score", r.get("scores", {}).get("functionality_score"))
        srs = r.get("srs", r.get("scores", {}).get("srs"))
        
        if sec is not None:
            security_scores.append(float(sec))
        if func is not None:
            functionality_scores.append(float(func))
        if srs is not None:
            srs_scores.append(float(srs))
    
    return {
        "security_score": security_scores,
        "functionality_score": functionality_scores,
        "srs": srs_scores
    }


def compute_near_success_rate(srs_scores: List[float], threshold: float = 0.8) -> Dict:
    """Compute near-success rate (0.8 <= SRS < 1.0)."""
    if not srs_scores:
        return {"threshold": threshold, "count": 0, "rate": 0.0}
    
    near_success = sum(1 for s in srs_scores if threshold <= s < 1.0)
    
    return {
        "threshold": threshold,
        "count": near_success,
        "rate": round(near_success / len(srs_scores), 4)
    }


def compute_success_tiers(srs_scores: List[float]) -> Dict:
    """Compute distribution across success tiers."""
    if not srs_scores:
        return {}
    
    n = len(srs_scores)
    
    tiers = {
        "perfect": sum(1 for s in srs_scores if s == 1.0),
        "near_success": sum(1 for s in srs_scores if 0.8 <= s < 1.0),
        "partial_success": sum(1 for s in srs_scores if 0.0 < s < 0.8),
        "complete_failure": sum(1 for s in srs_scores if s == 0.0)
    }
    
    return {
        tier: {"count": count, "rate": round(count / n, 4)}
        for tier, count in tiers.items()
    }


def analyze_tradeoff(security_scores: List[float], functionality_scores: List[float]) -> Dict:
    """Analyze security vs functionality trade-off."""
    if len(security_scores) != len(functionality_scores) or not security_scores:
        return {"correlation": 0.0, "p_value": 1.0, "interpretation": "insufficient data"}
    
    r, p = compute_pearson_correlation(security_scores, functionality_scores)
    
    # Interpretation
    if p > 0.05:
        interpretation = "no significant correlation"
    elif r > 0.5:
        interpretation = "strong positive correlation (security and functionality aligned)"
    elif r > 0.2:
        interpretation = "moderate positive correlation"
    elif r > -0.2:
        interpretation = "weak or no correlation"
    elif r > -0.5:
        interpretation = "moderate negative correlation (trade-off exists)"
    else:
        interpretation = "strong negative correlation (significant trade-off)"
    
    return {
        "correlation": r,
        "p_value": p,
        "significant": p < 0.05,
        "interpretation": interpretation
    }


def analyze_by_model(results: List[Dict], logger) -> Dict:
    """Analyze scores grouped by model."""
    by_model = defaultdict(list)
    
    for r in results:
        model = r.get("model", r.get("model_name", "unknown"))
        by_model[model].append(r)
    
    model_analysis = {}
    for model, model_results in by_model.items():
        scores = extract_scores(model_results)
        
        model_analysis[model] = {
            "count": len(model_results),
            "security_score": compute_statistics(scores["security_score"]),
            "functionality_score": compute_statistics(scores["functionality_score"]),
            "srs": compute_statistics(scores["srs"]),
            "near_success": compute_near_success_rate(scores["srs"]),
            "success_tiers": compute_success_tiers(scores["srs"]),
            "tradeoff": analyze_tradeoff(scores["security_score"], scores["functionality_score"])
        }
        
        logger.info(f"  {model}: {len(model_results)} patches, "
                   f"SRS mean={model_analysis[model]['srs']['mean']:.3f}")
    
    return model_analysis


def analyze_by_cwe(results: List[Dict], vuln_metadata: Dict, logger) -> Dict:
    """Analyze scores grouped by CWE type."""
    by_cwe = defaultdict(list)
    
    for r in results:
        vul_id = r.get("vul_id", "")
        cwe_id = r.get("cwe_id", "")
        
        if not cwe_id and vul_id in vuln_metadata:
            cwe_id = vuln_metadata[vul_id].get("cwe_id", "unknown")
        
        by_cwe[cwe_id].append(r)
    
    cwe_analysis = {}
    for cwe, cwe_results in by_cwe.items():
        scores = extract_scores(cwe_results)
        
        cwe_analysis[cwe] = {
            "count": len(cwe_results),
            "security_score": compute_statistics(scores["security_score"]),
            "functionality_score": compute_statistics(scores["functionality_score"]),
            "srs": compute_statistics(scores["srs"]),
            "near_success": compute_near_success_rate(scores["srs"])
        }
    
    logger.info(f"Analyzed {len(cwe_analysis)} CWE types")
    
    return cwe_analysis


def generate_latex_table(overall: Dict, by_model: Dict, output_path: Path, logger) -> None:
    """Generate LaTeX table for scores."""
    
    latex = []
    latex.append("\\begin{table}[htbp]")
    latex.append("\\centering")
    latex.append("\\caption{Score Statistics Summary}")
    latex.append("\\label{tab:scores}")
    latex.append("\\begin{tabular}{lcccc}")
    latex.append("\\toprule")
    latex.append("\\textbf{Metric} & \\textbf{Mean} & \\textbf{Std} & \\textbf{Median} & \\textbf{Range} \\\\")
    latex.append("\\midrule")
    
    # Overall scores
    for metric, label in [
        ("security_score", "Security Score"),
        ("functionality_score", "Functionality Score"),
        ("srs", "SRS")
    ]:
        stats = overall.get(metric, {})
        mean = stats.get("mean", 0)
        std = stats.get("std", 0)
        median = stats.get("median", 0)
        min_val = stats.get("min", 0)
        max_val = stats.get("max", 0)
        
        latex.append(f"{label} & {mean:.3f} & {std:.3f} & {median:.3f} & [{min_val:.2f}, {max_val:.2f}] \\\\")
    
    latex.append("\\bottomrule")
    latex.append("\\end{tabular}")
    latex.append("\\end{table}")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(latex))
    
    logger.info(f"Generated LaTeX table: {output_path}")


def save_csv_summary(overall: Dict, by_model: Dict, output_path: Path, logger) -> None:
    """Save CSV summary of score analysis."""
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Overall statistics
        writer.writerow(["=== Overall Score Statistics ==="])
        writer.writerow(["Metric", "Mean", "Std", "Median", "Min", "Max", "Q1", "Q3"])
        
        for metric in ["security_score", "functionality_score", "srs"]:
            stats = overall.get(metric, {})
            writer.writerow([
                metric,
                stats.get("mean", 0),
                stats.get("std", 0),
                stats.get("median", 0),
                stats.get("min", 0),
                stats.get("max", 0),
                stats.get("q1", 0),
                stats.get("q3", 0)
            ])
        
        writer.writerow([])
        
        # Near-success rate
        writer.writerow(["=== Near-Success Rate (0.8 <= SRS < 1.0) ==="])
        ns = overall.get("near_success", {})
        writer.writerow(["Count", "Rate"])
        writer.writerow([ns.get("count", 0), f"{ns.get('rate', 0):.2%}"])
        
        writer.writerow([])
        
        # Success tiers
        writer.writerow(["=== Success Tiers ==="])
        writer.writerow(["Tier", "Count", "Rate"])
        for tier, data in overall.get("success_tiers", {}).items():
            writer.writerow([tier, data.get("count", 0), f"{data.get('rate', 0):.2%}"])
        
        writer.writerow([])
        
        # Trade-off analysis
        writer.writerow(["=== Security-Functionality Trade-off ==="])
        tradeoff = overall.get("tradeoff", {})
        writer.writerow(["Correlation", "P-value", "Significant", "Interpretation"])
        writer.writerow([
            tradeoff.get("correlation", 0),
            tradeoff.get("p_value", 1),
            tradeoff.get("significant", False),
            tradeoff.get("interpretation", "")
        ])
        
        writer.writerow([])
        
        # Per-model summary
        writer.writerow(["=== Per-Model Summary ==="])
        writer.writerow(["Model", "Count", "SRS Mean", "SRS Std", "Near-Success Rate"])
        for model, data in by_model.items():
            writer.writerow([
                model,
                data.get("count", 0),
                data.get("srs", {}).get("mean", 0),
                data.get("srs", {}).get("std", 0),
                f"{data.get('near_success', {}).get('rate', 0):.2%}"
            ])
    
    logger.info(f"Saved CSV summary: {output_path}")


def main():
    """Main function for score analysis."""
    config = get_config()
    logger = init_phase_logger("SCORES", "score_analysis.log", str(config.logs_dir))
    
    logger.info("=" * 60)
    logger.info("Score Analysis")
    logger.info("=" * 60)
    
    # Load evaluation results
    logger.info("\n[1/5] Loading evaluation results...")
    results = load_evaluation_results(config)
    logger.info(f"Loaded {len(results)} evaluation results")
    
    if not results:
        logger.warning("No evaluation results found. Run evaluation first.")
        logger.info("Creating placeholder report...")
    
    # Load vulnerability metadata
    vuln_metadata = {}
    metadata_file = config.data_dir / "vulnerability_metadata.json"
    if metadata_file.exists():
        with open(metadata_file, 'r', encoding='utf-8') as f:
            vuln_metadata = json.load(f)
    
    # Extract scores
    logger.info("\n[2/5] Extracting scores...")
    scores = extract_scores(results)
    logger.info(f"Extracted {len(scores['srs'])} SRS scores")
    
    # Compute overall statistics
    logger.info("\n[3/5] Computing overall statistics...")
    overall = {
        "count": len(results),
        "security_score": compute_statistics(scores["security_score"]),
        "functionality_score": compute_statistics(scores["functionality_score"]),
        "srs": compute_statistics(scores["srs"]),
        "near_success": compute_near_success_rate(scores["srs"]),
        "success_tiers": compute_success_tiers(scores["srs"]),
        "tradeoff": analyze_tradeoff(scores["security_score"], scores["functionality_score"])
    }
    
    if scores["srs"]:
        logger.info(f"  SRS: mean={overall['srs']['mean']:.3f}, std={overall['srs']['std']:.3f}")
        logger.info(f"  Near-success rate: {overall['near_success']['rate']:.1%}")
        logger.info(f"  Trade-off correlation: r={overall['tradeoff']['correlation']:.3f}")
    
    # Analyze by model
    logger.info("\n[4/5] Analyzing by model...")
    by_model = analyze_by_model(results, logger)
    
    # Analyze by CWE
    logger.info("\n[5/5] Analyzing by CWE...")
    by_cwe = analyze_by_cwe(results, vuln_metadata, logger)
    
    # Save results
    logger.info("\nSaving results...")
    
    # Create output directories
    analysis_dir = config.results_dir / "analysis"
    tables_dir = config.results_dir / "tables"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    tables_dir.mkdir(parents=True, exist_ok=True)
    
    # Save JSON
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "total_results": len(results),
        "overall": overall,
        "by_model": by_model,
        "by_cwe": by_cwe
    }
    
    json_file = analysis_dir / "score_analysis.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    logger.info(f"Saved JSON: {json_file}")
    
    # Save CSV
    csv_file = analysis_dir / "score_analysis.csv"
    save_csv_summary(overall, by_model, csv_file, logger)
    
    # Generate LaTeX table
    if scores["srs"]:
        latex_file = tables_dir / "scores_table.tex"
        generate_latex_table(overall, by_model, latex_file, logger)
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("Score Analysis Complete")
    logger.info("=" * 60)
    
    if scores["srs"]:
        logger.info(f"\nKey Findings:")
        logger.info(f"  - Total patches analyzed: {len(results)}")
        logger.info(f"  - Mean SRS: {overall['srs']['mean']:.3f}")
        logger.info(f"  - Near-success rate (0.8 <= SRS < 1.0): {overall['near_success']['rate']:.1%}")
        logger.info(f"  - Perfect patches (SRS = 1.0): {overall['success_tiers'].get('perfect', {}).get('count', 0)}")
        logger.info(f"  - Security-Functionality correlation: {overall['tradeoff']['correlation']:.3f}")
    else:
        logger.info("\nNo scores to analyze. Run evaluation first.")
    
    logger.info(f"\nOutput files:")
    logger.info(f"  - {json_file}")
    logger.info(f"  - {csv_file}")


if __name__ == "__main__":
    main()
