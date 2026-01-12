"""
Difficulty Predictors
"""

import json
import csv
import sys
import math
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

try:
    from scipy import stats
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from logger import init_phase_logger
from config import get_config


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


def load_vulnerability_features(config) -> Dict:
    """Load vulnerability features from JSON."""
    features_file = config.data_dir / "vulnerability_features.json"
    if features_file.exists():
        with open(features_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def load_vulnerability_metadata(config) -> Dict:
    """Load vulnerability metadata for CWE information."""
    metadata_file = config.data_dir / "vulnerability_metadata.json"
    if metadata_file.exists():
        with open(metadata_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def compute_pearson_correlation(x: List[float], y: List[float]) -> Tuple[float, float]:
    """
    Compute Pearson correlation coefficient and exact p-value using scipy.
    
    Returns:
        Tuple of (correlation, p_value)
    """
    if len(x) != len(y) or len(x) < 3:
        return 0.0, 1.0
    
    # Filter out None/NaN values
    valid_pairs = [(xi, yi) for xi, yi in zip(x, y) 
                   if xi is not None and yi is not None 
                   and not math.isnan(xi) and not math.isnan(yi)]
    
    if len(valid_pairs) < 3:
        return 0.0, 1.0
    
    x_valid = [p[0] for p in valid_pairs]
    y_valid = [p[1] for p in valid_pairs]
    
    # Use scipy for exact p-value calculation
    if SCIPY_AVAILABLE:
        r, p_value = stats.pearsonr(x_valid, y_valid)
        return round(r, 4), round(p_value, 4)
    
    # Fallback to manual calculation if scipy not available
    n = len(valid_pairs)
    mean_x = sum(x_valid) / n
    mean_y = sum(y_valid) / n
    
    cov = sum((x_valid[i] - mean_x) * (y_valid[i] - mean_y) for i in range(n)) / n
    std_x = math.sqrt(sum((xi - mean_x) ** 2 for xi in x_valid) / n)
    std_y = math.sqrt(sum((yi - mean_y) ** 2 for yi in y_valid) / n)
    
    if std_x == 0 or std_y == 0:
        return 0.0, 1.0
    
    r = cov / (std_x * std_y)
    
    # Compute exact p-value using t-distribution
    if abs(r) >= 0.9999:
        p_value = 0.0001
    else:
        t_stat = r * math.sqrt((n - 2) / (1 - r ** 2))
        df = n - 2
        # Two-tailed p-value from t-distribution
        # Using approximation when scipy not available
        abs_t = abs(t_stat)
        # Better approximation using the t-distribution CDF
        p_value = 2 * (1 - _t_cdf(abs_t, df))
    
    return round(r, 4), round(p_value, 4)


def _t_cdf(t: float, df: int) -> float:
    """
    Approximate the CDF of the t-distribution.
    Uses the regularized incomplete beta function approximation.
    """
    x = df / (df + t * t)
    # Approximation using normal distribution for large df
    if df > 30:
        # Use normal approximation
        from math import erf
        return 0.5 * (1 + erf(t / math.sqrt(2)))
    
    # For smaller df, use a rough approximation
    # This is less accurate but avoids scipy dependency
    z = t / math.sqrt(1 + t*t/df)
    return 0.5 * (1 + math.erf(z / math.sqrt(2)))


def compute_spearman_correlation(x: List[float], y: List[float]) -> Tuple[float, float]:
    """
    Compute Spearman rank correlation coefficient with exact p-value.
    
    Returns:
        Tuple of (correlation, p_value)
    """
    if len(x) != len(y) or len(x) < 3:
        return 0.0, 1.0
    
    # Filter out None/NaN values
    valid_pairs = [(xi, yi) for xi, yi in zip(x, y) 
                   if xi is not None and yi is not None 
                   and not math.isnan(xi) and not math.isnan(yi)]
    
    if len(valid_pairs) < 3:
        return 0.0, 1.0
    
    x_valid = [p[0] for p in valid_pairs]
    y_valid = [p[1] for p in valid_pairs]
    
    # Use scipy for exact p-value calculation
    if SCIPY_AVAILABLE:
        rho, p_value = stats.spearmanr(x_valid, y_valid)
        return round(rho, 4), round(p_value, 4)
    
    # Fallback: Convert to ranks and compute Pearson
    def rank(values):
        sorted_indices = sorted(range(len(values)), key=lambda i: values[i])
        ranks = [0] * len(values)
        for rank_val, idx in enumerate(sorted_indices):
            ranks[idx] = rank_val + 1
        return ranks
    
    x_ranks = rank(x_valid)
    y_ranks = rank(y_valid)
    
    return compute_pearson_correlation(x_ranks, y_ranks)


def aggregate_scores_by_vulnerability(results: List[Dict]) -> Dict[str, Dict]:
    """Aggregate scores by vulnerability ID."""
    by_vul = defaultdict(list)
    
    for r in results:
        vul_id = r.get("vul_id", "")
        if vul_id:
            by_vul[vul_id].append(r)
    
    aggregated = {}
    for vul_id, vul_results in by_vul.items():
        srs_scores = []
        compile_success = 0
        security_success = 0
        
        for r in vul_results:
            srs = r.get("srs", r.get("scores", {}).get("srs"))
            if srs is not None:
                srs_scores.append(float(srs))
            
            # Handle nested structure: security.compile_success
            security = r.get("security", {})
            if security.get("compile_success") or r.get("compile_success", r.get("compilation_success", False)):
                compile_success += 1
            
            # Handle nested structure: security.pov_test_passed
            if security.get("pov_test_passed") or r.get("pov_passed", r.get("all_pov_passed", False)):
                security_success += 1
        
        if srs_scores:
            aggregated[vul_id] = {
                "patch_count": len(vul_results),
                "srs_mean": sum(srs_scores) / len(srs_scores),
                "srs_max": max(srs_scores),
                "srs_min": min(srs_scores),
                "compile_rate": compile_success / len(vul_results),
                "security_fix_rate": security_success / len(vul_results)
            }
    
    return aggregated


def compute_feature_correlations(
    vul_scores: Dict[str, Dict],
    features: Dict,
    logger
) -> Dict:
    """Compute correlations between SRS and vulnerability features."""
    
    # Prepare paired data
    feature_names = [
        ("loc_vulnerable", "Lines of Code"),
        ("human_patch_size", "Human Patch Size"),
        ("cyclomatic_complexity_max", "Max Cyclomatic Complexity"),
        ("cyclomatic_complexity_avg", "Avg Cyclomatic Complexity"),
        ("num_files", "Number of Files"),
        ("nloc", "Non-comment LOC"),
        ("function_count", "Function Count")
    ]
    
    correlations = {}
    
    for feature_key, feature_label in feature_names:
        srs_values = []
        feature_values = []
        
        for vul_id, scores in vul_scores.items():
            if vul_id in features:
                feat = features[vul_id]
                feat_val = feat.get(feature_key)
                
                if feat_val is not None:
                    srs_values.append(scores["srs_mean"])
                    feature_values.append(float(feat_val))
        
        if len(srs_values) >= 3:
            pearson_r, pearson_p = compute_pearson_correlation(srs_values, feature_values)
            spearman_r, spearman_p = compute_spearman_correlation(srs_values, feature_values)
            
            correlations[feature_key] = {
                "label": feature_label,
                "n": len(srs_values),
                "pearson_r": pearson_r,
                "pearson_p": pearson_p,
                "spearman_r": spearman_r,
                "spearman_p": spearman_p,
                "significant": pearson_p < 0.05 or spearman_p < 0.05
            }
            
            sig_marker = "*" if correlations[feature_key]["significant"] else ""
            logger.info(f"  {feature_label}: r={pearson_r:.3f} (p={pearson_p:.3f}){sig_marker}")
        else:
            logger.warning(f"  {feature_label}: insufficient data (n={len(srs_values)})")
    
    return correlations


def analyze_per_cwe(
    results: List[Dict],
    vuln_metadata: Dict,
    logger
) -> Dict:
    """Analyze success rates per CWE type."""
    
    by_cwe = defaultdict(list)
    
    for r in results:
        vul_id = r.get("vul_id", "")
        cwe_id = r.get("cwe_id", "")
        
        if not cwe_id and vul_id in vuln_metadata:
            cwe_id = vuln_metadata[vul_id].get("cwe_id", "unknown")
        
        by_cwe[cwe_id].append(r)
    
    cwe_analysis = {}
    
    for cwe, cwe_results in by_cwe.items():
        n = len(cwe_results)
        
        # Handle nested structure: security.compile_success and security.pov_test_passed
        compile_success = sum(1 for r in cwe_results 
                             if r.get("security", {}).get("compile_success") or 
                                r.get("compile_success", r.get("compilation_success", False)))
        security_success = sum(1 for r in cwe_results 
                              if r.get("security", {}).get("pov_test_passed") or
                                 r.get("pov_passed", r.get("all_pov_passed", False)))
        
        srs_scores = []
        for r in cwe_results:
            srs = r.get("srs", r.get("scores", {}).get("srs"))
            if srs is not None:
                srs_scores.append(float(srs))
        
        cwe_name = ""
        for r in cwe_results:
            if r.get("cwe_name"):
                cwe_name = r.get("cwe_name")
                break
        
        if not cwe_name:
            for vul_id in set(r.get("vul_id", "") for r in cwe_results):
                if vul_id in vuln_metadata:
                    cwe_name = vuln_metadata[vul_id].get("cwe_name", "")
                    if cwe_name:
                        break
        
        cwe_analysis[cwe] = {
            "cwe_name": cwe_name,
            "patch_count": n,
            "compile_rate": round(compile_success / n, 4) if n > 0 else 0,
            "security_fix_rate": round(security_success / n, 4) if n > 0 else 0,
            "srs_mean": round(sum(srs_scores) / len(srs_scores), 4) if srs_scores else 0,
            "srs_std": round(
                math.sqrt(sum((s - sum(srs_scores)/len(srs_scores))**2 for s in srs_scores) / len(srs_scores)), 4
            ) if len(srs_scores) > 1 else 0
        }
    
    logger.info(f"Analyzed {len(cwe_analysis)} CWE types")
    
    return cwe_analysis


def rank_cwe_by_difficulty(cwe_analysis: Dict) -> List[Dict]:
    """Rank CWE types by difficulty (lower SRS = harder)."""
    
    ranked = []
    for cwe, data in cwe_analysis.items():
        ranked.append({
            "cwe_id": cwe,
            "cwe_name": data.get("cwe_name", ""),
            "patch_count": data.get("patch_count", 0),
            "srs_mean": data.get("srs_mean", 0),
            "compile_rate": data.get("compile_rate", 0),
            "security_fix_rate": data.get("security_fix_rate", 0)
        })
    
    # Sort by SRS mean (ascending = hardest first)
    ranked.sort(key=lambda x: x["srs_mean"])
    
    # Add rank
    for i, item in enumerate(ranked):
        item["difficulty_rank"] = i + 1
    
    return ranked


def identify_significant_predictors(correlations: Dict) -> List[Dict]:
    """Identify statistically significant predictors."""
    
    significant = []
    for feature, data in correlations.items():
        if data.get("significant", False):
            significant.append({
                "feature": feature,
                "label": data.get("label", feature),
                "pearson_r": data.get("pearson_r", 0),
                "pearson_p": data.get("pearson_p", 1),
                "interpretation": interpret_correlation(data.get("pearson_r", 0))
            })
    
    # Sort by absolute correlation strength
    significant.sort(key=lambda x: abs(x["pearson_r"]), reverse=True)
    
    return significant


def interpret_correlation(r: float) -> str:
    """Interpret correlation coefficient."""
    abs_r = abs(r)
    direction = "positive" if r > 0 else "negative"
    
    if abs_r >= 0.7:
        strength = "strong"
    elif abs_r >= 0.4:
        strength = "moderate"
    elif abs_r >= 0.2:
        strength = "weak"
    else:
        return "negligible correlation"
    
    if r > 0:
        meaning = "higher values associated with higher SRS (easier)"
    else:
        meaning = "higher values associated with lower SRS (harder)"
    
    return f"{strength} {direction} correlation: {meaning}"


def generate_correlations_latex_table(correlations: Dict, output_path: Path, logger) -> None:
    """Generate LaTeX table for correlations."""
    
    latex = []
    latex.append("\\begin{table}[htbp]")
    latex.append("\\centering")
    latex.append("\\caption{Correlation Between Vulnerability Features and SRS}")
    latex.append("\\label{tab:correlations}")
    latex.append("\\begin{tabular}{lcccc}")
    latex.append("\\toprule")
    latex.append("\\textbf{Feature} & \\textbf{n} & \\textbf{Pearson r} & \\textbf{p-value} & \\textbf{Sig.} \\\\")
    latex.append("\\midrule")
    
    for feature, data in sorted(correlations.items(), key=lambda x: abs(x[1].get("pearson_r", 0)), reverse=True):
        label = data.get("label", feature)
        n = data.get("n", 0)
        r = data.get("pearson_r", 0)
        p = data.get("pearson_p", 1)
        sig = "$\\checkmark$" if data.get("significant", False) else ""
        
        latex.append(f"{label} & {n} & {r:.3f} & {p:.3f} & {sig} \\\\")
    
    latex.append("\\bottomrule")
    latex.append("\\end{tabular}")
    latex.append("\\end{table}")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(latex))
    
    logger.info(f"Generated LaTeX table: {output_path}")


def generate_cwe_difficulty_latex_table(ranked_cwe: List[Dict], output_path: Path, logger) -> None:
    """Generate LaTeX table for CWE difficulty rankings."""
    
    latex = []
    latex.append("\\begin{table}[htbp]")
    latex.append("\\centering")
    latex.append("\\caption{CWE Types Ranked by Difficulty (Lower SRS = Harder)}")
    latex.append("\\label{tab:cwe-difficulty}")
    latex.append("\\begin{tabular}{clccc}")
    latex.append("\\toprule")
    latex.append("\\textbf{Rank} & \\textbf{CWE} & \\textbf{Patches} & \\textbf{SRS Mean} & \\textbf{Fix Rate} \\\\")
    latex.append("\\midrule")
    
    for item in ranked_cwe[:15]:  # Top 15 hardest
        rank = item["difficulty_rank"]
        cwe = item["cwe_id"]
        n = item["patch_count"]
        srs = item["srs_mean"]
        fix_rate = item["security_fix_rate"]
        
        latex.append(f"{rank} & {cwe} & {n} & {srs:.3f} & {fix_rate:.1%} \\\\")
    
    latex.append("\\bottomrule")
    latex.append("\\end{tabular}")
    latex.append("\\end{table}")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(latex))
    
    logger.info(f"Generated LaTeX table: {output_path}")


def save_csv_summary(correlations: Dict, ranked_cwe: List[Dict], output_path: Path, logger) -> None:
    """Save CSV summary of difficulty predictors."""
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Correlations
        writer.writerow(["=== Feature Correlations with SRS ==="])
        writer.writerow(["Feature", "Label", "n", "Pearson r", "p-value", "Spearman r", "Significant"])
        
        for feature, data in sorted(correlations.items(), key=lambda x: abs(x[1].get("pearson_r", 0)), reverse=True):
            writer.writerow([
                feature,
                data.get("label", ""),
                data.get("n", 0),
                data.get("pearson_r", 0),
                data.get("pearson_p", 1),
                data.get("spearman_r", 0),
                "Yes" if data.get("significant", False) else "No"
            ])
        
        writer.writerow([])
        
        # CWE difficulty rankings
        writer.writerow(["=== CWE Difficulty Rankings ==="])
        writer.writerow(["Rank", "CWE ID", "CWE Name", "Patches", "SRS Mean", "Compile Rate", "Security Fix Rate"])
        
        for item in ranked_cwe:
            writer.writerow([
                item["difficulty_rank"],
                item["cwe_id"],
                item["cwe_name"],
                item["patch_count"],
                item["srs_mean"],
                f"{item['compile_rate']:.2%}",
                f"{item['security_fix_rate']:.2%}"
            ])
    
    logger.info(f"Saved CSV summary: {output_path}")


def main():
    """Main function for difficulty predictor analysis."""
    config = get_config()
    logger = init_phase_logger("DIFFICULTY", "difficulty_predictors.log", str(config.logs_dir))
    
    logger.info("=" * 60)
    logger.info("Difficulty Predictors Analysis")
    logger.info("=" * 60)
    
    # Load data
    logger.info("\n[1/6] Loading evaluation results...")
    results = load_evaluation_results(config)
    logger.info(f"Loaded {len(results)} evaluation results")
    
    logger.info("\n[2/6] Loading vulnerability features...")
    features = load_vulnerability_features(config)
    logger.info(f"Loaded features for {len(features)} vulnerabilities")
    
    logger.info("\n[3/6] Loading vulnerability metadata...")
    vuln_metadata = load_vulnerability_metadata(config)
    logger.info(f"Loaded metadata for {len(vuln_metadata)} vulnerabilities")
    
    if not results:
        logger.warning("No evaluation results found. Run evaluation first.")
        logger.info("Creating placeholder report...")
    
    # Aggregate scores by vulnerability
    logger.info("\n[4/6] Aggregating scores by vulnerability...")
    vul_scores = aggregate_scores_by_vulnerability(results)
    logger.info(f"Aggregated scores for {len(vul_scores)} vulnerabilities")
    
    # Compute feature correlations
    logger.info("\n[5/6] Computing feature correlations...")
    correlations = compute_feature_correlations(vul_scores, features, logger)
    
    # Identify significant predictors
    significant_predictors = identify_significant_predictors(correlations)
    if significant_predictors:
        logger.info(f"\nSignificant predictors (p < 0.05):")
        for pred in significant_predictors:
            logger.info(f"  - {pred['label']}: r={pred['pearson_r']:.3f}")
    else:
        logger.info("\nNo statistically significant predictors found (p < 0.05)")
    
    # Per-CWE analysis
    logger.info("\n[6/6] Analyzing per-CWE difficulty...")
    cwe_analysis = analyze_per_cwe(results, vuln_metadata, logger)
    ranked_cwe = rank_cwe_by_difficulty(cwe_analysis)
    
    if ranked_cwe:
        logger.info("\nTop 5 hardest CWE types:")
        for item in ranked_cwe[:5]:
            logger.info(f"  {item['difficulty_rank']}. {item['cwe_id']}: SRS={item['srs_mean']:.3f}")
    
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
        "vulnerabilities_analyzed": len(vul_scores),
        "correlations": correlations,
        "significant_predictors": significant_predictors,
        "cwe_analysis": cwe_analysis,
        "cwe_difficulty_ranking": ranked_cwe
    }
    
    # Convert numpy types to Python native types for JSON serialization
    def convert_numpy_types(obj):
        if isinstance(obj, dict):
            return {k: convert_numpy_types(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_numpy_types(v) for v in obj]
        elif hasattr(obj, 'item'):  # numpy scalar
            return obj.item()
        elif isinstance(obj, bool):
            return bool(obj)
        return obj
    
    output_data = convert_numpy_types(output_data)
    
    json_file = analysis_dir / "difficulty_predictors.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    logger.info(f"Saved JSON: {json_file}")
    
    # Save CSV
    csv_file = analysis_dir / "difficulty_predictors.csv"
    save_csv_summary(correlations, ranked_cwe, csv_file, logger)
    
    # Generate LaTeX tables
    if correlations:
        latex_corr_file = tables_dir / "correlations_table.tex"
        generate_correlations_latex_table(correlations, latex_corr_file, logger)
    
    if ranked_cwe:
        latex_cwe_file = tables_dir / "cwe_difficulty_table.tex"
        generate_cwe_difficulty_latex_table(ranked_cwe, latex_cwe_file, logger)
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("Difficulty Predictor Analysis Complete")
    logger.info("=" * 60)
    
    if correlations:
        logger.info(f"\nKey Findings:")
        logger.info(f"  - Vulnerabilities analyzed: {len(vul_scores)}")
        logger.info(f"  - Features tested: {len(correlations)}")
        logger.info(f"  - Significant predictors: {len(significant_predictors)}")
        logger.info(f"  - CWE types analyzed: {len(cwe_analysis)}")
        
        if significant_predictors:
            logger.info(f"\nStrongest predictor: {significant_predictors[0]['label']} "
                       f"(r={significant_predictors[0]['pearson_r']:.3f})")
    else:
        logger.info("\nNo correlations computed. Run evaluation first.")
    
    logger.info(f"\nOutput files:")
    logger.info(f"  - {json_file}")
    logger.info(f"  - {csv_file}")
    if correlations:
        logger.info(f"  - {tables_dir / 'correlations_table.tex'}")
    if ranked_cwe:
        logger.info(f"  - {tables_dir / 'cwe_difficulty_table.tex'}")


if __name__ == "__main__":
    main()
