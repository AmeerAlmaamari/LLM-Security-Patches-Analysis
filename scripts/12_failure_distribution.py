"""
Failure Distribution Report
"""

import json
import csv
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from collections import defaultdict

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from logger import init_phase_logger
from config import get_config
from failure_analyzer import get_failure_distribution, PrimaryFailureCategory


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


def compute_failure_distribution(results: List[Dict], logger) -> Dict:
    """Compute failure distribution from evaluation results."""
    
    # Extract classifications
    classifications = []
    for r in results:
        # Handle different result formats
        if "failure_classification" in r:
            clf = r["failure_classification"]
        elif "classification" in r:
            clf = r["classification"]
        elif "primary_category" in r:
            clf = r
        else:
            # Try to infer from result fields
            clf = infer_classification(r)
        
        if clf:
            classifications.append(clf)
    
    logger.info(f"Found {len(classifications)} classifications")
    
    # Use the failure_analyzer function
    distribution = get_failure_distribution(classifications)
    
    return distribution


def infer_classification(result: Dict) -> Dict:
    """Infer classification from evaluation result fields."""
    
    # First, check if category is already present at top level (from 06_evaluate_patches.py)
    if "category" in result:
        return {
            "primary_category": result["category"],
            "subcategory": result.get("subcategory", "other")
        }
    
    # Handle nested structure from evaluation files
    # Fields may be nested under 'security' and 'functionality' keys
    security = result.get("security", {})
    functionality = result.get("functionality", {})
    
    # Extract compile_success from nested or flat structure
    compile_success = (
        security.get("compile_success") or 
        result.get("compile_success") or 
        result.get("compilation_success", False)
    )
    
    # Extract pov_passed from nested or flat structure
    pov_passed = (
        security.get("pov_test_passed") or
        result.get("pov_passed") or 
        result.get("all_pov_passed", False)
    )
    
    # Extract test counts from nested or flat structure
    tests_passed = functionality.get("tests_passed", result.get("tests_passed", 0))
    tests_run = functionality.get("tests_run", result.get("tests_run", 1))
    tests_human = result.get("tests_passed_human", tests_run)
    
    if not compile_success:
        error_type = (
            security.get("compile_error_type") or
            result.get("error_type", "other")
        )
        return {
            "primary_category": "compilation_failure",
            "subcategory": error_type if error_type else "other"
        }
    
    is_secure = pov_passed
    is_functional = tests_passed >= tests_human if tests_human > 0 else True
    
    if is_secure and is_functional:
        return {"primary_category": "correct_and_secure", "subcategory": None}
    elif not is_secure and is_functional:
        return {"primary_category": "security_failure", "subcategory": "other"}
    elif is_secure and not is_functional:
        return {"primary_category": "functionality_failure", "subcategory": "other"}
    else:
        return {"primary_category": "insecure_and_breaking", "subcategory": "other"}


def compute_distribution_by_model(results: List[Dict], logger) -> Dict:
    """Compute failure distribution grouped by model."""
    by_model = defaultdict(list)
    
    for r in results:
        model = r.get("model", r.get("model_name", "unknown"))
        by_model[model].append(r)
    
    logger.info(f"Found {len(by_model)} models")
    
    distributions = {}
    for model, model_results in by_model.items():
        logger.info(f"  {model}: {len(model_results)} results")
        distributions[model] = compute_failure_distribution(model_results, logger)
    
    return distributions


def compute_distribution_by_cwe(results: List[Dict], vuln_metadata: Dict, logger) -> Dict:
    """Compute failure distribution grouped by CWE type."""
    by_cwe = defaultdict(list)
    
    for r in results:
        vul_id = r.get("vul_id", "")
        cwe_id = r.get("cwe_id", "")
        
        if not cwe_id and vul_id in vuln_metadata:
            cwe_id = vuln_metadata[vul_id].get("cwe_id", "unknown")
        
        by_cwe[cwe_id].append(r)
    
    logger.info(f"Found {len(by_cwe)} CWE types")
    
    distributions = {}
    for cwe, cwe_results in by_cwe.items():
        distributions[cwe] = compute_failure_distribution(cwe_results, logger)
    
    return distributions


def generate_latex_table(distribution: Dict, output_path: Path, logger) -> None:
    """Generate LaTeX table for the paper."""
    
    primary_dist = distribution.get("primary_distribution", {})
    total = distribution.get("total", 0)
    
    # Define category order
    category_order = [
        ("correct_and_secure", "Correct \\& Secure"),
        ("compilation_failure", "Compilation Failure"),
        ("security_failure", "Security Failure"),
        ("functionality_failure", "Functionality Failure"),
        ("insecure_and_breaking", "Insecure \\& Breaking"),
    ]
    
    latex = []
    latex.append("\\begin{table}[htbp]")
    latex.append("\\centering")
    latex.append("\\caption{Failure Mode Distribution}")
    latex.append("\\label{tab:failure-distribution}")
    latex.append("\\begin{tabular}{lrr}")
    latex.append("\\toprule")
    latex.append("\\textbf{Category} & \\textbf{Count} & \\textbf{Percentage} \\\\")
    latex.append("\\midrule")
    
    for cat_key, cat_label in category_order:
        if cat_key in primary_dist:
            count = primary_dist[cat_key]["count"]
            pct = primary_dist[cat_key]["percentage"]
            latex.append(f"{cat_label} & {count} & {pct:.1f}\\% \\\\")
        else:
            latex.append(f"{cat_label} & 0 & 0.0\\% \\\\")
    
    latex.append("\\midrule")
    latex.append(f"\\textbf{{Total}} & \\textbf{{{total}}} & \\textbf{{100.0\\%}} \\\\")
    latex.append("\\bottomrule")
    latex.append("\\end{tabular}")
    latex.append("\\end{table}")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(latex))
    
    logger.info(f"Generated LaTeX table: {output_path}")


def generate_subcategory_latex_table(distribution: Dict, output_path: Path, logger) -> None:
    """Generate detailed subcategory LaTeX table."""
    
    sub_dist = distribution.get("subcategory_distribution", {})
    total = distribution.get("total", 0)
    
    latex = []
    latex.append("\\begin{table}[htbp]")
    latex.append("\\centering")
    latex.append("\\caption{Detailed Failure Subcategory Distribution}")
    latex.append("\\label{tab:failure-subcategories}")
    latex.append("\\begin{tabular}{llrr}")
    latex.append("\\toprule")
    latex.append("\\textbf{Category} & \\textbf{Subcategory} & \\textbf{Count} & \\textbf{\\%} \\\\")
    latex.append("\\midrule")
    
    # Group by primary category
    current_primary = None
    for key, data in sorted(sub_dist.items(), key=lambda x: -x[1]["count"]):
        parts = key.split("/")
        if len(parts) == 2:
            primary, sub = parts
            
            if primary != current_primary:
                if current_primary is not None:
                    latex.append("\\midrule")
                current_primary = primary
            
            # Format names
            primary_label = primary.replace("_", " ").title()
            sub_label = sub.replace("_", " ").title()
            
            latex.append(f"{primary_label} & {sub_label} & {data['count']} & {data['percentage']:.1f}\\% \\\\")
    
    latex.append("\\bottomrule")
    latex.append("\\end{tabular}")
    latex.append("\\end{table}")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(latex))
    
    logger.info(f"Generated subcategory LaTeX table: {output_path}")


def save_csv_summary(distribution: Dict, by_model: Dict, output_path: Path, logger) -> None:
    """Save CSV summary of failure distribution."""
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Overall distribution
        writer.writerow(["=== Overall Distribution ==="])
        writer.writerow(["Category", "Count", "Percentage"])
        
        primary_dist = distribution.get("primary_distribution", {})
        for cat, data in sorted(primary_dist.items(), key=lambda x: -x[1]["count"]):
            writer.writerow([cat, data["count"], f"{data['percentage']:.2f}%"])
        
        writer.writerow([])
        
        # Per-model distribution
        writer.writerow(["=== Per-Model Distribution ==="])
        
        for model, model_dist in by_model.items():
            writer.writerow([f"Model: {model}"])
            writer.writerow(["Category", "Count", "Percentage"])
            
            model_primary = model_dist.get("primary_distribution", {})
            for cat, data in sorted(model_primary.items(), key=lambda x: -x[1]["count"]):
                writer.writerow([cat, data["count"], f"{data['percentage']:.2f}%"])
            
            writer.writerow([])
    
    logger.info(f"Saved CSV summary: {output_path}")


def main():
    """Main function to compute failure distribution."""
    config = get_config()
    logger = init_phase_logger("FAILURE", "failure_distribution.log", str(config.logs_dir))
    
    logger.info("=" * 60)
    logger.info("Failure Distribution Report")
    logger.info("=" * 60)
    
    # Load evaluation results
    logger.info("\n[1/5] Loading evaluation results...")
    results = load_evaluation_results(config)
    logger.info(f"Loaded {len(results)} evaluation results")
    
    if not results:
        logger.warning("No evaluation results found. Run evaluation first.")
        logger.info("Creating placeholder report...")
        results = []
    
    # Load vulnerability metadata
    vuln_metadata = {}
    metadata_file = config.data_dir / "vulnerability_metadata.json"
    if metadata_file.exists():
        with open(metadata_file, 'r', encoding='utf-8') as f:
            vuln_metadata = json.load(f)
    
    # Compute overall distribution
    logger.info("\n[2/5] Computing overall failure distribution...")
    overall_distribution = compute_failure_distribution(results, logger)
    
    # Compute per-model distribution
    logger.info("\n[3/5] Computing per-model distribution...")
    by_model = compute_distribution_by_model(results, logger)
    
    # Compute per-CWE distribution
    logger.info("\n[4/5] Computing per-CWE distribution...")
    by_cwe = compute_distribution_by_cwe(results, vuln_metadata, logger)
    
    # Save results
    logger.info("\n[5/5] Saving results...")
    
    # Create output directories
    analysis_dir = config.results_dir / "analysis"
    tables_dir = config.results_dir / "tables"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    tables_dir.mkdir(parents=True, exist_ok=True)
    
    # Save JSON
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "total_results": len(results),
        "overall_distribution": overall_distribution,
        "by_model": by_model,
        "by_cwe": by_cwe
    }
    
    json_file = analysis_dir / "failure_distribution.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    logger.info(f"Saved JSON: {json_file}")
    
    # Save CSV
    csv_file = analysis_dir / "failure_distribution.csv"
    save_csv_summary(overall_distribution, by_model, csv_file, logger)
    
    # Generate LaTeX tables
    if overall_distribution.get("total", 0) > 0:
        latex_file = tables_dir / "failure_taxonomy_table.tex"
        generate_latex_table(overall_distribution, latex_file, logger)
        
        latex_sub_file = tables_dir / "failure_subcategories_table.tex"
        generate_subcategory_latex_table(overall_distribution, latex_sub_file, logger)
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("Failure Distribution Report Complete")
    logger.info("=" * 60)
    
    if overall_distribution.get("total", 0) > 0:
        logger.info("\nOverall Distribution:")
        for cat, data in overall_distribution.get("primary_distribution", {}).items():
            logger.info(f"  {cat}: {data['count']} ({data['percentage']:.1f}%)")
    else:
        logger.info("\nNo results to analyze. Run evaluation first.")
    
    logger.info(f"\nOutput files:")
    logger.info(f"  - {json_file}")
    logger.info(f"  - {csv_file}")
    if overall_distribution.get("total", 0) > 0:
        logger.info(f"  - {tables_dir / 'failure_taxonomy_table.tex'}")


if __name__ == "__main__":
    main()
