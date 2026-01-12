"""
Generate Essential Visualizations for Paper

Creates only the most important figures for a 5-page paper:
1. Failure Mode Distribution (RQ1) - Pie chart showing failure categories
2. SRS Distribution (RQ2) - Histogram with success tiers

Output: results/analysis/figures/
"""

import json
import sys
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from config import get_config

# Set style for publication-quality figures
plt.rcParams.update({
    'font.size': 10,
    'font.family': 'serif',
    'axes.labelsize': 11,
    'axes.titlesize': 12,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.1
})


def load_analysis_data(config):
    """Load all analysis JSON files."""
    analysis_dir = config.results_dir / "analysis"
    
    data = {}
    
    # Load failure distribution
    failure_file = analysis_dir / "failure_distribution.json"
    if failure_file.exists():
        with open(failure_file, 'r', encoding='utf-8') as f:
            data['failure'] = json.load(f)
    
    # Load score analysis
    score_file = analysis_dir / "score_analysis.json"
    if score_file.exists():
        with open(score_file, 'r', encoding='utf-8') as f:
            data['scores'] = json.load(f)
    
    # Load difficulty predictors
    difficulty_file = analysis_dir / "difficulty_predictors.json"
    if difficulty_file.exists():
        with open(difficulty_file, 'r', encoding='utf-8') as f:
            data['difficulty'] = json.load(f)
    
    return data


def create_failure_distribution_pie(data, output_dir):
    """
    Figure 1: Failure Mode Distribution (RQ1)
    Pie chart showing the distribution of failure categories.
    """
    if 'failure' not in data:
        print("No failure distribution data found")
        return
    
    dist = data['failure']['overall_distribution']['primary_distribution']
    
    # Define categories and colors (professional palette)
    category_config = {
        'correct_and_secure': {'label': 'Correct & Secure', 'color': '#2ecc71'},  # Green
        'security_failure': {'label': 'Security Failure', 'color': '#e74c3c'},     # Red
        'functionality_failure': {'label': 'Functionality Failure', 'color': '#f39c12'},  # Orange
        'insecure_and_breaking': {'label': 'Insecure & Breaking', 'color': '#9b59b6'},    # Purple
        'compile_error': {'label': 'Compilation Error', 'color': '#3498db'},       # Blue
        'evaluation_error': {'label': 'Evaluation Error', 'color': '#95a5a6'}      # Gray
    }
    
    # Prepare data
    labels = []
    sizes = []
    colors = []
    
    # Sort by count descending
    sorted_cats = sorted(dist.items(), key=lambda x: x[1]['count'], reverse=True)
    
    for cat, info in sorted_cats:
        if cat in category_config and info['count'] > 0:
            cfg = category_config[cat]
            labels.append(f"{cfg['label']}\n({info['count']}, {info['percentage']:.1f}%)")
            sizes.append(info['count'])
            colors.append(cfg['color'])
    
    # Create figure
    fig, ax = plt.subplots(figsize=(6, 5))
    
    # Create pie chart
    wedges, texts = ax.pie(
        sizes, 
        colors=colors,
        startangle=90,
        counterclock=False,
        wedgeprops={'linewidth': 1, 'edgecolor': 'white'}
    )
    
    # Add legend
    ax.legend(
        wedges, 
        labels,
        title="Failure Categories",
        loc="center left",
        bbox_to_anchor=(1, 0, 0.5, 1),
        fontsize=9
    )
    
    ax.set_title(f'Patch Outcome Distribution (n={data["failure"]["total_results"]})', 
                 fontweight='bold', pad=10)
    
    plt.tight_layout()
    
    # Save
    output_path = output_dir / "fig1_failure_distribution.pdf"
    plt.savefig(output_path, format='pdf')
    output_path_png = output_dir / "fig1_failure_distribution.png"
    plt.savefig(output_path_png, format='png')
    plt.close()
    
    print(f"Saved: {output_path}")
    print(f"Saved: {output_path_png}")


def create_srs_histogram(data, output_dir):
    """
    Figure 2: SRS Distribution (RQ2)
    Histogram showing the distribution of Security Repair Scores with tier annotations.
    """
    if 'scores' not in data:
        print("No score analysis data found")
        return
    
    # Load raw SRS values from evaluations
    config = get_config()
    evaluations_dir = config.results_dir / "evaluations"
    
    srs_values = []
    for eval_file in evaluations_dir.glob("**/eval_patch_*.json"):
        try:
            with open(eval_file, 'r', encoding='utf-8') as f:
                result = json.load(f)
            srs = result.get('srs', 0)
            srs_values.append(srs)
        except:
            continue
    
    if not srs_values:
        print("No SRS values found")
        return
    
    # Create figure
    fig, ax = plt.subplots(figsize=(7, 4))
    
    # Create histogram
    bins = np.linspace(0, 1, 21)  # 20 bins from 0 to 1
    n, bins_edges, patches = ax.hist(srs_values, bins=bins, color='#3498db', 
                                      edgecolor='white', alpha=0.8)
    
    # Color bins by tier
    for i, patch in enumerate(patches):
        bin_center = (bins_edges[i] + bins_edges[i+1]) / 2
        if bin_center >= 1.0:
            patch.set_facecolor('#2ecc71')  # Perfect - Green
        elif bin_center >= 0.8:
            patch.set_facecolor('#27ae60')  # Near-success - Darker green
        elif bin_center > 0:
            patch.set_facecolor('#3498db')  # Partial - Blue
        else:
            patch.set_facecolor('#e74c3c')  # Failure - Red
    
    # Add vertical lines for thresholds
    ax.axvline(x=0.8, color='#27ae60', linestyle='--', linewidth=1.5, label='Near-success threshold')
    ax.axvline(x=1.0, color='#2ecc71', linestyle='-', linewidth=1.5, label='Perfect score')
    
    # Add statistics annotation
    stats = data['scores']['overall']['srs']
    tiers = data['scores']['overall']['success_tiers']
    
    stats_text = (
        f"Mean: {stats['mean']:.3f}\n"
        f"Median: {stats['median']:.3f}\n"
        f"Std: {stats['std']:.3f}\n"
        f"─────────\n"
        f"Perfect: {tiers['perfect']['count']} ({tiers['perfect']['rate']*100:.1f}%)\n"
        f"Near-success: {tiers['near_success']['count']} ({tiers['near_success']['rate']*100:.1f}%)\n"
        f"Partial: {tiers['partial_success']['count']} ({tiers['partial_success']['rate']*100:.1f}%)\n"
        f"Failure: {tiers['complete_failure']['count']} ({tiers['complete_failure']['rate']*100:.1f}%)"
    )
    
    ax.text(0.02, 0.98, stats_text, transform=ax.transAxes, fontsize=8,
            verticalalignment='top', fontfamily='monospace',
            bbox=dict(boxstyle='round', facecolor='white', alpha=0.9, edgecolor='gray'))
    
    ax.set_xlabel('Security Repair Score (SRS)')
    ax.set_ylabel('Number of Patches')
    ax.set_title('Distribution of Security Repair Scores', fontweight='bold')
    ax.set_xlim(0, 1.05)
    ax.legend(loc='upper center', fontsize=8)
    
    plt.tight_layout()
    
    # Save
    output_path = output_dir / "fig2_srs_distribution.pdf"
    plt.savefig(output_path, format='pdf')
    output_path_png = output_dir / "fig2_srs_distribution.png"
    plt.savefig(output_path_png, format='png')
    plt.close()
    
    print(f"Saved: {output_path}")
    print(f"Saved: {output_path_png}")


def main():
    """Generate all essential figures."""
    config = get_config()
    
    # Create output directory
    figures_dir = config.results_dir / "analysis" / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 60)
    print("Generating Essential Figures for Paper")
    print("=" * 60)
    
    # Load data
    print("\nLoading analysis data...")
    data = load_analysis_data(config)
    
    # Generate figures
    print("\n--- Figure 1: Failure Mode Distribution (RQ1) ---")
    create_failure_distribution_pie(data, figures_dir)
    
    print("\n--- Figure 2: SRS Distribution (RQ2) ---")
    create_srs_histogram(data, figures_dir)
    
    print("\n" + "=" * 60)
    print("Figure generation complete!")
    print(f"Output directory: {figures_dir}")
    print("=" * 60)


if __name__ == "__main__":
    main()
