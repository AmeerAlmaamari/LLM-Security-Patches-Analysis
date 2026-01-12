# Why LLMs Fail: A Failure Analysis and Partial Success Measurement for Automated Security Patch Generation

This repository contains the replication package for the seminar paper "Why LLMs Fail: A Failure Analysis and Partial Success Measurement for Automated Security Patch Generation."

The study investigates why Large Language Models fail at security patch generation and to what degree they partially succeed. It evaluates 319 LLM-generated patches across 64 Java vulnerabilities from the Vul4J dataset using a tri-axis evaluation protocol.

## Overview

![Experiment Pipeline](replication/experiment_pipeline.png)

The experiment consists of three main phases:

1. **Dataset and Patch Generation**: Extract vulnerable code from Vul4J and generate patches using Gemini 3.0 Flash
2. **Tri-Axis Evaluation**: Evaluate each patch on compilation, security correctness, and functional correctness
3. **Classification and Metrics**: Classify patches into failure categories and compute partial-success scores

## Key Findings

* Only 24.8% of patches achieve full correctness (Correct and Secure)
* The dominant failure mode is semantic misunderstanding, not syntactic errors
* LLMs preserve functionality well (mean score 0.832) but struggle with security (mean score 0.251)
* Vulnerability type shows substantial variation in repair difficulty (0% to 45% success rates)

## Repository Structure

```
almaamari/
├── README.adoc              # This file
├── replication/             # Experiment replication package
│   ├── scripts/             # Python scripts for each experiment step
│   ├── src/                 # Core modules (evaluator, patch generator, etc.)
│   ├── data/                # Dataset files and extracted vulnerable code
│   ├── results/             # Generated patches, evaluations, and analysis
│   └── experiment_pipeline.png
```

## Requirements

### Software Dependencies

* **Python 3.8+**
* **Docker** (for running Vul4J evaluation environment)
* **Git** (for cloning repositories)

### Python Packages

Install the required Python packages:

```bash
pip install -r replication/requirements.txt
```

The main dependencies are:

* `openai` - OpenRouter API client
* `httpx`, `aiohttp` - HTTP clients
* `pandas`, `numpy` - Data analysis
* `matplotlib`, `seaborn` - Visualization
* `loguru` - Logging
* `python-dotenv` - Environment configuration
* `gitpython` - Git operations
* `tqdm` - Progress bars
* `pyyaml` - Configuration files
* `scipy` - Statistical analysis

### External Tools

* **Semgrep**: Static analysis tool for security scanning (installed inside Docker)
* **Lizard**: Code complexity analyzer (installed inside Docker)

### API Key

This experiment uses the OpenRouter API to access Gemini 3.0 Flash. You need an API key from [OpenRouter](https://openrouter.ai/keys).

Create a `.env` file in the `replication/` directory:

```bash
cp replication/.env.template replication/.env
# Edit .env and add your API key
```

## Dataset

### Vul4J

The experiment uses the [Vul4J dataset](https://github.com/tuhh-softsec/vul4j), which provides:

* 79 real-world Java vulnerabilities (64 confirmed reproducible)
* Proof-of-Vulnerability (PoV) test cases
* Developer test suites
* Human-written patches as ground truth

### Setting Up Vul4J

Clone the Vul4J repository:

```bash
git clone https://github.com/tuhh-softsec/vul4j.git
```

The Vul4J directory should be placed at the path specified in `replication/config.yaml` (default: `../vul4j` relative to the replication directory).

### Docker Environment

Vul4J requires a Docker container with all project dependencies pre-installed:

```bash
docker pull bqcuongas/vul4j:alldeps
docker run -d --name vul4j -v /path/to/workspace:/workspace bqcuongas/vul4j:alldeps tail -f /dev/null
```

Replace `/path/to/workspace` with your actual workspace path.

## Running the Experiment

The experiment is divided into numbered scripts that should be run in sequence. Each script is self-contained and can be re-run independently.

### Step 0: Verify Environment

Check that all dependencies are correctly installed:

```bash
cd replication
python scripts/00_verify_environment.py
```

This script verifies:

* Python version and package imports
* Docker container status
* Vul4J accessibility
* API key configuration
* Directory structure

### Step 1: Prepare Dataset

Load the vulnerability list and metadata:

```bash
python scripts/01_prepare_dataset.py
```

Output: `data/vulnerability_list.json`, `data/vulnerability_metadata.json`

### Step 2: Checkout Vulnerabilities

Checkout all 64 vulnerabilities using Vul4J:

```bash
python scripts/02_checkout_vulnerabilities.py
```

This step takes approximately 2-3 hours depending on network speed. The script supports resuming from interruptions.

Output: `data/vulnerabilities/` directory with checked-out projects

### Step 3: Extract Vulnerable Code

Extract the vulnerable source code from each checkout:

```bash
python scripts/03_extract_vulnerable_code.py
```

Output: `data/vulnerable_code.json`

### Step 4: Verify Dataset

Verify that all dataset components are complete:

```bash
python scripts/04_verify_dataset.py
```

Output: `data/dataset_summary.json`

### Step 5: Generate Patches

Generate patches using the LLM:

```bash
python scripts/05_generate_patches.py --n-patches 5
```

Options:

* `--n-patches N`: Number of patches per vulnerability (default: 5)
* `--vulns VUL_IDS`: Process specific vulnerabilities only
* `--dry-run`: Show what would be done without generating

Output: `results/patches/{VUL_ID}/{model_name}/patch_*.java`

### Step 6: Evaluate Patches

Run the tri-axis evaluation on all generated patches:

```bash
python scripts/06_evaluate_patches.py
```

Options:

* `--vulns VUL_IDS`: Evaluate specific vulnerabilities
* `--resume`: Resume from previous progress

This step takes approximately 8-12 hours for all 320 patches. Each patch is evaluated for:

1. Compilation success
2. Security correctness (PoV tests + Semgrep)
3. Functional correctness (full test suite)

Output: `results/evaluations/{VUL_ID}/{model_name}/eval_patch_*.json`

### Step 7: Analyze Results

Generate the analysis and metrics:

```bash
python scripts/07_analyze_results.py
```

Output: `results/analysis/` directory with JSON reports

### Additional Analysis Scripts

```bash
# Collect Semgrep baselines for vulnerable code
python scripts/09_semgrep_baseline.py

# Collect human patch baselines
python scripts/10_human_baseline.py

# Extract code complexity features
python scripts/11_extract_features.py

# Select sample for manual analysis
python scripts/14_manual_analysis_sample.py

# Compute failure distribution
python scripts/15_failure_distribution.py

# Compute score statistics
python scripts/16_score_analysis.py

# Analyze difficulty predictors
python scripts/17_difficulty_predictors.py

# Generate figures for the paper
python scripts/18_generate_figures.py
```

## Results

### Output Files

After running the experiment, the following results are generated:

| File | Description |
|------|-------------|
| `results/evaluations/evaluation_summary.json` | Summary of all patch evaluations |
| `results/analysis/failure_distribution.json` | Distribution of patches across failure categories |
| `results/analysis/score_analysis.json` | Statistics for Security Score, Functionality Score, and SRS |
| `results/analysis/difficulty_predictors.json` | Correlation analysis between features and repair success |
| `results/analysis/figures/` | Generated figures for the paper |

### Evaluation Metrics

Each patch evaluation produces:

* **Category**: One of `correct_and_secure`, `insecure`, `breaking`, `insecure_and_breaking`, `compile_error`
* **Security Score**: 0.0 to 1.0, based on PoV test and Semgrep warnings
* **Functionality Score**: 0.0 to 1.0, ratio of tests passed vs. human patch
* **SRS (Security Repair Score)**: Combined metric with equal weights

### Failure Taxonomy

Patches are classified into:

* **Correct and Secure**: All three axes pass
* **Insecure and Breaking**: Security and functionality fail
* **Compilation Error**: Failed to compile
* **Security Failure**: Compiles and functional, but vulnerability remains
* **Functionality Failure**: Security fixed, but tests fail

## Configuration

The experiment configuration is stored in `replication/config.yaml`:

```yaml
# API Configuration
openrouter_api_key: ${OPENROUTER_API_KEY}
openrouter_base_url: https://openrouter.ai/api/v1

# Model Configuration
models:
  - name: gemini-3.0-flash
    openrouter_id: google/gemini-3-flash-preview
    max_tokens: 8192
    temperature: 0.7

# Experiment Settings
n_samples: 5  # patches per vulnerability

# Paths
vul4j_dir: ../vul4j
data_dir: data
results_dir: results
logs_dir: logs
```

## Troubleshooting

### Docker Container Not Running

```bash
docker start vul4j
```

### API Rate Limiting

The scripts include automatic rate limiting. If you encounter rate limit errors, increase the delay in `config.yaml`:

```yaml
rate_limit_delay: 2.0  # seconds between API calls
```

### Compilation Timeouts

Some projects have long compilation times. Adjust timeouts in the evaluator:

```python
# In scripts/06_evaluate_patches.py
evaluator = PatchEvaluator(
    timeout_compile=2700,  # 45 minutes
    timeout_test=1800      # 30 minutes
)
```

### Encoding Errors

The scripts use UTF-8 encoding throughout. If you encounter encoding errors on Windows, ensure your terminal supports UTF-8:

```powershell
chcp 65001
```
