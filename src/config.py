"""
Experiment Configuration Module

Contains all configuration settings for the vulnerability repair experiment.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from dotenv import load_dotenv


# Load environment variables from .env file
load_dotenv()


@dataclass
class ModelConfig:
    """Configuration for an LLM model."""
    name: str
    openrouter_id: str
    max_tokens: int = 4096
    temperature: float = 0.7
    
    
@dataclass
class ExperimentConfig:
    """Main experiment configuration."""
    
    # Project paths
    project_root: Path = field(default_factory=lambda: Path(__file__).parent.parent)
    data_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / "data")
    results_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / "results")
    logs_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / "logs")
    vul4j_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent / "vul4j")
    
    # API Configuration
    openrouter_api_key: str = field(default_factory=lambda: os.getenv("OPENROUTER_API_KEY", ""))
    openrouter_base_url: str = field(default_factory=lambda: os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"))
    
    # Experiment parameters
    n_samples: int = 5  # Number of patches to generate per vulnerability
    timeout_seconds: int = 600  # 10 minutes timeout per evaluation
    rate_limit_delay: float = 1.0  # Seconds between API requests
    
    # Docker configuration
    docker_container_name: str = "vul4j"
    docker_workspace_path: str = "/workspace"
    
    # Model to use
    models: List[ModelConfig] = field(default_factory=lambda: [
        ModelConfig(
            name="gemini-3.0-flash",
            openrouter_id="google/gemini-3-flash-preview",
            max_tokens=65536,
            temperature=0.7
        )
    ])
    
    def __post_init__(self):
        """Ensure directories exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "vulnerabilities").mkdir(parents=True, exist_ok=True)
        (self.results_dir / "patches").mkdir(parents=True, exist_ok=True)
        (self.results_dir / "evaluations").mkdir(parents=True, exist_ok=True)
        (self.results_dir / "aggregated").mkdir(parents=True, exist_ok=True)
    
    def get_model_by_name(self, name: str) -> Optional[ModelConfig]:
        """Get a model configuration by name."""
        for model in self.models:
            if model.name == name:
                return model
        return None
    
    def get_vulnerability_dir(self, vul_id: str) -> Path:
        """Get the directory for a specific vulnerability."""
        return self.data_dir / "vulnerabilities" / vul_id
    
    def get_patch_dir(self, vul_id: str, model_name: str) -> Path:
        """Get the directory for patches of a specific vulnerability and model."""
        patch_dir = self.results_dir / "patches" / vul_id / model_name
        patch_dir.mkdir(parents=True, exist_ok=True)
        return patch_dir
    
    def get_evaluation_dir(self, vul_id: str, model_name: str) -> Path:
        """Get the directory for evaluations of a specific vulnerability and model."""
        eval_dir = self.results_dir / "evaluations" / vul_id / model_name
        eval_dir.mkdir(parents=True, exist_ok=True)
        return eval_dir
    
    def get_docker_path(self, local_path: Path) -> str:
        """Convert a local path to a Docker container path."""
        # Get relative path from project root's parent (replication folder)
        try:
            rel_path = local_path.relative_to(self.project_root.parent)
            return f"{self.docker_workspace_path}/{rel_path.as_posix()}"
        except ValueError:
            # Path is not relative to project root
            return str(local_path)
    
    def validate(self) -> Dict[str, bool]:
        """Validate the configuration."""
        validations = {
            "api_key_set": bool(self.openrouter_api_key),
            "vul4j_exists": self.vul4j_dir.exists(),
            "data_dir_exists": self.data_dir.exists(),
            "results_dir_exists": self.results_dir.exists(),
            "logs_dir_exists": self.logs_dir.exists(),
        }
        return validations


# CWE to Semgrep rule mapping
CWE_SEMGREP_RULES: Dict[str, List[str]] = {
    "CWE-20": ["p/java", "p/security-audit"],  # Improper Input Validation
    "CWE-22": ["p/java", "p/security-audit"],  # Path Traversal
    "CWE-78": ["p/java", "p/command-injection"],  # OS Command Injection
    "CWE-79": ["p/java", "p/xss"],  # Cross-site Scripting
    "CWE-89": ["p/java", "p/sql-injection"],  # SQL Injection
    "CWE-94": ["p/java", "p/security-audit"],  # Code Injection
    "CWE-113": ["p/java", "p/security-audit"],  # HTTP Response Splitting
    "CWE-200": ["p/java", "p/security-audit"],  # Information Exposure
    "CWE-264": ["p/java", "p/security-audit"],  # Permissions/Privileges
    "CWE-310": ["p/java", "p/security-audit"],  # Cryptographic Issues
    "CWE-352": ["p/java", "p/security-audit"],  # CSRF
    "CWE-399": ["p/java", "p/security-audit"],  # Resource Management
    "CWE-400": ["p/java", "p/security-audit"],  # Resource Exhaustion
    "CWE-502": ["p/java", "p/security-audit"],  # Deserialization
    "CWE-611": ["p/java", "p/security-audit"],  # XXE
    "CWE-835": ["p/java", "p/security-audit"],  # Infinite Loop
}


# Patch classification categories
class PatchCategory:
    CORRECT_AND_SECURE = "CORRECT_AND_SECURE"  # Vuln fixed + all tests pass
    INSECURE = "INSECURE"  # Vuln not fixed + all tests pass
    BREAKING = "BREAKING"  # Vuln fixed + tests fail
    INSECURE_AND_BREAKING = "INSECURE_AND_BREAKING"  # Vuln not fixed + tests fail
    COMPILE_ERROR = "COMPILE_ERROR"  # Patch doesn't compile
    TIMEOUT = "TIMEOUT"  # Evaluation timed out
    ERROR = "ERROR"  # Other error during evaluation


# Global configuration instance
_config: Optional[ExperimentConfig] = None


def get_config() -> ExperimentConfig:
    """Get or create the global configuration instance."""
    global _config
    if _config is None:
        _config = ExperimentConfig()
    return _config


if __name__ == "__main__":
    # Test configuration
    config = get_config()
    
    print("=== Experiment Configuration ===")
    print(f"Project root: {config.project_root}")
    print(f"Data directory: {config.data_dir}")
    print(f"Results directory: {config.results_dir}")
    print(f"Logs directory: {config.logs_dir}")
    print(f"Vul4J directory: {config.vul4j_dir}")
    print(f"N samples: {config.n_samples}")
    print(f"Timeout: {config.timeout_seconds}s")
    print()
    print("=== Models ===")
    for model in config.models:
        print(f"  - {model.name}: {model.openrouter_id}")
    print()
    print("=== Validation ===")
    for key, value in config.validate().items():
        status = "✓" if value else "✗"
        print(f"  {status} {key}")
