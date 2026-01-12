
import sys
import subprocess
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from logger import init_phase_logger
from config import get_config


def check_python_version() -> bool:
    version = sys.version_info
    return version.major >= 3 and version.minor >= 8


def check_package_imports() -> dict:
    packages = {
        "openai": False,
        "httpx": False,
        "aiohttp": False,
        "pandas": False,
        "numpy": False,
        "git": False,  # gitpython
        "loguru": False,
        "matplotlib": False,
        "seaborn": False,
        "dotenv": False,  # python-dotenv
        "tqdm": False,
        "yaml": False,  # pyyaml
    }
    
    for package in packages:
        try:
            __import__(package)
            packages[package] = True
        except ImportError:
            packages[package] = False
    
    return packages


def check_semgrep() -> tuple:
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        return False, result.stderr
    except FileNotFoundError:
        return False, "Semgrep not found in PATH"
    except Exception as e:
        return False, str(e)


def check_docker_container() -> tuple:
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=vul4j", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if "vul4j" in result.stdout:
            return True, "Container 'vul4j' is running"
        return False, "Container 'vul4j' is not running"
    except FileNotFoundError:
        return False, "Docker not found in PATH"
    except Exception as e:
        return False, str(e)


def check_vul4j_in_docker() -> tuple:
    try:
        result = subprocess.run(
            ["docker", "exec", "vul4j", "vul4j", "info", "--id", "VUL4J-10"],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0 and "VUL4J-10" in result.stdout:
            return True, "vul4j is accessible in Docker"
        return False, result.stderr or "vul4j command failed"
    except Exception as e:
        return False, str(e)


def check_openrouter_api_key() -> bool:
    config = get_config()
    return bool(config.openrouter_api_key) and config.openrouter_api_key != "your_key_here"


def check_directory_structure() -> dict:
    config = get_config()
    dirs = {
        "data": config.data_dir.exists(),
        "data/vulnerabilities": (config.data_dir / "vulnerabilities").exists(),
        "results": config.results_dir.exists(),
        "results/patches": (config.results_dir / "patches").exists(),
        "results/evaluations": (config.results_dir / "evaluations").exists(),
        "results/aggregated": (config.results_dir / "aggregated").exists(),
        "logs": config.logs_dir.exists(),
        "vul4j": config.vul4j_dir.exists(),
    }
    return dirs


def main():
    # Initialize logger
    log_dir = Path(__file__).parent.parent / "logs"
    logger = init_phase_logger("VERIFY", "verify_environment.log", str(log_dir))
    
    logger.info("Starting environment verification...")
    
    all_passed = True
    
    # 1. Python version
    logger.info("Checking Python version...")
    python_ok = check_python_version()
    if python_ok:
        logger.success(f"Python version: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    else:
        logger.error(f"Python version {sys.version_info.major}.{sys.version_info.minor} < 3.8")
        all_passed = False
    
    # 2. Package imports
    logger.info("Checking package imports...")
    packages = check_package_imports()
    for package, installed in packages.items():
        if installed:
            logger.success(f"Package '{package}' imported successfully")
        else:
            logger.error(f"Package '{package}' failed to import")
            all_passed = False
    
    # 3. Semgrep
    logger.info("Checking Semgrep installation...")
    semgrep_ok, semgrep_msg = check_semgrep()
    if semgrep_ok:
        logger.success(f"Semgrep version: {semgrep_msg}")
    else:
        logger.warning(f"Semgrep check: {semgrep_msg}")
        logger.info("Note: Semgrep will be run inside Docker container")
    
    # 4. Docker container
    logger.info("Checking Docker container...")
    docker_ok, docker_msg = check_docker_container()
    if docker_ok:
        logger.success(docker_msg)
    else:
        logger.error(docker_msg)
        all_passed = False
    
    # 5. Vul4J in Docker
    if docker_ok:
        logger.info("Checking vul4j in Docker...")
        vul4j_ok, vul4j_msg = check_vul4j_in_docker()
        if vul4j_ok:
            logger.success(vul4j_msg)
        else:
            logger.error(f"vul4j check failed: {vul4j_msg}")
            all_passed = False
    
    # 6. OpenRouter API key
    logger.info("Checking OpenRouter API key...")
    api_key_ok = check_openrouter_api_key()
    if api_key_ok:
        logger.success("OpenRouter API key is set")
    else:
        logger.warning("OpenRouter API key is NOT set - create .env file from .env.template")
    
    # 7. Directory structure
    logger.info("Checking directory structure...")
    dirs = check_directory_structure()
    for dir_name, exists in dirs.items():
        if exists:
            logger.success(f"Directory '{dir_name}' exists")
        else:
            logger.error(f"Directory '{dir_name}' does not exist")
            all_passed = False
    
    # Summary
    logger.info("=" * 50)
    if all_passed:
        logger.success("All environment checks passed!")
    else:
        logger.warning("Some checks failed - review the log above")
    
    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
