"""
Partial Scorer Module
"""

from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class PatchScores:
    """Complete scoring result for a patch."""
    security_score: float      # 0.0 to 1.0
    functionality_score: float # 0.0 to 1.0
    srs: float                 # Security Repair Score (0.0 to 1.0)
    compilation_success: bool
    details: Dict
    
    def to_dict(self) -> Dict:
        return {
            "security_score": round(self.security_score, 4),
            "functionality_score": round(self.functionality_score, 4),
            "srs": round(self.srs, 4),
            "compilation_success": self.compilation_success,
            "details": self.details
        }


def calculate_security_score(
    pov_passed: bool,
    semgrep_warnings_before: int,
    semgrep_warnings_after: int
) -> float:
    """
    Calculate Security Score based on PoV test result and Semgrep warning reduction.
    
    Formula: S = P × (1 - min(W_after / W_before, 1))
    Where:
        P = 1 if PoV tests pass (vulnerability fixed), 0 otherwise
        W_before = Semgrep warnings on vulnerable code
        W_after = Semgrep warnings on patched code
    
    Args:
        pov_passed: Whether PoV tests passed (vulnerability fixed)
        semgrep_warnings_before: Number of Semgrep warnings on vulnerable code
        semgrep_warnings_after: Number of Semgrep warnings on patched code
        
    Returns:
        Security score between 0.0 and 1.0
    """
    # P component: PoV test result
    p = 1.0 if pov_passed else 0.0
    
    # Warning reduction component
    # Avoid division by zero
    w_before = max(semgrep_warnings_before, 1)
    w_after = semgrep_warnings_after
    
    # Calculate warning reduction ratio
    warning_ratio = min(w_after / w_before, 1.0)
    warning_reduction = 1.0 - warning_ratio
    
    # Final security score
    security_score = p * warning_reduction
    
    # If PoV passed but no Semgrep data, give full credit
    if pov_passed and semgrep_warnings_before == 0:
        security_score = 1.0
    
    return security_score


def calculate_functionality_score(
    tests_passed: int,
    tests_passed_human: int
) -> float:
    """
    Calculate Functionality Score based on test pass rate relative to human baseline.
    
    Formula: F = T_passed / T_human
    Where:
        T_passed = Tests passed by the LLM patch
        T_human = Tests passed by the human patch (baseline)
    
    Args:
        tests_passed: Number of tests passed by the LLM patch
        tests_passed_human: Number of tests passed by human patch (baseline)
        
    Returns:
        Functionality score between 0.0 and 1.0
    """
    # Avoid division by zero
    if tests_passed_human == 0:
        # If human patch passes 0 tests, any passing tests is good
        return 1.0 if tests_passed >= 0 else 0.0
    
    # Calculate ratio (cap at 1.0 - can't be better than human)
    functionality_score = min(tests_passed / tests_passed_human, 1.0)
    
    return functionality_score


def calculate_srs(
    compilation_success: bool,
    security_score: float,
    functionality_score: float,
    weight_security: float = 0.5,
    weight_functionality: float = 0.5
) -> float:
    """
    Calculate Security Repair Score (SRS).
    
    Formula: SRS = C × (w_s × S + w_f × F)
    Where:
        C = 1 if compilation succeeds, 0 otherwise
        S = Security Score
        F = Functionality Score
        w_s, w_f = Weights (default 0.5 each)
    
    Args:
        compilation_success: Whether the patch compiled successfully
        security_score: Security score (0.0 to 1.0)
        functionality_score: Functionality score (0.0 to 1.0)
        weight_security: Weight for security component (default 0.5)
        weight_functionality: Weight for functionality component (default 0.5)
        
    Returns:
        SRS between 0.0 and 1.0
    """
    # Compilation gate
    c = 1.0 if compilation_success else 0.0
    
    # Weighted combination
    weighted_score = (weight_security * security_score + 
                      weight_functionality * functionality_score)
    
    # Final SRS
    srs = c * weighted_score
    
    return srs


def score_patch(
    compilation_success: bool,
    pov_passed: bool,
    tests_passed: int,
    tests_passed_human: int,
    semgrep_warnings_before: int = 0,
    semgrep_warnings_after: int = 0,
    weight_security: float = 0.5,
    weight_functionality: float = 0.5
) -> PatchScores:
    """
    Calculate all scores for a patch.
    
    This is the main entry point for scoring.
    
    Args:
        compilation_success: Whether compilation succeeded
        pov_passed: Whether PoV tests passed (vulnerability fixed)
        tests_passed: Number of tests passed by the patch
        tests_passed_human: Number of tests passed by human patch (baseline)
        semgrep_warnings_before: Semgrep warnings on vulnerable code
        semgrep_warnings_after: Semgrep warnings on patched code
        weight_security: Weight for security in SRS (default 0.5)
        weight_functionality: Weight for functionality in SRS (default 0.5)
        
    Returns:
        PatchScores with all calculated scores
    """
    # Calculate component scores
    if compilation_success:
        security_score = calculate_security_score(
            pov_passed, semgrep_warnings_before, semgrep_warnings_after
        )
        functionality_score = calculate_functionality_score(
            tests_passed, tests_passed_human
        )
    else:
        # Compilation failed - all scores are 0
        security_score = 0.0
        functionality_score = 0.0
    
    # Calculate SRS
    srs = calculate_srs(
        compilation_success, security_score, functionality_score,
        weight_security, weight_functionality
    )
    
    return PatchScores(
        security_score=security_score,
        functionality_score=functionality_score,
        srs=srs,
        compilation_success=compilation_success,
        details={
            "pov_passed": pov_passed,
            "tests_passed": tests_passed,
            "tests_passed_human": tests_passed_human,
            "semgrep_warnings_before": semgrep_warnings_before,
            "semgrep_warnings_after": semgrep_warnings_after,
            "weight_security": weight_security,
            "weight_functionality": weight_functionality
        }
    )


def aggregate_scores(scores_list: list) -> Dict:
    """
    Aggregate scores across multiple patches.
    
    Args:
        scores_list: List of PatchScores objects or dicts
        
    Returns:
        Dictionary with aggregated statistics
    """
    if not scores_list:
        return {}
    
    total = len(scores_list)
    
    # Extract scores
    security_scores = []
    functionality_scores = []
    srs_scores = []
    compile_success_count = 0
    
    for s in scores_list:
        if isinstance(s, dict):
            security_scores.append(s.get("security_score", 0))
            functionality_scores.append(s.get("functionality_score", 0))
            srs_scores.append(s.get("srs", 0))
            if s.get("compilation_success"):
                compile_success_count += 1
        else:
            security_scores.append(s.security_score)
            functionality_scores.append(s.functionality_score)
            srs_scores.append(s.srs)
            if s.compilation_success:
                compile_success_count += 1
    
    def stats(values):
        if not values:
            return {"mean": 0, "min": 0, "max": 0, "std": 0}
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std = variance ** 0.5
        return {
            "mean": round(mean, 4),
            "min": round(min(values), 4),
            "max": round(max(values), 4),
            "std": round(std, 4)
        }
    
    # Count categories
    perfect_count = sum(1 for s in srs_scores if s == 1.0)
    near_success_count = sum(1 for s in srs_scores if 0.8 <= s < 1.0)  # 0.8 <= SRS < 1.0
    partial_success_count = sum(1 for s in srs_scores if 0 < s < 0.8)   # 0 < SRS < 0.8
    complete_failure_count = sum(1 for s in srs_scores if s == 0)
    
    return {
        "total_patches": total,
        "compilation_success_rate": round(compile_success_count / total, 4),
        "security_score": stats(security_scores),
        "functionality_score": stats(functionality_scores),
        "srs": stats(srs_scores),
        "perfect_patches": perfect_count,
        "near_success_patches": near_success_count,  # SRS > 0.8 (paper: "close to correct")
        "partial_success_patches": partial_success_count,
        "complete_failure_patches": complete_failure_count
    }


def aggregate_scores_by_model(scores_by_model: Dict[str, list]) -> Dict:
    """
    Aggregate scores grouped by model.
    
    Args:
        scores_by_model: Dictionary mapping model name to list of scores
        
    Returns:
        Dictionary with per-model aggregated statistics
    """
    return {
        model: aggregate_scores(scores)
        for model, scores in scores_by_model.items()
    }
