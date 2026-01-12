"""
Failure Analyzer Module
"""

import re
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class PrimaryFailureCategory(Enum):
    """Primary failure categories."""
    CORRECT_AND_SECURE = "correct_and_secure"
    COMPILATION_FAILURE = "compilation_failure"
    SECURITY_FAILURE = "security_failure"
    FUNCTIONALITY_FAILURE = "functionality_failure"
    INSECURE_AND_BREAKING = "insecure_and_breaking"


class CompilationErrorType(Enum):
    """Subcategories for compilation failures."""
    SYNTAX_ERROR = "syntax_error"
    MISSING_IMPORT = "missing_import"
    TYPE_MISMATCH = "type_mismatch"
    UNRESOLVED_REFERENCE = "unresolved_reference"
    OTHER = "other"


class SecurityFailureType(Enum):
    """Subcategories for security failures."""
    NO_CHANGE = "no_change"           # Patch identical to vulnerable code
    INCOMPLETE_FIX = "incomplete_fix" # Partial fix, vulnerability remains
    WRONG_LOCATION = "wrong_location" # Fix applied to wrong code section
    WRONG_STRATEGY = "wrong_strategy" # Incorrect fix approach
    OTHER = "other"


class FunctionalityFailureType(Enum):
    """Subcategories for functionality failures."""
    BEHAVIORAL_CHANGE = "behavioral_change"   # Changed expected behavior
    API_VIOLATION = "api_violation"           # Broke API contract
    OVERCORRECTION = "overcorrection"         # Too restrictive fix
    OTHER = "other"


# Regex patterns for compilation error classification
COMPILATION_ERROR_PATTERNS = {
    CompilationErrorType.SYNTAX_ERROR: [
        r"error:.*expected",
        r"illegal start of",
        r"';' expected",
        r"'\)' expected",
        r"'\}' expected",
        r"unclosed string literal",
        r"reached end of file while parsing",
    ],
    CompilationErrorType.MISSING_IMPORT: [
        r"cannot find symbol.*class",
        r"package .* does not exist",
        r"cannot access class",
        r"symbol:.*class.*not found",
    ],
    CompilationErrorType.TYPE_MISMATCH: [
        r"incompatible types",
        r"cannot be converted to",
        r"bad operand types",
        r"inconvertible types",
        r"required:.*found:",
    ],
    CompilationErrorType.UNRESOLVED_REFERENCE: [
        r"cannot find symbol.*variable",
        r"cannot find symbol.*method",
        r"method .* not found",
        r"variable .* not found",
        r"cannot resolve symbol",
    ],
}


@dataclass
class FailureClassification:
    """Complete failure classification result."""
    primary_category: str
    subcategory: Optional[str] = None
    confidence: float = 1.0
    details: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "primary_category": self.primary_category,
            "subcategory": self.subcategory,
            "confidence": self.confidence,
            "details": self.details
        }


def classify_compilation_error(error_message: str) -> Tuple[CompilationErrorType, float]:
    """
    Classify a compilation error into subcategories
    """
    if not error_message:
        return CompilationErrorType.OTHER, 0.5
    
    error_lower = error_message.lower()
    
    for error_type, patterns in COMPILATION_ERROR_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, error_lower, re.IGNORECASE):
                return error_type, 0.9
    
    return CompilationErrorType.OTHER, 0.5


def classify_security_failure(
    patch_code: str,
    vulnerable_code: str,
    pov_passed: bool,
    semgrep_warnings_before: int,
    semgrep_warnings_after: int
) -> Tuple[SecurityFailureType, float]:
    """
    Classify a security failure into subcategories.
    """
    # If PoV passed, this shouldn't be called
    if pov_passed:
        return SecurityFailureType.OTHER, 0.0
    
    # Check for NO_CHANGE - patch is identical to vulnerable code
    if patch_code and vulnerable_code:
        # Normalize whitespace for comparison
        patch_normalized = ' '.join(patch_code.split())
        vuln_normalized = ' '.join(vulnerable_code.split())
        if patch_normalized == vuln_normalized:
            return SecurityFailureType.NO_CHANGE, 1.0
    
    # Check for INCOMPLETE_FIX - some warnings reduced but not all
    if semgrep_warnings_after > 0 and semgrep_warnings_after < semgrep_warnings_before:
        return SecurityFailureType.INCOMPLETE_FIX, 0.8
    
    # If no warnings reduced at all
    if semgrep_warnings_after >= semgrep_warnings_before:
        return SecurityFailureType.WRONG_STRATEGY, 0.7
    
    return SecurityFailureType.OTHER, 0.5


def classify_functionality_failure(
    tests_passed: int,
    tests_passed_human: int,
    tests_failed: int,
    failed_test_names: list
) -> Tuple[FunctionalityFailureType, float]:
    """
    Classify a functionality failure into subcategories.
    """
    if tests_passed >= tests_passed_human:
        return FunctionalityFailureType.OTHER, 0.0
    
    # Calculate failure severity
    failure_rate = tests_failed / max(tests_passed_human, 1)
    
    # High failure rate suggests overcorrection (too restrictive)
    if failure_rate > 0.5:
        return FunctionalityFailureType.OVERCORRECTION, 0.7
    
    # Check for API-related failures in test names
    api_keywords = ['api', 'interface', 'contract', 'public', 'endpoint']
    if failed_test_names:
        api_failures = sum(1 for name in failed_test_names 
                         if any(kw in name.lower() for kw in api_keywords))
        if api_failures > 0:
            return FunctionalityFailureType.API_VIOLATION, 0.7
    
    # Default to behavioral change
    return FunctionalityFailureType.BEHAVIORAL_CHANGE, 0.6


def classify_patch(
    compilation_success: bool,
    compilation_error: Optional[str],
    pov_passed: bool,
    tests_passed: int,
    tests_passed_human: int,
    patch_code: Optional[str] = None,
    vulnerable_code: Optional[str] = None,
    semgrep_warnings_before: int = 0,
    semgrep_warnings_after: int = 0,
    tests_failed: int = 0,
    failed_test_names: list = None
) -> FailureClassification:
    """
    Classify a patch into the hierarchical failure taxonomy.
    """
    failed_test_names = failed_test_names or []
    
    # Level 1: Compilation check
    if not compilation_success:
        error_type, confidence = classify_compilation_error(compilation_error)
        return FailureClassification(
            primary_category=PrimaryFailureCategory.COMPILATION_FAILURE.value,
            subcategory=error_type.value,
            confidence=confidence,
            details={"error_snippet": (compilation_error or "")[:500]}
        )
    
    # Level 2: Security check (PoV tests)
    is_secure = pov_passed
    
    # Level 3: Functionality check (compare with human baseline)
    is_functional = tests_passed >= tests_passed_human
    
    # Classify based on security and functionality
    if is_secure and is_functional:
        return FailureClassification(
            primary_category=PrimaryFailureCategory.CORRECT_AND_SECURE.value,
            subcategory=None,
            confidence=1.0
        )
    
    elif not is_secure and is_functional:
        # Security failure only
        sec_type, confidence = classify_security_failure(
            patch_code, vulnerable_code, pov_passed,
            semgrep_warnings_before, semgrep_warnings_after
        )
        return FailureClassification(
            primary_category=PrimaryFailureCategory.SECURITY_FAILURE.value,
            subcategory=sec_type.value,
            confidence=confidence
        )
    
    elif is_secure and not is_functional:
        # Functionality failure only
        func_type, confidence = classify_functionality_failure(
            tests_passed, tests_passed_human, tests_failed, failed_test_names
        )
        return FailureClassification(
            primary_category=PrimaryFailureCategory.FUNCTIONALITY_FAILURE.value,
            subcategory=func_type.value,
            confidence=confidence
        )
    
    else:
        # Both security and functionality failures
        # Determine which is more severe for subcategorization
        sec_type, sec_conf = classify_security_failure(
            patch_code, vulnerable_code, pov_passed,
            semgrep_warnings_before, semgrep_warnings_after
        )
        func_type, func_conf = classify_functionality_failure(
            tests_passed, tests_passed_human, tests_failed, failed_test_names
        )
        
        return FailureClassification(
            primary_category=PrimaryFailureCategory.INSECURE_AND_BREAKING.value,
            subcategory=f"{sec_type.value}+{func_type.value}",
            confidence=min(sec_conf, func_conf),
            details={
                "security_subcategory": sec_type.value,
                "functionality_subcategory": func_type.value
            }
        )


def get_failure_distribution(classifications: list) -> Dict:
    """
    Calculate failure distribution from a list of classifications.
    """
    total = len(classifications)
    if total == 0:
        return {}
    
    # Count primary categories
    primary_counts = {}
    subcategory_counts = {}
    
    for clf in classifications:
        if isinstance(clf, dict):
            primary = clf.get("primary_category", "unknown")
            sub = clf.get("subcategory")
        else:
            primary = clf.primary_category
            sub = clf.subcategory
        
        primary_counts[primary] = primary_counts.get(primary, 0) + 1
        
        if sub:
            key = f"{primary}/{sub}"
            subcategory_counts[key] = subcategory_counts.get(key, 0) + 1
    
    return {
        "total": total,
        "primary_distribution": {
            k: {"count": v, "percentage": round(v / total * 100, 2)}
            for k, v in sorted(primary_counts.items(), key=lambda x: -x[1])
        },
        "subcategory_distribution": {
            k: {"count": v, "percentage": round(v / total * 100, 2)}
            for k, v in sorted(subcategory_counts.items(), key=lambda x: -x[1])
        }
    }
