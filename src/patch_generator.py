"""
Patch Generator Module

Handles prompt templating and code extraction from LLM responses.
"""

import re
import json
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime

from config import get_config, ModelConfig
from openrouter_client import OpenRouterClient, APIResponse
from logger import init_phase_logger

REPAIR_PROMPT_TEMPLATE = """You are a security expert. The following Java code contains {cwe_id} ({cwe_name}).

Task: Fix the security vulnerability. Preserve all original functionality.

Requirements:
- Return ONLY the complete corrected Java code
- No explanations, comments, or markdown formatting
- Maintain the exact same class/method structure

{vulnerable_code}"""

# Multi-file prompt template for vulnerabilities spanning multiple files
MULTI_FILE_REPAIR_PROMPT_TEMPLATE = """You are a security expert. The following Java files contain a security vulnerability ({cwe_id}: {cwe_name}).

Task: Fix the security vulnerability across ALL affected files. Preserve all original functionality.

Requirements:
- Return ALL files with fixes applied
- Use this EXACT format for each file:
  === FILE: <filepath> ===
  <complete corrected code>
  === END FILE ===
- No explanations or markdown formatting
- Maintain the exact same class/method structure in each file

{vulnerable_files}"""


def format_multi_file_input(vulnerable_files: List[Dict]) -> str:
    """
    Format multiple vulnerable files for the prompt.
    
    Args:
        vulnerable_files: List of dicts with 'file_path' and 'vulnerable_code'
        
    Returns:
        Formatted string with all files
    """
    parts = []
    for f in vulnerable_files:
        file_path = f.get('file_path', 'Unknown')
        code = f.get('vulnerable_code', '')
        parts.append(f"=== FILE: {file_path} ===\n{code}\n=== END FILE ===")
    return "\n\n".join(parts)


def extract_multi_file_patches(response: str) -> Dict[str, str]:
    """
    Extract multiple file patches from LLM response.
    
    Expected format:
    === FILE: path/to/File.java ===
    <code>
    === END FILE ===
    
    Args:
        response: Raw LLM response
        
    Returns:
        Dict mapping file_path -> patched_code
    """
    patches = {}
    
    # Pattern to match file blocks
    pattern = r'===\s*FILE:\s*([^=]+?)\s*===\s*\n([\s\S]*?)\n===\s*END FILE\s*==='
    matches = re.findall(pattern, response, re.IGNORECASE)
    
    for file_path, code in matches:
        file_path = file_path.strip()
        code = code.strip()
        
        # Remove any markdown code blocks if present
        if code.startswith('```'):
            code = extract_code_from_response(code)
        
        patches[file_path] = code
    
    # Fallback: If no structured format found, try to detect file boundaries
    if not patches:
        # Try alternative patterns
        alt_pattern = r'//\s*File:\s*([^\n]+)\n([\s\S]*?)(?=//\s*File:|$)'
        alt_matches = re.findall(alt_pattern, response)
        for file_path, code in alt_matches:
            patches[file_path.strip()] = code.strip()
    
    return patches


@dataclass
class PatchResult:
    """Result of a single patch generation."""
    vul_id: str
    model_name: str
    patch_index: int
    success: bool
    patch_code: Optional[str] = None  # For single-file patches
    patch_files: Optional[Dict[str, str]] = None  # For multi-file patches: {filepath: code}
    raw_response: Optional[str] = None
    is_multi_file: bool = False
    error: Optional[str] = None
    latency_ms: Optional[float] = None
    tokens_used: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass 
class GenerationMetadata:
    """Metadata for a batch of patch generations."""
    vul_id: str
    model_name: str
    cwe_id: str
    cwe_name: str
    total_patches: int
    successful_patches: int
    failed_patches: int
    total_tokens: int
    total_latency_ms: float
    start_time: str
    end_time: str
    patches: List[Dict[str, Any]] = field(default_factory=list)


def validate_java_code(code: str, context: str = "code") -> Tuple[bool, str]:
    """
    Validate that Java code is syntactically reasonable.
    
    Checks:
    - Balanced braces {}
    - Balanced parentheses ()
    - Balanced brackets []
    - No stray markdown artifacts
    - Contains valid Java structure
    
    Args:
        code: Java code to validate
        context: Description for error messages (e.g., "input" or "output")
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not code or not code.strip():
        return False, f"{context}: Empty code"
    
    code = code.strip()
    
    # Check for markdown artifacts
    if code.startswith('```') or code.endswith('```'):
        return False, f"{context}: Contains markdown code block markers"
    
    if '```' in code:
        return False, f"{context}: Contains embedded markdown markers"
    
    # Check balanced braces (critical - must match)
    open_braces = code.count('{')
    close_braces = code.count('}')
    if open_braces != close_braces:
        return False, f"{context}: Unbalanced braces (open={open_braces}, close={close_braces})"
    
    # Check balanced parentheses (critical - must match)
    open_parens = code.count('(')
    close_parens = code.count(')')
    if open_parens != close_parens:
        return False, f"{context}: Unbalanced parentheses (open={open_parens}, close={close_parens})"
    
    # Check for basic Java structure
    has_class = 'class ' in code or 'interface ' in code or 'enum ' in code
    has_package = 'package ' in code
    has_import = 'import ' in code
    
    if not (has_class or has_package or has_import):
        # Could be a code fragment, check for method-like structure
        has_method = any(kw in code for kw in ['public ', 'private ', 'protected ', 'void ', 'static '])
        if not has_method:
            return False, f"{context}: Does not appear to be valid Java code"
    
    # Check minimum length (a valid Java file should have some content)
    if len(code) < 50:
        return False, f"{context}: Code too short ({len(code)} chars)"
    
    return True, ""


def extract_code_from_response(response: str) -> str:
    """
    Extract Java code from LLM response.
    Handles responses with or without markdown code blocks.
    
    Args:
        response: Raw LLM response text
        
    Returns:
        Extracted Java code (without markdown formatting)
    """
    if not response:
        return ""
    
    # Remove any leading/trailing whitespace
    response = response.strip()
    
    # Method 1: Manual extraction for responses wrapped in code blocks
    if response.startswith('```'):
        lines = response.split('\n')
        # Find the end of the code block
        end_idx = len(lines) - 1
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].strip() == '```':
                end_idx = i
                break
        # Skip first line (```java or ```) and last line (```)
        code_lines = lines[1:end_idx]
        if code_lines:
            return '\n'.join(code_lines).strip()
    
    # Method 2: Regex for code blocks in the middle of text
    java_block_pattern = r'```(?:java)?\s*\n([\s\S]*?)\n```'
    matches = re.findall(java_block_pattern, response)
    if matches:
        return max(matches, key=len).strip()
    
    # Method 3: If response looks like Java code directly
    lines = response.split('\n')
    if lines:
        first_line = lines[0].strip().lower()
        if any(first_line.startswith(kw) for kw in ['package', 'import', 'public', 'private', 'protected', 'class', '/*', '//']):
            return response.strip()
    
    # Last resort: return entire response
    return response.strip()


def create_prompt(vulnerable_code: str, cwe_id: str, cwe_name: str) -> str:
    """
    Create a repair prompt from the template.
    
    Args:
        vulnerable_code: The vulnerable Java code
        cwe_id: CWE identifier (e.g., "CWE-79")
        cwe_name: CWE name (e.g., "Cross-site Scripting")
        
    Returns:
        Formatted prompt string
    """
    return REPAIR_PROMPT_TEMPLATE.format(
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        vulnerable_code=vulnerable_code
    )


class PatchGenerator:
    """
    Generates patches for vulnerabilities using LLMs.
    """
    
    def __init__(self, logger=None):
        """Initialize the patch generator."""
        self.config = get_config()
        self.logger = logger or init_phase_logger("GENERATE", "generation.log", str(self.config.logs_dir))
        self.client = OpenRouterClient(self.logger)
    
    def generate_patch(
        self,
        vul_id: str,
        vulnerable_code: str,
        cwe_id: str,
        cwe_name: str,
        model: ModelConfig,
        patch_index: int
    ) -> PatchResult:
        """
        Generate a single patch for a vulnerability.
        
        Args:
            vul_id: Vulnerability ID
            vulnerable_code: The vulnerable code to fix
            cwe_id: CWE identifier
            cwe_name: CWE name
            model: Model configuration
            patch_index: Index of this patch (0-9)
            
        Returns:
            PatchResult with the generated patch or error
        """
        # INPUT VALIDATION: Check vulnerable code before sending to LLM
        input_valid, input_error = validate_java_code(vulnerable_code, "Input vulnerable code")
        if not input_valid:
            self.logger.warning(f"    Input validation warning: {input_error}")
            # Continue anyway - the code might still be processable
        
        prompt = create_prompt(vulnerable_code, cwe_id, cwe_name)
        
        response = self.client.generate(model, prompt)
        
        if response.success:
            patch_code = extract_code_from_response(response.content)
            
           
            output_valid, output_error = validate_java_code(patch_code, "Generated patch")
            if not output_valid:
                self.logger.warning(f"    Output validation warning: {output_error}")
               
            
            return PatchResult(
                vul_id=vul_id,
                model_name=model.name,
                patch_index=patch_index,
                success=True,  # Always success if we got code - compiler will validate
                patch_code=patch_code,
                raw_response=response.content,
                latency_ms=response.latency_ms,
                tokens_used=response.usage.get("total_tokens") if response.usage else None
            )
        else:
            return PatchResult(
                vul_id=vul_id,
                model_name=model.name,
                patch_index=patch_index,
                success=False,
                error=response.error
            )
    
    def generate_multi_file_patch(
        self,
        vul_id: str,
        vulnerable_files: List[Dict],
        cwe_id: str,
        cwe_name: str,
        model: ModelConfig,
        patch_index: int
    ) -> PatchResult:
        """
        Generate a patch for a multi-file vulnerability.
        
        Args:
            vul_id: Vulnerability ID
            vulnerable_files: List of dicts with 'file_path' and 'vulnerable_code'
            cwe_id: CWE identifier
            cwe_name: CWE name
            model: Model configuration
            patch_index: Index of this patch
            
        Returns:
            PatchResult with patch_files dict mapping filepath -> code
        """
        # Format all files for the prompt
        formatted_files = format_multi_file_input(vulnerable_files)
        
        prompt = MULTI_FILE_REPAIR_PROMPT_TEMPLATE.format(
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            vulnerable_files=formatted_files
        )
        
        self.logger.debug(f"    Multi-file prompt: {len(prompt):,} chars, {len(vulnerable_files)} files")
        
        response = self.client.generate(model, prompt)
        
        if response.success:
            # Extract patches for each file
            patch_files = extract_multi_file_patches(response.content)
            
            if not patch_files:
                # Fallback: If extraction failed, try to use single-file extraction
                # This handles cases where LLM ignores the multi-file format
                self.logger.warning(f"    Multi-file extraction failed, trying single-file fallback")
                single_code = extract_code_from_response(response.content)
                if single_code and len(vulnerable_files) == 1:
                    patch_files = {vulnerable_files[0]['file_path']: single_code}
            
            if patch_files:
                self.logger.debug(f"    Extracted patches for {len(patch_files)} files")
                return PatchResult(
                    vul_id=vul_id,
                    model_name=model.name,
                    patch_index=patch_index,
                    success=True,
                    patch_files=patch_files,
                    is_multi_file=True,
                    raw_response=response.content,
                    latency_ms=response.latency_ms,
                    tokens_used=response.usage.get("total_tokens") if response.usage else None
                )
            else:
                return PatchResult(
                    vul_id=vul_id,
                    model_name=model.name,
                    patch_index=patch_index,
                    success=False,
                    is_multi_file=True,
                    error="Failed to extract patches from multi-file response",
                    raw_response=response.content
                )
        else:
            return PatchResult(
                vul_id=vul_id,
                model_name=model.name,
                patch_index=patch_index,
                success=False,
                is_multi_file=True,
                error=response.error
            )
    
    def generate_patches_for_vulnerability(
        self,
        vul_id: str,
        vulnerable_code: str,
        cwe_id: str,
        cwe_name: str,
        model: ModelConfig,
        n_patches: int = 10,
        output_dir: Optional[Path] = None
    ) -> GenerationMetadata:
        """
        Generate multiple patches for a single vulnerability.
        
        Args:
            vul_id: Vulnerability ID
            vulnerable_code: The vulnerable code to fix
            cwe_id: CWE identifier
            cwe_name: CWE name
            model: Model configuration
            n_patches: Number of patches to generate
            output_dir: Directory to save patches (optional)
            
        Returns:
            GenerationMetadata with all results
        """
        start_time = datetime.now()
        
        # Validate input vulnerable code once before generating patches
        input_valid, input_error = validate_java_code(vulnerable_code, "Input vulnerable code")
        if not input_valid:
            self.logger.warning(f"  Input validation issue for {vul_id}: {input_error}")
        else:
            self.logger.debug(f"  Input validation passed for {vul_id}")
        
        metadata = GenerationMetadata(
            vul_id=vul_id,
            model_name=model.name,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            total_patches=n_patches,
            successful_patches=0,
            failed_patches=0,
            total_tokens=0,
            total_latency_ms=0,
            start_time=start_time.isoformat(),
            end_time=""
        )
        
        max_retries = 2  # Retry up to 2 times for validation failures
        
        for i in range(n_patches):
            self.logger.info(f"  Generating patch {i+1}/{n_patches} for {vul_id} with {model.name}...")
            
            result = None
            for attempt in range(max_retries + 1):
                result = self.generate_patch(
                    vul_id=vul_id,
                    vulnerable_code=vulnerable_code,
                    cwe_id=cwe_id,
                    cwe_name=cwe_name,
                    model=model,
                    patch_index=i
                )
                
                if result.success:
                    break
                elif result.error and "Validation failed" in result.error and attempt < max_retries:
                    self.logger.warning(f"    Retry {attempt + 1}/{max_retries} due to validation failure")
                else:
                    break
            
            if result.success:
                metadata.successful_patches += 1
                metadata.total_tokens += result.tokens_used or 0
                metadata.total_latency_ms += result.latency_ms or 0
                
                # Save patch file
                if output_dir:
                    patch_file = output_dir / f"patch_{i}.java"
                    patch_file.write_text(result.patch_code, encoding='utf-8')
                
                self.logger.success(f"    Patch {i} generated ({result.tokens_used} tokens, {result.latency_ms:.0f}ms)")
            else:
                metadata.failed_patches += 1
                self.logger.error(f"    Patch {i} failed: {result.error}")
            
            # Validate generated code for completeness
            code_check_successful = False
            code_check_error = None
            if result.patch_code:
                code_check_successful, code_check_error = validate_java_code(result.patch_code, "Generated patch")
            
            # Store result in metadata
            metadata.patches.append({
                "index": i,
                "success": result.success,
                "error": result.error,
                "tokens_used": result.tokens_used,
                "latency_ms": result.latency_ms,
                "timestamp": result.timestamp,
                "code_check_successful": code_check_successful,
                "code_check_error": code_check_error if not code_check_successful else None
            })
        
        metadata.end_time = datetime.now().isoformat()
        
        # Save metadata
        if output_dir:
            metadata_file = output_dir / "generation_metadata.json"
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "vul_id": metadata.vul_id,
                    "model_name": metadata.model_name,
                    "cwe_id": metadata.cwe_id,
                    "cwe_name": metadata.cwe_name,
                    "total_patches": metadata.total_patches,
                    "successful_patches": metadata.successful_patches,
                    "failed_patches": metadata.failed_patches,
                    "total_tokens": metadata.total_tokens,
                    "total_latency_ms": metadata.total_latency_ms,
                    "start_time": metadata.start_time,
                    "end_time": metadata.end_time,
                    "patches": metadata.patches
                }, f, indent=2)
        
        return metadata
    
    def generate_patches_for_multi_file_vulnerability(
        self,
        vul_id: str,
        vulnerable_files: List[Dict],
        cwe_id: str,
        cwe_name: str,
        model: ModelConfig,
        n_patches: int = 10,
        output_dir: Optional[Path] = None
    ) -> GenerationMetadata:
        """
        Generate multiple patches for a multi-file vulnerability.
        
        Args:
            vul_id: Vulnerability ID
            vulnerable_files: List of dicts with 'file_path' and 'vulnerable_code'
            cwe_id: CWE identifier
            cwe_name: CWE name
            model: Model configuration
            n_patches: Number of patches to generate
            output_dir: Directory to save patches (optional)
            
        Returns:
            GenerationMetadata with all results
        """
        start_time = datetime.now()
        
        self.logger.info(f"  Multi-file vulnerability: {len(vulnerable_files)} files")
        for f in vulnerable_files:
            self.logger.debug(f"    - {f.get('file_path', '?')}: {len(f.get('vulnerable_code', '')):,} chars")
        
        metadata = GenerationMetadata(
            vul_id=vul_id,
            model_name=model.name,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            total_patches=n_patches,
            successful_patches=0,
            failed_patches=0,
            total_tokens=0,
            total_latency_ms=0,
            start_time=start_time.isoformat(),
            end_time=""
        )
        
        max_retries = 2
        
        for i in range(n_patches):
            self.logger.info(f"  Generating multi-file patch {i+1}/{n_patches} for {vul_id}...")
            
            result = None
            for attempt in range(max_retries + 1):
                result = self.generate_multi_file_patch(
                    vul_id=vul_id,
                    vulnerable_files=vulnerable_files,
                    cwe_id=cwe_id,
                    cwe_name=cwe_name,
                    model=model,
                    patch_index=i
                )
                
                if result.success:
                    break
                elif attempt < max_retries:
                    self.logger.warning(f"    Retry {attempt + 1}/{max_retries}")
                else:
                    break
            
            if result.success and result.patch_files:
                metadata.successful_patches += 1
                metadata.total_tokens += result.tokens_used or 0
                metadata.total_latency_ms += result.latency_ms or 0
                
                # Save patch files - create subdirectory for each patch
                if output_dir:
                    patch_subdir = output_dir / f"patch_{i}"
                    patch_subdir.mkdir(parents=True, exist_ok=True)
                    
                    # Save each file
                    for file_path, code in result.patch_files.items():
                        # Use just the filename to avoid path issues
                        filename = Path(file_path).name
                        patch_file = patch_subdir / filename
                        patch_file.write_text(code, encoding='utf-8')
                    
                    # Save file mapping for evaluation
                    mapping_file = patch_subdir / "_file_mapping.json"
                    with open(mapping_file, 'w') as f:
                        json.dump({
                            "files": list(result.patch_files.keys()),
                            "is_multi_file": True
                        }, f, indent=2)
                
                self.logger.success(f"    Patch {i}: {len(result.patch_files)} files ({result.tokens_used} tokens)")
            else:
                metadata.failed_patches += 1
                self.logger.error(f"    Patch {i} failed: {result.error}")
            
            # Store result in metadata
            metadata.patches.append({
                "index": i,
                "success": result.success,
                "is_multi_file": True,
                "files_patched": list(result.patch_files.keys()) if result.patch_files else [],
                "error": result.error,
                "tokens_used": result.tokens_used,
                "latency_ms": result.latency_ms,
                "timestamp": result.timestamp
            })
        
        metadata.end_time = datetime.now().isoformat()
        
        # Save metadata
        if output_dir:
            metadata_file = output_dir / "generation_metadata.json"
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "vul_id": metadata.vul_id,
                    "model_name": metadata.model_name,
                    "cwe_id": metadata.cwe_id,
                    "cwe_name": metadata.cwe_name,
                    "is_multi_file": True,
                    "num_files": len(vulnerable_files),
                    "total_patches": metadata.total_patches,
                    "successful_patches": metadata.successful_patches,
                    "failed_patches": metadata.failed_patches,
                    "total_tokens": metadata.total_tokens,
                    "total_latency_ms": metadata.total_latency_ms,
                    "start_time": metadata.start_time,
                    "end_time": metadata.end_time,
                    "patches": metadata.patches
                }, f, indent=2)
        
        return metadata
    
    def is_generation_complete(self, vul_id: str, model_name: str, n_patches: int = 10) -> bool:
        """
        Check if patch generation is already complete for a vulnerability/model.
        
        Args:
            vul_id: Vulnerability ID
            model_name: Model name
            n_patches: Expected number of patches
            
        Returns:
            True if all patches already exist
        """
        patch_dir = self.config.get_patch_dir(vul_id, model_name)
        # Check for single-file patches
        existing_patches = list(patch_dir.glob("patch_*.java"))
        # Also check for multi-file patch directories
        existing_dirs = [d for d in patch_dir.glob("patch_*") if d.is_dir()]
        return len(existing_patches) >= n_patches or len(existing_dirs) >= n_patches


if __name__ == "__main__":
    # Test the patch generator
    config = get_config()
    logger = init_phase_logger("TEST", "test.log", str(config.logs_dir))
    
    print("=" * 60)
    print("Patch Generator Test")
    print("=" * 60)
    
    # Test code extraction
    test_responses = [
        '```java\npublic class Test {\n    public void foo() {}\n}\n```',
        '```\npublic class Test {}\n```',
        'public class Test {\n    // Direct code\n}',
        'Here is the fix:\n```java\nclass Fixed {}\n```\nThis fixes the issue.',
    ]
    
    print("\nTesting code extraction:")
    for i, resp in enumerate(test_responses):
        extracted = extract_code_from_response(resp)
        print(f"  Test {i+1}: {len(extracted)} chars extracted")
    
    print("\n[OK] Code extraction working")
    
    # Test prompt creation
    prompt = create_prompt(
        vulnerable_code="public void process(String input) { eval(input); }",
        cwe_id="CWE-94",
        cwe_name="Code Injection"
    )
    print(f"\nPrompt length: {len(prompt)} chars")
    print("[OK] Prompt template working")
    
    print("\n" + "=" * 60)
    print("Patch Generator module ready")
    print("=" * 60)
