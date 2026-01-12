"""
OpenRouter API Client

Handles all communication with the OpenRouter API for LLM patch generation.
Includes rate limiting, retries, and comprehensive logging.
"""

import time
import json
import httpx
from typing import Optional, Dict, Any
from dataclasses import dataclass
from pathlib import Path

from config import get_config, ModelConfig
from logger import init_phase_logger


@dataclass
class APIResponse:
    """Structured response from the API."""
    success: bool
    content: Optional[str] = None
    error: Optional[str] = None
    model: Optional[str] = None
    usage: Optional[Dict[str, int]] = None
    latency_ms: Optional[float] = None


class OpenRouterClient:
    """
    Client for OpenRouter API with rate limiting, retries, and logging.
    """
    
    def __init__(self, logger=None):
        """Initialize the OpenRouter client."""
        self.config = get_config()
        self.api_key = self.config.openrouter_api_key
        self.base_url = self.config.openrouter_base_url
        self.rate_limit_delay = self.config.rate_limit_delay
        self.logger = logger or init_phase_logger("API", "api.log", str(self.config.logs_dir))
        
        self._last_request_time = 0
        self._total_requests = 0
        self._total_tokens = 0
        
        if not self.api_key:
            self.logger.warning("OpenRouter API key not set. Please set OPENROUTER_API_KEY in .env file.")
    
    def _wait_for_rate_limit(self):
        """Ensure we don't exceed rate limits."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - elapsed
            time.sleep(sleep_time)
        self._last_request_time = time.time()
    
    def generate(
        self,
        model: ModelConfig,
        prompt: str,
        max_retries: int = 1,
        timeout: float = 600.0  # 10 minutes for large files
    ) -> APIResponse:
        """
        Generate a response from the specified model.
        
        Args:
            model: ModelConfig with model details
            prompt: The prompt to send
            max_retries: Number of retries on failure
            timeout: Request timeout in seconds
            
        Returns:
            APIResponse with success status and content or error
        """
        if not self.api_key:
            return APIResponse(
                success=False,
                error="API key not configured. Set OPENROUTER_API_KEY in .env file."
            )
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://research.university.edu",
            "X-Title": "LLM Vulnerability Repair Research"
        }
        
        payload = {
            "model": model.openrouter_id,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": model.temperature,
            "max_tokens": model.max_tokens
        }
        
        for attempt in range(max_retries):
            try:
                self._wait_for_rate_limit()
                
                start_time = time.time()
                
                with httpx.Client(timeout=timeout) as client:
                    response = client.post(
                        f"{self.base_url}/chat/completions",
                        headers=headers,
                        json=payload
                    )
                
                latency_ms = (time.time() - start_time) * 1000
                
                if response.status_code == 200:
                    data = response.json()
                    content = data["choices"][0]["message"]["content"]
                    usage = data.get("usage", {})
                    
                    self._total_requests += 1
                    self._total_tokens += usage.get("total_tokens", 0)
                    
                    self.logger.debug(f"API call successful: {model.name}, {usage.get('total_tokens', 0)} tokens, {latency_ms:.0f}ms")
                    
                    return APIResponse(
                        success=True,
                        content=content,
                        model=model.name,
                        usage=usage,
                        latency_ms=latency_ms
                    )
                
                elif response.status_code == 429:
                    # Rate limited - wait and retry
                    wait_time = (attempt + 1) * 5
                    self.logger.warning(f"Rate limited. Waiting {wait_time}s before retry {attempt + 1}/{max_retries}")
                    time.sleep(wait_time)
                    continue
                
                elif response.status_code >= 500:
                    # Server error - retry
                    wait_time = (attempt + 1) * 2
                    self.logger.warning(f"Server error {response.status_code}. Retry {attempt + 1}/{max_retries}")
                    time.sleep(wait_time)
                    continue
                
                else:
                    # Client error - don't retry
                    error_msg = f"API error {response.status_code}: {response.text[:200]}"
                    self.logger.error(error_msg)
                    return APIResponse(success=False, error=error_msg)
                    
            except httpx.TimeoutException:
                wait_time = min(2 ** attempt * 5, 60)
                self.logger.warning(f"Request timeout. Retry {attempt + 1}/{max_retries} in {wait_time}s")
                time.sleep(wait_time)
                continue
                
            except Exception as e:
                # Exponential backoff for connection errors
                wait_time = min(2 ** attempt * 5, 60)  # 5s, 10s, 20s, 40s, 60s
                self.logger.warning(f"Request exception: {e}. Retry {attempt + 1}/{max_retries} in {wait_time}s")
                if attempt == max_retries - 1:
                    return APIResponse(success=False, error=str(e))
                time.sleep(wait_time)
                continue
        
        return APIResponse(success=False, error=f"Failed after {max_retries} retries")
    
    def test_connection(self, model: ModelConfig) -> bool:
        """
        Test the API connection with a simple prompt.
        
        Args:
            model: Model to test with
            
        Returns:
            True if connection successful, False otherwise
        """
        test_prompt = "Reply with only the word 'OK' to confirm you received this message."
        
        self.logger.info(f"Testing connection with {model.name}...")
        
        response = self.generate(model, test_prompt, max_retries=2, timeout=30.0)
        
        if response.success:
            self.logger.success(f"Connection test passed for {model.name}")
            return True
        else:
            self.logger.error(f"Connection test failed for {model.name}: {response.error}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics."""
        return {
            "total_requests": self._total_requests,
            "total_tokens": self._total_tokens,
            "estimated_cost_usd": self._total_tokens * 0.00001  # Rough estimate
        }


def test_openrouter_client():
    """Test the OpenRouter client."""
    config = get_config()
    logger = init_phase_logger("TEST", "test.log", str(config.logs_dir))
    
    client = OpenRouterClient(logger)
    
    print("=" * 60)
    print("OpenRouter Client Test")
    print("=" * 60)
    
    # Check API key
    if not client.api_key:
        print("\n[ERROR] API key not set!")
        print("Please create a .env file with your OpenRouter API key:")
        print("  1. Copy .env.template to .env")
        print("  2. Replace 'your_key_here' with your actual API key")
        print("  3. Get your key from: https://openrouter.ai/keys")
        return False
    
    print(f"\n[OK] API key configured (length: {len(client.api_key)})")
    
    # Test each model
    all_passed = True
    for model in config.models:
        print(f"\nTesting {model.name} ({model.openrouter_id})...")
        
        if client.test_connection(model):
            print(f"  [PASS] {model.name}")
        else:
            print(f"  [FAIL] {model.name}")
            all_passed = False
    
    # Print stats
    stats = client.get_stats()
    print(f"\nStats: {stats['total_requests']} requests, {stats['total_tokens']} tokens")
    
    print("\n" + "=" * 60)
    if all_passed:
        print("[SUCCESS] All tests passed!")
    else:
        print("[WARNING] Some tests failed. Check your API key and model access.")
    print("=" * 60)
    
    return all_passed


if __name__ == "__main__":
    test_openrouter_client()
