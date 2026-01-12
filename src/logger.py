"""
Experiment Logger Module

Provides structured logging with timestamp, level, and context tagging.
Outputs to both console and log files.
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from loguru import logger


class ExperimentLogger:
    """Logger for the vulnerability repair experiment."""
    
    LOG_FORMAT = "[{time:YYYY-MM-DD HH:mm:ss}] [{level}] [{extra[context]}] {message}"
    
    def __init__(self, log_dir: str = "logs", context: str = "MAIN"):
        """
        Initialize the experiment logger.
        
        Args:
            log_dir: Directory to store log files
            context: Current context tag for log messages
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.context = context
        
        # Remove default logger
        logger.remove()
        
        # Add console handler
        logger.add(
            sys.stdout,
            format=self.LOG_FORMAT,
            level="DEBUG",
            colorize=True
        )
        
        # Configure with context
        self._logger = logger.bind(context=self.context)
    
    def set_context(self, context: str):
        """Update the current context."""
        self.context = context
        self._logger = logger.bind(context=self.context)
    
    def add_file_handler(self, filename: str):
        """
        Add a file handler for logging to a specific file.
        
        Args:
            filename: Name of the log file (will be created in log_dir)
        """
        log_path = self.log_dir / filename
        logger.add(
            str(log_path),
            format=self.LOG_FORMAT,
            level="DEBUG",
            rotation="10 MB",
            retention="30 days"
        )
    
    def info(self, message: str):
        """Log an info message."""
        self._logger.info(message)
    
    def success(self, message: str):
        """Log a success message."""
        self._logger.success(message)
    
    def warning(self, message: str):
        """Log a warning message."""
        self._logger.warning(message)
    
    def error(self, message: str):
        """Log an error message."""
        self._logger.error(message)
    
    def debug(self, message: str):
        """Log a debug message."""
        self._logger.debug(message)
    
    def exception(self, message: str):
        """Log an exception with traceback."""
        self._logger.exception(message)


# Global logger instance
_experiment_logger: Optional[ExperimentLogger] = None


def get_logger(log_dir: str = "logs", context: str = "MAIN") -> ExperimentLogger:
    """
    Get or create the global experiment logger.
    
    Args:
        log_dir: Directory to store log files
        context: Current context tag
        
    Returns:
        ExperimentLogger instance
    """
    global _experiment_logger
    if _experiment_logger is None:
        _experiment_logger = ExperimentLogger(log_dir=log_dir, context=context)
    return _experiment_logger


def init_phase_logger(context: str, log_file: str, log_dir: str = "logs") -> ExperimentLogger:
    """
    Initialize a logger with a specific context.
    
    Args:
        context: Context tag for log messages
        log_file: Log file name
        log_dir: Directory to store log files
        
    Returns:
        Configured ExperimentLogger instance
    """
    exp_logger = get_logger(log_dir=log_dir, context=context)
    exp_logger.set_context(context)
    exp_logger.add_file_handler(log_file)
    return exp_logger


if __name__ == "__main__":
    # Test the logger
    test_logger = init_phase_logger("TEST", "test.log", "logs")
    
    test_logger.info("Starting logger test...")
    test_logger.success("Logger initialized successfully")
    test_logger.warning("This is a warning message")
    test_logger.error("This is an error message")
    test_logger.debug("This is a debug message")
    
    test_logger.set_context("TEST2")
    test_logger.info("Context changed")
    
    print("\nLogger test complete. Check logs/test.log for output.")
