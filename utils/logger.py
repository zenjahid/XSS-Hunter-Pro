"""
Logger module
"""

import logging
import sys
import os
from datetime import datetime

# Global logger instance
_logger = None


def setup_logger(level="INFO"):
    """
    Set up the logger.

    Args:
        level (str): Logging level
    """
    global _logger

    if _logger is not None:
        return _logger

    # Create logger
    _logger = logging.getLogger("xss_hunter")
    _logger.setLevel(getattr(logging, level))

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level))

    # Create formatter
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    console_handler.setFormatter(formatter)

    # Add handler to logger
    _logger.addHandler(console_handler)

    # Create logs directory if it doesn't exist
    logs_dir = os.path.join(os.getcwd(), 'logs')
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)

    # Create file handler
    log_file = os.path.join(
        logs_dir, f"xss_hunter_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(getattr(logging, level))
    file_handler.setFormatter(formatter)

    # Add handler to logger
    _logger.addHandler(file_handler)

    return _logger


def get_logger():
    """
    Get the logger instance.

    Returns:
        Logger: Logger instance
    """
    global _logger

    if _logger is None:
        _logger = setup_logger()

    return _logger
