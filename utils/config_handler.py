"""
Configuration handler module
"""

import os
import yaml

from utils.logger import get_logger


class ConfigHandler:
    """
    Configuration handler for loading and managing configuration
    """

    def __init__(self, config_file=None):
        """
        Initialize the configuration handler.

        Args:
            config_file (str): Path to the configuration file
        """
        self.logger = get_logger()
        self.config = {}

        # Default configuration
        self.default_config = {
            'scanner': {
                'timeout': 10,
                'delay': 0.1,
                'threads': 5,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'methods': 'all',
                'use_dom': False,
                'test_stored': False,
                'include_blind': False,
                'waf_bypass': False,
                'use_polyglot': False
            },
            'crawler': {
                'depth': 2,
                'exclude_pattern': None
            },
            'reporting': {
                'output_format': 'all'
            },
            'proxy': {
                'url': None,
                'auth': None
            }
        }

        # Load configuration from file if provided
        if config_file:
            self._load_config(config_file)
        else:
            # Try to load from default locations
            default_locations = [
                'config.yaml',
                'config.yml',
                os.path.expanduser('~/.xss_hunter/config.yaml'),
                os.path.expanduser('~/.config/xss_hunter/config.yaml')
            ]

            for location in default_locations:
                if os.path.exists(location):
                    self._load_config(location)
                    break

            # If no configuration file is found, use default configuration
            if not self.config:
                self.logger.info(
                    "No configuration file found, using default configuration")
                self.config = self.default_config

    def _load_config(self, config_file):
        """
        Load configuration from a file.

        Args:
            config_file (str): Path to the configuration file
        """
        try:
            with open(config_file, 'r') as f:
                self.config = yaml.safe_load(f)

            self.logger.info(f"Loaded configuration from {config_file}")

            # Merge with default configuration for missing values
            for section, values in self.default_config.items():
                if section not in self.config:
                    self.config[section] = values
                else:
                    for key, value in values.items():
                        if key not in self.config[section]:
                            self.config[section][key] = value

        except Exception as e:
            self.logger.error(
                f"Error loading configuration from {config_file}: {str(e)}")
            self.config = self.default_config

    def get(self, section, key=None, default=None):
        """
        Get a configuration value.

        Args:
            section (str): Configuration section
            key (str): Configuration key
            default: Default value if the key is not found

        Returns:
            The configuration value or the default value if not found
        """
        if section not in self.config:
            return default

        if key is None:
            return self.config[section]

        if key not in self.config[section]:
            return default

        return self.config[section][key]
