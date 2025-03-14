"""
Validator module for validating inputs
"""

import re
import validators


def validate_url(url):
    """
    Validate a URL.

    Args:
        url (str): URL to validate

    Returns:
        bool: True if the URL is valid, False otherwise
    """
    return validators.url(url)


def validate_ip(ip):
    """
    Validate an IP address.

    Args:
        ip (str): IP address to validate

    Returns:
        bool: True if the IP address is valid, False otherwise
    """
    return validators.ipv4(ip) or validators.ipv6(ip)


def validate_email(email):
    """
    Validate an email address.

    Args:
        email (str): Email address to validate

    Returns:
        bool: True if the email address is valid, False otherwise
    """
    return validators.email(email)


def validate_domain(domain):
    """
    Validate a domain name.

    Args:
        domain (str): Domain name to validate

    Returns:
        bool: True if the domain name is valid, False otherwise
    """
    return validators.domain(domain)


def validate_regex(pattern):
    """
    Validate a regular expression.

    Args:
        pattern (str): Regular expression to validate

    Returns:
        bool: True if the regular expression is valid, False otherwise
    """
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False
