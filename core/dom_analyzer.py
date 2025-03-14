"""
DOM analyzer module for detecting DOM-based XSS vulnerabilities
"""

import re
from urllib.parse import urlparse, urljoin

from utils.logger import get_logger


class DOMAnalyzer:
    """
    DOM analyzer for detecting DOM-based XSS vulnerabilities
    """

    def __init__(self):
        """Initialize the DOM analyzer"""
        self.logger = get_logger()

        # Define patterns for DOM XSS sinks
        self.dom_sinks = [
            # innerHTML and similar
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'\.insertAdjacentHTML\s*\(',
            r'\.write\s*\(',
            r'\.writeln\s*\(',

            # Document methods
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',

            # jQuery methods
            r'\$\([^)]*\)\.html\s*\(',
            r'\$\([^)]*\)\.append\s*\(',
            r'\$\([^)]*\)\.prepend\s*\(',
            r'\$\([^)]*\)\.after\s*\(',
            r'\$\([^)]*\)\.before\s*\(',

            # eval and similar
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'new\s+Function\s*\(',

            # Element creation
            r'document\.createElement\s*\(',

            # Location methods
            r'location\s*=',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
            r'location\.assign\s*\(',

            # Other dangerous functions
            r'\.setAttribute\s*\([\'"](?:src|href|data|action|formaction)[\'"]',
        ]

        # Define patterns for DOM XSS sources
        self.dom_sources = [
            # URL sources
            r'location',
            r'location\.href',
            r'location\.search',
            r'location\.hash',
            r'document\.URL',
            r'document\.documentURI',
            r'document\.referrer',

            # Cookie sources
            r'document\.cookie',

            # Storage sources
            r'localStorage',
            r'sessionStorage',

            # Message sources
            r'postMessage',
            r'onmessage',

            # Form sources
            r'\.value',
            r'\.innerHTML',
            r'\.outerHTML',
            r'\.textContent',
            r'\.innerText',

            # jQuery sources
            r'\$\([^)]*\)\.val\s*\(',
            r'\$\([^)]*\)\.text\s*\(',
            r'\$\([^)]*\)\.html\s*\(',
            r'\$\([^)]*\)\.attr\s*\(',
        ]

    def analyze(self, html_content, payload):
        """
        Analyze HTML content for DOM-based XSS vulnerabilities.

        Args:
            html_content (str): HTML content to analyze
            payload (str): XSS payload to check for

        Returns:
            tuple: (is_vulnerable, payload) if vulnerable, (False, None) otherwise
        """
        # Extract all script tags
        script_pattern = re.compile(
            r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
        scripts = script_pattern.findall(html_content)

        # Extract inline event handlers
        event_pattern = re.compile(
            r'on\w+\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
        events = event_pattern.findall(html_content)

        # Combine all JavaScript code
        js_code = '\n'.join(scripts + events)

        # Check for DOM sinks
        for sink_pattern in self.dom_sinks:
            sink_matches = re.findall(sink_pattern, js_code)

            if sink_matches:
                # Check for DOM sources
                for source_pattern in self.dom_sources:
                    source_matches = re.findall(source_pattern, js_code)

                    if source_matches:
                        # If both sink and source are found, the page might be vulnerable
                        self.logger.debug(
                            f"Potential DOM XSS: Source: {source_pattern}, Sink: {sink_pattern}")

                        # Check if the payload is reflected in the JavaScript code
                        if payload in js_code:
                            return True, payload

        return False, None

    def scan_page(self, url, html_content):
        """
        Scan a page for DOM-based XSS vulnerabilities.

        Args:
            url (str): URL of the page
            html_content (str): HTML content of the page

        Returns:
            list: List of detected vulnerabilities
        """
        vulnerabilities = []

        # Extract all script tags
        script_pattern = re.compile(
            r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
        scripts = script_pattern.findall(html_content)

        # Extract inline event handlers
        event_pattern = re.compile(
            r'on\w+\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
        events = event_pattern.findall(html_content)

        # Combine all JavaScript code
        js_code = '\n'.join(scripts + events)

        # Check for DOM sinks
        for sink_pattern in self.dom_sinks:
            sink_matches = re.findall(sink_pattern, js_code)

            if sink_matches:
                # Check for DOM sources
                for source_pattern in self.dom_sources:
                    source_matches = re.findall(source_pattern, js_code)

                    if source_matches:
                        # If both sink and source are found, the page might be vulnerable
                        vulnerability = {
                            'url': url,
                            'type': 'Potential DOM-based XSS',
                            'source': source_pattern,
                            'sink': sink_pattern,
                            'evidence': f"Source: {source_pattern}, Sink: {sink_pattern}"
                        }

                        vulnerabilities.append(vulnerability)

        return vulnerabilities
