"""
Core XSS scanner module for detecting XSS vulnerabilities
"""

import requests
import random
import re
import time
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from payloads.basic_payloads import BASIC_PAYLOADS
from payloads.advanced_payloads import ADVANCED_PAYLOADS
from payloads.dom_payloads import DOM_PAYLOADS
from payloads.waf_bypass_payloads import WAF_BYPASS_PAYLOADS
from payloads.polyglot_payloads import POLYGLOT_PAYLOADS
from core.dom_analyzer import DOMAnalyzer
from core.waf_detector import WAFDetector
from core.http_client import HTTPClient
from utils.logger import get_logger
from utils.encoders import encode_payload


class XSSScanner:
    """
    Advanced XSS vulnerability scanner with multiple detection techniques
    """

    def __init__(self,
                 methods='all',
                 use_dom=False,
                 test_stored=False,
                 include_blind=False,
                 waf_bypass=False,
                 use_polyglot=False,
                 timeout=10,
                 delay=0.1,
                 user_agent=None,
                 threads=5,
                 cookies=None,
                 headers=None,
                 basic_auth=None,
                 proxy=None,
                 proxy_auth=None,
                 config=None):
        """
        Initialize the XSS scanner with the specified configuration.

        Args:
            methods (str): HTTP methods to test ('get', 'post', or 'all')
            use_dom (bool): Enable DOM XSS detection
            test_stored (bool): Test for stored XSS vulnerabilities
            include_blind (bool): Include blind XSS payloads
            waf_bypass (bool): Enable WAF bypass techniques
            use_polyglot (bool): Use polyglot XSS payloads
            timeout (int): Request timeout in seconds
            delay (float): Delay between requests in seconds
            user_agent (str): Custom User-Agent string
            threads (int): Number of concurrent threads
            cookies (str): Cookies to include with HTTP requests
            headers (str): Additional HTTP headers
            basic_auth (str): Basic authentication credentials (username:password)
            proxy (str): Proxy URL (format: "http://host:port")
            proxy_auth (str): Proxy authentication credentials (username:password)
            config (ConfigHandler): Configuration handler object
        """
        self.logger = get_logger()
        self.methods = methods
        self.use_dom = use_dom
        self.test_stored = test_stored
        self.include_blind = include_blind
        self.waf_bypass = waf_bypass
        self.use_polyglot = use_polyglot
        self.timeout = timeout
        self.delay = delay
        self.threads = threads
        self.config = config

        # Initialize HTTP client
        self.http_client = HTTPClient(
            timeout=timeout,
            user_agent=user_agent,
            cookies=cookies,
            headers=headers,
            basic_auth=basic_auth,
            proxy=proxy,
            proxy_auth=proxy_auth
        )

        # Initialize WAF detector if WAF bypass is enabled
        if self.waf_bypass:
            self.waf_detector = WAFDetector(self.http_client)

        # Initialize payload list
        self.payloads = self._initialize_payloads()
        self.logger.info(f"Loaded {len(self.payloads)} XSS payloads")

        # Initialize DOM analyzer if DOM testing is enabled
        if self.use_dom:
            self.dom_analyzer = DOMAnalyzer()
            self.logger.info("DOM XSS detection enabled")

    def _initialize_payloads(self):
        """Initialize the list of payloads based on the configuration"""
        payloads = []

        # Always include basic payloads
        payloads.extend(BASIC_PAYLOADS)

        # Add advanced payloads
        payloads.extend(ADVANCED_PAYLOADS)

        # Add DOM-specific payloads if DOM testing is enabled
        if self.use_dom:
            payloads.extend(DOM_PAYLOADS)

        # Add WAF bypass payloads if WAF bypass is enabled
        if self.waf_bypass:
            payloads.extend(WAF_BYPASS_PAYLOADS)

        # Add polyglot payloads if polyglot testing is enabled
        if self.use_polyglot:
            payloads.extend(POLYGLOT_PAYLOADS)

        return payloads

    def authenticate(self, auth_url, auth_data):
        """
        Perform form-based authentication.

        Args:
            auth_url (str): Authentication URL
            auth_data (str): Authentication POST data

        Returns:
            bool: True if authentication was successful, False otherwise
        """
        try:
            response = self.http_client.post(auth_url, data=auth_data)
            if response.status_code in (200, 302):
                return True
            return False
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            return False

    def _extract_inputs(self, url, html_content):
        """
        Extract input parameters from URL and HTML content.

        Args:
            url (str): URL to analyze
            html_content (str): HTML content to analyze

        Returns:
            dict: Dictionary containing parameters and their values
        """
        params = {}

        # Extract parameters from URL query string
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        for param, values in query_params.items():
            params[param] = values[0]

        # Extract input fields from HTML forms
        form_field_pattern = re.compile(
            r'<input[^>]*name=[\'"]([^\'"]*)[\'"][^>]*>', re.IGNORECASE)
        for match in form_field_pattern.finditer(html_content):
            field_name = match.group(1)
            if field_name and field_name not in params:
                params[field_name] = ""

        return params

    def _modify_url_parameter(self, url, param, value):
        """
        Modify a parameter in the URL's query string.

        Args:
            url (str): Original URL
            param (str): Parameter name to modify
            value (str): New parameter value

        Returns:
            str: Modified URL
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Update or add the parameter
        query_params[param] = [value]

        # Convert the query parameters back to a string
        new_query = urlencode(query_params, doseq=True)

        # Construct the new URL
        new_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))

        return new_url

    def _test_parameter(self, url, param, value, method='GET'):
        """
        Test a parameter with a specific payload.

        Args:
            url (str): Target URL
            param (str): Parameter name
            value (str): Payload value
            method (str): HTTP method to use

        Returns:
            dict: Vulnerability details if found, None otherwise
        """
        try:
            # Apply delay if specified
            if self.delay > 0:
                time.sleep(self.delay)

            encoded_value = encode_payload(value)
            response = None

            if method.upper() == 'GET':
                test_url = self._modify_url_parameter(
                    url, param, encoded_value)
                response = self.http_client.get(test_url)
            else:
                data = {param: encoded_value}
                response = self.http_client.post(url, data=data)

            if not response:
                return None

            # Check if payload is reflected in the response
            is_vulnerable = False
            reflected_payload = None

            # Check for direct reflection
            if value in response.text or encoded_value in response.text:
                is_vulnerable = True
                reflected_payload = value

            # Check for DOM-based XSS if enabled
            if self.use_dom and not is_vulnerable:
                dom_vulnerable, dom_payload = self.dom_analyzer.analyze(
                    response.text, value)
                if dom_vulnerable:
                    is_vulnerable = True
                    reflected_payload = dom_payload

            if is_vulnerable:
                return {
                    'url': url,
                    'parameter': param,
                    'payload': reflected_payload,
                    'encoded_payload': encoded_value,
                    'method': method,
                    'type': 'DOM-based XSS' if self.use_dom else 'Reflected XSS',
                    'evidence': self._extract_evidence(response.text, reflected_payload)
                }

            return None

        except Exception as e:
            self.logger.debug(
                f"Error testing parameter {param} with payload {value}: {str(e)}")
            return None

    def _extract_evidence(self, content, payload):
        """
        Extract evidence of XSS vulnerability from the content.

        Args:
            content (str): HTML content
            payload (str): XSS payload

        Returns:
            str: Evidence snippet
        """
        try:
            # Find the position of the payload in the content
            pos = content.find(payload)
            if pos == -1:
                return "Payload not found directly in response"

            # Extract a snippet around the payload
            start = max(0, pos - 50)
            end = min(len(content), pos + len(payload) + 50)

            # Extract the snippet
            snippet = content[start:end]

            # Highlight the payload in the snippet
            highlighted = snippet.replace(payload, f"**{payload}**")

            return highlighted
        except Exception:
            return "Error extracting evidence"

    def _test_stored_xss(self, url, param, payload):
        """
        Test for stored XSS vulnerabilities.

        Args:
            url (str): Target URL
            param (str): Parameter name
            payload (str): XSS payload

        Returns:
            dict: Vulnerability details if found, None otherwise
        """
        try:
            # Submit the payload
            data = {param: payload}
            submit_response = self.http_client.post(url, data=data)

            if not submit_response or submit_response.status_code not in (200, 201, 302):
                return None

            # Wait a moment
            time.sleep(1)

            # Check if the payload is stored by retrieving the page again
            check_response = self.http_client.get(url)

            if not check_response:
                return None

            # Check if payload is present in the response
            if payload in check_response.text:
                return {
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'method': 'POST',
                    'type': 'Stored XSS',
                    'evidence': self._extract_evidence(check_response.text, payload)
                }

            return None

        except Exception as e:
            self.logger.debug(
                f"Error testing stored XSS for parameter {param}: {str(e)}")
            return None

    def scan_target(self, url):
        """
        Scan a target URL for XSS vulnerabilities.

        Args:
            url (str): Target URL

        Returns:
            list: List of detected vulnerabilities
        """
        self.logger.info(f"Scanning target: {url}")
        vulnerabilities = []

        try:
            # Check for WAF if WAF bypass is enabled
            if self.waf_bypass:
                waf_detected, waf_type = self.waf_detector.detect_waf(url)
                if waf_detected:
                    self.logger.info(f"WAF detected: {waf_type}")

            # Get the initial page to extract parameters
            response = self.http_client.get(url)
            if not response:
                self.logger.error(f"Failed to retrieve initial page: {url}")
                return vulnerabilities

            # Extract parameters from URL and HTML content
            params = self._extract_inputs(url, response.text)

            if not params:
                self.logger.info(f"No parameters found to test in {url}")

                # Still try some basic attacks even without parameters
                basic_payloads = self.payloads[:5]  # Use a subset of payloads

                for payload in basic_payloads:
                    test_url = f"{url}?xss={payload}"
                    test_response = self.http_client.get(test_url)

                    if test_response and payload in test_response.text:
                        vulnerabilities.append({
                            'url': test_url,
                            'parameter': 'xss',
                            'payload': payload,
                            'method': 'GET',
                            'type': 'Reflected XSS',
                            'evidence': self._extract_evidence(test_response.text, payload)
                        })

                return vulnerabilities

            self.logger.info(f"Found {len(params)} parameters to test")

            # Test each parameter with each payload
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []

                for param in params:
                    for payload in self.payloads:
                        # Test GET requests
                        if self.methods in ('get', 'all'):
                            futures.append(
                                executor.submit(
                                    self._test_parameter, url, param, payload, 'GET')
                            )

                        # Test POST requests
                        if self.methods in ('post', 'all'):
                            futures.append(
                                executor.submit(
                                    self._test_parameter, url, param, payload, 'POST')
                            )

                        # Test stored XSS if enabled
                        if self.test_stored:
                            futures.append(
                                executor.submit(
                                    self._test_stored_xss, url, param, payload)
                            )

                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                        self.logger.info(
                            f"Found XSS vulnerability: {result['type']} in {result['parameter']}")

            # Test for DOM XSS if enabled
            if self.use_dom:
                dom_vulnerabilities = self.dom_analyzer.scan_page(
                    url, response.text)
                if dom_vulnerabilities:
                    vulnerabilities.extend(dom_vulnerabilities)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error scanning target {url}: {str(e)}")
            return vulnerabilities
