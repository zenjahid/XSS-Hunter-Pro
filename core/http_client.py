"""
HTTP client module for making requests
"""

import requests
import urllib3
from requests.exceptions import RequestException

from utils.logger import get_logger

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPClient:
    """
    HTTP client for making requests with configurable options
    """

    def __init__(self, timeout=10, user_agent=None, cookies=None, headers=None,
                 basic_auth=None, proxy=None, proxy_auth=None):
        """
        Initialize the HTTP client.

        Args:
            timeout (int): Request timeout in seconds
            user_agent (str): Custom User-Agent string
            cookies (str): Cookies to include with HTTP requests
            headers (str): Additional HTTP headers
            basic_auth (str): Basic authentication credentials (username:password)
            proxy (str): Proxy URL (format: "http://host:port")
            proxy_auth (str): Proxy authentication credentials (username:password)
        """
        self.logger = get_logger()
        self.timeout = timeout

        # Set up headers
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        # Parse and add additional headers
        if headers:
            for header_line in headers.split(';'):
                if ':' in header_line:
                    key, value = header_line.split(':', 1)
                    self.headers[key.strip()] = value.strip()

        # Set up cookies
        self.cookies = {}
        if cookies:
            for cookie in cookies.split(';'):
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    self.cookies[key.strip()] = value.strip()

        # Set up authentication
        self.auth = None
        if basic_auth and ':' in basic_auth:
            username, password = basic_auth.split(':', 1)
            self.auth = (username, password)

        # Set up proxy
        self.proxies = None
        if proxy:
            self.proxies = {
                'http': proxy,
                'https': proxy
            }

            if proxy_auth and ':' in proxy_auth:
                proxy_username, proxy_password = proxy_auth.split(':', 1)
                proxy_with_auth = proxy.replace(
                    '://', f'://{proxy_username}:{proxy_password}@')
                self.proxies = {
                    'http': proxy_with_auth,
                    'https': proxy_with_auth
                }

        # Create a session
        self.session = requests.Session()

    def get(self, url, params=None):
        """
        Make a GET request.

        Args:
            url (str): URL to request
            params (dict): Query parameters

        Returns:
            Response: Response object or None if the request failed
        """
        try:
            response = self.session.get(
                url,
                params=params,
                headers=self.headers,
                cookies=self.cookies,
                auth=self.auth,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=False  # Skip SSL verification
            )
            return response
        except RequestException as e:
            self.logger.debug(f"GET request to {url} failed: {str(e)}")
            return None

    def post(self, url, data=None, json=None):
        """
        Make a POST request.

        Args:
            url (str): URL to request
            data (dict): Form data
            json (dict): JSON data

        Returns:
            Response: Response object or None if the request failed
        """
        try:
            response = self.session.post(
                url,
                data=data,
                json=json,
                headers=self.headers,
                cookies=self.cookies,
                auth=self.auth,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=False  # Skip SSL verification
            )
            return response
        except RequestException as e:
            self.logger.debug(f"POST request to {url} failed: {str(e)}")
            return None
