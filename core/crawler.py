"""
Web crawler module for discovering URLs to test
"""

import requests
from urllib.parse import urlparse, urljoin
import re
import time
from bs4 import BeautifulSoup
import tldextract
import validators

from utils.logger import get_logger


class WebCrawler:
    """
    Web crawler for discovering URLs on a target website
    """

    def __init__(self, depth=2, exclude_pattern=None, timeout=10, delay=0.1,
                 user_agent=None, cookies=None, headers=None, basic_auth=None,
                 proxy=None, proxy_auth=None):
        """
        Initialize the web crawler.

        Args:
            depth (int): Maximum crawling depth
            exclude_pattern (str): Regex pattern to exclude URLs
            timeout (int): Request timeout in seconds
            delay (float): Delay between requests in seconds
            user_agent (str): Custom User-Agent string
            cookies (str): Cookies to include with HTTP requests
            headers (str): Additional HTTP headers
            basic_auth (str): Basic authentication credentials (username:password)
            proxy (str): Proxy URL (format: "http://host:port")
            proxy_auth (str): Proxy authentication credentials (username:password)
        """
        self.logger = get_logger()
        self.depth = depth
        self.exclude_pattern = re.compile(
            exclude_pattern) if exclude_pattern else None
        self.timeout = timeout
        self.delay = delay

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

    def _is_same_domain(self, url, base_url):
        """
        Check if a URL belongs to the same domain as the base URL.

        Args:
            url (str): URL to check
            base_url (str): Base URL to compare against

        Returns:
            bool: True if the URLs belong to the same domain, False otherwise
        """
        url_domain = tldextract.extract(url)
        base_domain = tldextract.extract(base_url)

        return (url_domain.domain == base_domain.domain and
                url_domain.suffix == base_domain.suffix)

    def _normalize_url(self, url):
        """
        Normalize a URL by removing fragments and trailing slashes.

        Args:
            url (str): URL to normalize

        Returns:
            str: Normalized URL
        """
        # Remove fragment
        url = url.split('#')[0]

        # Remove trailing slash
        if url.endswith('/'):
            url = url[:-1]

        return url

    def _should_crawl(self, url):
        """
        Check if a URL should be crawled.

        Args:
            url (str): URL to check

        Returns:
            bool: True if the URL should be crawled, False otherwise
        """
        # Skip URLs with common non-HTML extensions
        skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf',
                           '.doc', '.xls', '.zip', '.tar', '.gz', '.css', '.js']

        for ext in skip_extensions:
            if url.lower().endswith(ext):
                return False

        # Skip URLs matching the exclude pattern
        if self.exclude_pattern and self.exclude_pattern.search(url):
            return False

        return True

    def _extract_urls(self, base_url, html_content):
        """
        Extract URLs from HTML content.

        Args:
            base_url (str): Base URL for resolving relative URLs
            html_content (str): HTML content to parse

        Returns:
            list: List of extracted URLs
        """
        urls = []

        try:
            soup = BeautifulSoup(html_content, 'html.parser')

            # Extract URLs from <a> tags
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']

                # Skip empty or javascript: links
                if not href or href.startswith('javascript:'):
                    continue

                # Resolve relative URLs
                full_url = urljoin(base_url, href)

                # Skip invalid URLs
                if not validators.url(full_url):
                    continue

                # Normalize the URL
                normalized_url = self._normalize_url(full_url)

                # Check if the URL should be crawled
                if self._should_crawl(normalized_url):
                    urls.append(normalized_url)

            # Extract URLs from <form> tags
            for form_tag in soup.find_all('form', action=True):
                action = form_tag['action']

                # Skip empty actions
                if not action:
                    continue

                # Resolve relative URLs
                full_url = urljoin(base_url, action)

                # Skip invalid URLs
                if not validators.url(full_url):
                    continue

                # Normalize the URL
                normalized_url = self._normalize_url(full_url)

                # Check if the URL should be crawled
                if self._should_crawl(normalized_url):
                    urls.append(normalized_url)

        except Exception as e:
            self.logger.debug(f"Error extracting URLs from page: {str(e)}")

        return urls

    def crawl(self, start_url):
        """
        Crawl a website starting from the given URL.

        Args:
            start_url (str): Starting URL for crawling

        Returns:
            list: List of discovered URLs
        """
        self.logger.info(f"Starting crawl from: {start_url}")

        parsed_start_url = urlparse(start_url)
        base_domain = f"{parsed_start_url.scheme}://{parsed_start_url.netloc}"

        # URLs to crawl
        queue = [(start_url, 0)]  # (url, depth)

        # URLs that have been crawled
        crawled = set()

        # URLs that have been discovered
        discovered = [start_url]

        while queue:
            url, depth = queue.pop(0)

            # Skip if already crawled or depth limit exceeded
            if url in crawled or depth > self.depth:
                continue

            # Mark as crawled
            crawled.add(url)

            self.logger.debug(f"Crawling {url} (depth {depth})")

            try:
                # Apply delay
                if self.delay > 0:
                    time.sleep(self.delay)

                # Make the request
                response = requests.get(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    auth=self.auth,
                    proxies=self.proxies,
                    timeout=self.timeout,
                    verify=False  # Skip SSL verification
                )

                # Skip non-HTML responses
                content_type = response.headers.get('Content-Type', '')
                if not content_type.startswith('text/html'):
                    continue

                # Extract URLs from the page
                new_urls = self._extract_urls(url, response.text)

                for new_url in new_urls:
                    # Skip URLs that are not part of the same domain
                    if not self._is_same_domain(new_url, start_url):
                        continue

                    # Add to discovered URLs if not already discovered
                    if new_url not in discovered:
                        discovered.append(new_url)

                        # Add to queue for crawling
                        queue.append((new_url, depth + 1))

            except Exception as e:
                self.logger.debug(f"Error crawling {url}: {str(e)}")

        self.logger.info(
            f"Crawling completed. Discovered {len(discovered)} URLs")
        return discovered
