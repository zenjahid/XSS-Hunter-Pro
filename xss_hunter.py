#!/usr/bin/env python3
"""
XSS Hunter Pro - Advanced XSS Vulnerability Testing Framework
"""

import argparse
import sys
import os
import time
from datetime import datetime

from core.scanner import XSSScanner
from core.crawler import WebCrawler
from utils.config_handler import ConfigHandler
from utils.logger import setup_logger, get_logger
from utils.validator import validate_url
from reporting.report_generator import ReportGenerator


def banner():
    """Display the tool banner"""
    banner_text = """
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║  ██╗  ██╗███████╗███████╗    ██╗  ██╗██╗   ██╗███╗   ║
    ║  ╚██╗██╔╝██╔════╝██╔════╝    ██║  ██║██║   ██║████╗  ║
    ║   ╚███╔╝ ███████╗███████╗    ███████║██║   ██║██╔██╗ ║
    ║   ██╔██╗ ╚════██║╚════██║    ██╔══██║██║   ██║██║╚██╗║
    ║  ██╔╝ ██╗███████║███████║    ██║  ██║╚██████╔╝██║ ╚██║
    ║  ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
    ║                                                       ║
    ║              XSS Hunter Pro v1.0.0                   ║
    ║       Advanced XSS Vulnerability Testing Tool        ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(banner_text)
    print(f"  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  Use responsibly and only on systems you have permission to test.\n")


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='XSS Hunter Pro - Advanced XSS Vulnerability Testing Framework')

    # Target options
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('-u', '--url', help='Target URL to scan')
    target_group.add_argument(
        '-l', '--list', help='File containing list of URLs to scan')
    target_group.add_argument(
        '-c', '--crawl', action='store_true', help='Crawl the target website for testing')
    target_group.add_argument(
        '--depth', type=int, default=2, help='Crawling depth (default: 2)')
    target_group.add_argument(
        '--exclude', help='Regex pattern to exclude URLs from crawling')

    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('-m', '--method', choices=['get', 'post', 'all'], default='all',
                            help='HTTP method to use (default: all)')
    scan_group.add_argument('--dom', action='store_true',
                            help='Enable DOM XSS detection')
    scan_group.add_argument('--stored', action='store_true',
                            help='Attempt to detect stored XSS')
    scan_group.add_argument('--blind', action='store_true',
                            help='Include blind XSS payloads')
    scan_group.add_argument('--waf', action='store_true',
                            help='Enable WAF bypass techniques')
    scan_group.add_argument(
        '--polyglot', action='store_true', help='Use polyglot XSS payloads')
    scan_group.add_argument('--timeout', type=int, default=10,
                            help='Request timeout in seconds (default: 10)')
    scan_group.add_argument('--delay', type=float, default=0.1,
                            help='Delay between requests in seconds (default: 0.1)')
    scan_group.add_argument('--user-agent', help='Custom User-Agent string')
    scan_group.add_argument('--threads', type=int, default=5,
                            help='Number of concurrent threads (default: 5)')

    # Authentication options
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument(
        '--cookie', help='Cookies to include with HTTP requests')
    auth_group.add_argument(
        '--headers', help='Additional HTTP headers (format: "Header1: value1; Header2: value2")')
    auth_group.add_argument(
        '--auth-basic', help='Basic authentication credentials (username:password)')
    auth_group.add_argument(
        '--auth-form', action='store_true', help='Use form-based authentication')
    auth_group.add_argument('--auth-url', help='Authentication URL')
    auth_group.add_argument(
        '--auth-data', help='Authentication POST data (format: "key1=value1&key2=value2")')

    # Proxy options
    proxy_group = parser.add_argument_group('Proxy')
    proxy_group.add_argument(
        '--proxy', help='Use proxy (format: "http://host:port")')
    proxy_group.add_argument(
        '--proxy-auth', help='Proxy authentication credentials (username:password)')

    # Output options
    output_group = parser.add_argument_group('Output')
    output_group.add_argument(
        '-o', '--output', help='Base filename for output reports')
    output_group.add_argument('--format', choices=['txt', 'json', 'html', 'all'], default='all',
                              help='Output report format (default: all)')
    output_group.add_argument(
        '-v', '--verbose', action='store_true', help='Enable verbose output')
    output_group.add_argument('-q', '--quiet', action='store_true',
                              help='Suppress banner and non-essential output')

    # Misc options
    misc_group = parser.add_argument_group('Miscellaneous')
    misc_group.add_argument('--config', help='Path to configuration file')
    misc_group.add_argument(
        '--update-payloads', action='store_true', help='Update payload database')

    return parser.parse_args()


def main():
    """Main function"""
    args = parse_arguments()

    if not args.quiet:
        banner()

    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    if args.quiet:
        log_level = "ERROR"
    setup_logger(log_level)
    logger = get_logger()

    # Load configuration
    config = ConfigHandler(args.config)

    # Validate inputs
    if not args.url and not args.list:
        logger.error(
            "No target specified. Use -u/--url or -l/--list to specify targets.")
        sys.exit(1)

    # Process targets
    targets = []
    if args.url:
        if validate_url(args.url):
            targets.append(args.url)
        else:
            logger.error(f"Invalid URL: {args.url}")
            sys.exit(1)

    if args.list:
        try:
            with open(args.list, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and validate_url(url):
                        targets.append(url)
        except Exception as e:
            logger.error(f"Error reading URL list: {str(e)}")
            sys.exit(1)

    if not targets:
        logger.error("No valid targets found.")
        sys.exit(1)

    logger.info(f"Loaded {len(targets)} target(s) for scanning")

    # Initialize scanner
    scanner = XSSScanner(
        methods=args.method,
        use_dom=args.dom,
        test_stored=args.stored,
        include_blind=args.blind,
        waf_bypass=args.waf,
        use_polyglot=args.polyglot,
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent,
        threads=args.threads,
        cookies=args.cookie,
        headers=args.headers,
        basic_auth=args.auth_basic,
        proxy=args.proxy,
        proxy_auth=args.proxy_auth,
        config=config
    )

    # Initialize crawler if needed
    if args.crawl:
        crawler = WebCrawler(
            depth=args.depth,
            exclude_pattern=args.exclude,
            timeout=args.timeout,
            delay=args.delay,
            user_agent=args.user_agent,
            cookies=args.cookie,
            headers=args.headers,
            basic_auth=args.auth_basic,
            proxy=args.proxy,
            proxy_auth=args.proxy_auth
        )

    # Process form authentication if needed
    if args.auth_form:
        if not args.auth_url or not args.auth_data:
            logger.error(
                "Form authentication requires --auth-url and --auth-data")
            sys.exit(1)

        if not scanner.authenticate(args.auth_url, args.auth_data):
            logger.error("Authentication failed")
            sys.exit(1)

        logger.info("Authentication successful")

    # Process targets
    start_time = time.time()
    all_vulnerabilities = []

    for target in targets:
        logger.info(f"Scanning target: {target}")

        # Crawl if requested
        if args.crawl:
            logger.info(f"Crawling target: {target}")
            crawled_urls = crawler.crawl(target)
            logger.info(f"Found {len(crawled_urls)} URLs during crawling")
            scan_targets = crawled_urls
        else:
            scan_targets = [target]

        # Scan all targets
        for url in scan_targets:
            vulnerabilities = scanner.scan_target(url)
            if vulnerabilities:
                all_vulnerabilities.extend(vulnerabilities)
                logger.info(
                    f"Found {len(vulnerabilities)} potential XSS vulnerabilities in {url}")

    # Generate report
    if all_vulnerabilities:
        logger.info(f"Total vulnerabilities found: {len(all_vulnerabilities)}")

        if args.output:
            report_generator = ReportGenerator(all_vulnerabilities)
            output_formats = args.format.split(',') if args.format != 'all' else [
                'txt', 'json', 'html']

            for fmt in output_formats:
                output_file = f"{args.output}.{fmt}"
                report_generator.generate_report(output_file, fmt)
                logger.info(f"Report saved to {output_file}")
    else:
        logger.info("No XSS vulnerabilities found")

    # Print summary
    duration = time.time() - start_time
    logger.info(f"Scan completed in {duration:.2f} seconds")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)
