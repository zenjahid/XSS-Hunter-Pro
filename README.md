# XSS Hunter Pro

![XSS Hunter Pro](https://img.shields.io/badge/XSS%20Hunter-Pro-blue)
![Python](https://img.shields.io/badge/Python-3.6%2B-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

XSS Hunter Pro is an advanced Cross-Site Scripting (XSS) vulnerability testing framework designed to help security professionals identify and validate XSS vulnerabilities in web applications.

## Features

- **Comprehensive XSS Detection**: Test for reflected, stored, and DOM-based XSS vulnerabilities
- **Advanced Payload Database**: Includes hundreds of XSS payloads categorized by type and purpose
- **WAF Bypass Techniques**: Automatically detect and bypass common Web Application Firewalls
- **Web Crawler**: Discover and test all accessible pages and parameters
- **Polyglot Payloads**: Use context-aware payloads that work in multiple contexts
- **Detailed Reporting**: Generate comprehensive reports in multiple formats (TXT, JSON, HTML)
- **Authentication Support**: Test authenticated pages with various authentication methods
- **Proxy Support**: Route requests through a proxy for anonymity or debugging
- **Concurrent Testing**: Multi-threaded scanning for faster results
- **Customizable Configuration**: Extensive configuration options via YAML file

## Installation

```bash
# Clone the repository
git clone https://github.com/zenjahid/xss-hunter-pro.git
cd xss-hunter-pro

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python xss_hunter.py -u https://example.com
```

### Scan with Crawling

```bash
python xss_hunter.py -u https://example.com -c --depth 3
```

### Scan Multiple URLs from a File

```bash
python xss_hunter.py -l urls.txt
```

### Enable Advanced Detection Methods

```bash
python xss_hunter.py -u https://example.com --dom --stored --waf --polyglot
```

### Use Authentication

```bash
python xss_hunter.py -u https://example.com --auth-form --auth-url https://example.com/login --auth-data "username=user&password=pass"
```

### Generate Reports

```bash
python xss_hunter.py -u https://example.com -o report --format all
```

### Use Proxy

```bash
python xss_hunter.py -u https://example.com --proxy http://127.0.0.1:8080
```

## Command Line Options

### Target Options

- `-u, --url`: Target URL to scan
- `-l, --list`: File containing list of URLs to scan
- `-c, --crawl`: Crawl the target website for testing
- `--depth`: Crawling depth (default: 2)
- `--exclude`: Regex pattern to exclude URLs from crawling

### Scan Options

- `-m, --method`: HTTP method to use (get, post, all)
- `--dom`: Enable DOM XSS detection
- `--stored`: Attempt to detect stored XSS
- `--blind`: Include blind XSS payloads
- `--waf`: Enable WAF bypass techniques
- `--polyglot`: Use polyglot XSS payloads
- `--timeout`: Request timeout in seconds
- `--delay`: Delay between requests in seconds
- `--user-agent`: Custom User-Agent string
- `--threads`: Number of concurrent threads

### Authentication Options

- `--cookie`: Cookies to include with HTTP requests
- `--headers`: Additional HTTP headers
- `--auth-basic`: Basic authentication credentials (username:password)
- `--auth-form`: Use form-based authentication
- `--auth-url`: Authentication URL
- `--auth-data`: Authentication POST data

### Proxy Options

- `--proxy`: Use proxy (format: "http://host:port")
- `--proxy-auth`: Proxy authentication credentials (username:password)

### Output Options

- `-o, --output`: Base filename for output reports
- `--format`: Output report format (txt, json, html, all)
- `-v, --verbose`: Enable verbose output
- `-q, --quiet`: Suppress banner and non-essential output

### Miscellaneous Options

- `--config`: Path to configuration file
- `--update-payloads`: Update payload database

## Configuration

You can customize XSS Hunter Pro by editing the `config.yaml` file. The configuration file allows you to set default values for various options, including:

- Scanner settings (timeout, delay, threads, etc.)
- Crawler settings (depth, exclude patterns)
- Reporting settings (output format)
- Proxy settings (URL, authentication)

## Disclaimer

This tool is intended for legal security testing with proper authorization. Unauthorized testing of web applications may violate laws and regulations. Always obtain proper permission before testing any system you don't own.

## License

MIT License

Copyright (c) 2023 zenjahid

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
