"""
Report generator module
"""

import os
import json
from datetime import datetime

from reporting.html_report import generate_html_report
from utils.logger import get_logger


class ReportGenerator:
    """
    Report generator for generating vulnerability reports
    """

    def __init__(self, vulnerabilities):
        """
        Initialize the report generator.

        Args:
            vulnerabilities (list): List of detected vulnerabilities
        """
        self.logger = get_logger()
        self.vulnerabilities = vulnerabilities
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def generate_report(self, output_file, format='txt'):
        """
        Generate a report.

        Args:
            output_file (str): Output file path
            format (str): Report format ('txt', 'json', or 'html')

        Returns:
            bool: True if the report was generated successfully, False otherwise
        """
        try:
            if format == 'txt':
                return self._generate_txt_report(output_file)
            elif format == 'json':
                return self._generate_json_report(output_file)
            elif format == 'html':
                return self._generate_html_report(output_file)
            else:
                self.logger.error(f"Unsupported report format: {format}")
                return False
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            return False

    def _generate_txt_report(self, output_file):
        """
        Generate a text report.

        Args:
            output_file (str): Output file path

        Returns:
            bool: True if the report was generated successfully, False otherwise
        """
        try:
            with open(output_file, 'w') as f:
                f.write(f"XSS Hunter Pro - Vulnerability Report\n")
                f.write(f"Generated: {self.timestamp}\n")
                f.write(
                    f"Total vulnerabilities found: {len(self.vulnerabilities)}\n\n")

                for i, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"Vulnerability #{i}\n")
                    f.write(f"URL: {vuln.get('url', 'N/A')}\n")
                    f.write(f"Type: {vuln.get('type', 'N/A')}\n")
                    f.write(f"Method: {vuln.get('method', 'N/A')}\n")
                    f.write(f"Parameter: {vuln.get('parameter', 'N/A')}\n")
                    f.write(f"Payload: {vuln.get('payload', 'N/A')}\n")

                    if 'encoded_payload' in vuln:
                        f.write(
                            f"Encoded Payload: {vuln['encoded_payload']}\n")

                    if 'evidence' in vuln:
                        f.write(f"Evidence: {vuln['evidence']}\n")

                    f.write("\n")

            self.logger.info(f"Text report generated: {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error generating text report: {str(e)}")
            return False

    def _generate_json_report(self, output_file):
        """
        Generate a JSON report.

        Args:
            output_file (str): Output file path

        Returns:
            bool: True if the report was generated successfully, False otherwise
        """
        try:
            report = {
                'timestamp': self.timestamp,
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities
            }

            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)

            self.logger.info(f"JSON report generated: {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Error generating JSON report: {str(e)}")
            return False

    def _generate_html_report(self, output_file):
        """
        Generate an HTML report.

        Args:
            output_file (str): Output file path

        Returns:
            bool: True if the report was generated successfully, False otherwise
        """
        try:
            html_content = generate_html_report(
                self.vulnerabilities, self.timestamp)

            with open(output_file, 'w') as f:
                f.write(html_content)

            self.logger.info(f"HTML report generated: {output_file}")
            return True

        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            return False
