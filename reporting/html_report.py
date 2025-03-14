"""
HTML report generator module
"""

import html


def generate_html_report(vulnerabilities, timestamp):
    """
    Generate an HTML report.

    Args:
        vulnerabilities (list): List of detected vulnerabilities
        timestamp (str): Report timestamp

    Returns:
        str: HTML report content
    """
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Hunter Pro - Vulnerability Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background-color: #3498db;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }}
        .vulnerability {{
            background-color: #f9f9f9;
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 0 5px 5px 0;
        }}
        .vulnerability h3 {{
            margin-top: 0;
            color: #e74c3c;
        }}
        .details {{
            display: grid;
            grid-template-columns: 150px auto;
            gap: 10px;
        }}
        .label {{
            font-weight: bold;
        }}
        .evidence {{
            background-color: #f1f1f1;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            margin-top: 10px;
        }}
        .highlight {{
            background-color: #ffeb3b;
            padding: 2px;
        }}
        .summary {{
            background-color: #2ecc71;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XSS Hunter Pro - Vulnerability Report</h1>
            <p>Generated: {timestamp}</p>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <p>Total vulnerabilities found: {len(vulnerabilities)}</p>
        </div>
        
        <h2>Vulnerabilities</h2>
"""

    for i, vuln in enumerate(vulnerabilities, 1):
        url = html.escape(vuln.get('url', 'N/A'))
        vuln_type = html.escape(vuln.get('type', 'N/A'))
        method = html.escape(vuln.get('method', 'N/A'))
        parameter = html.escape(vuln.get('parameter', 'N/A'))
        payload = html.escape(vuln.get('payload', 'N/A'))
        encoded_payload = html.escape(
            vuln.get('encoded_payload', 'N/A')) if 'encoded_payload' in vuln else None
        evidence = vuln.get('evidence', 'N/A')

        # Highlight the payload in the evidence
        if payload in evidence:
            evidence = evidence.replace(
                payload, f'<span class="highlight">{html.escape(payload)}</span>')

        html_content += f"""
        <div class="vulnerability">
            <h3>Vulnerability #{i}</h3>
            <div class="details">
                <div class="label">URL:</div>
                <div>{url}</div>
                
                <div class="label">Type:</div>
                <div>{vuln_type}</div>
                
                <div class="label">Method:</div>
                <div>{method}</div>
                
                <div class="label">Parameter:</div>
                <div>{parameter}</div>
                
                <div class="label">Payload:</div>
                <div>{payload}</div>
"""

        if encoded_payload:
            html_content += f"""
                <div class="label">Encoded Payload:</div>
                <div>{encoded_payload}</div>
"""

        html_content += f"""
                <div class="label">Evidence:</div>
                <div class="evidence">{evidence}</div>
            </div>
        </div>
"""

    html_content += """
    </div>
</body>
</html>
"""

    return html_content
