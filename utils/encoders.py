"""
Encoder module for encoding payloads
"""

import urllib.parse
import html
import base64
import random
import string


def encode_payload(payload, encoding=None):
    """
    Encode a payload using the specified encoding.

    Args:
        payload (str): Payload to encode
        encoding (str): Encoding to use (None for no encoding)

    Returns:
        str: Encoded payload
    """
    if encoding is None:
        return payload

    if encoding == 'url':
        return urllib.parse.quote(payload)

    if encoding == 'double_url':
        return urllib.parse.quote(urllib.parse.quote(payload))

    if encoding == 'html':
        return html.escape(payload)

    if encoding == 'base64':
        return base64.b64encode(payload.encode()).decode()

    if encoding == 'hex':
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

    if encoding == 'unicode':
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    if encoding == 'octal':
        return ''.join(f'\\{ord(c):03o}' for c in payload)

    if encoding == 'random':
        encodings = ['url', 'double_url', 'html',
                     'base64', 'hex', 'unicode', 'octal']
        return encode_payload(payload, random.choice(encodings))

    return payload


def random_string(length=10):
    """
    Generate a random string.

    Args:
        length (int): Length of the string

    Returns:
        str: Random string
    """
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
