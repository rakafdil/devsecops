# VulnWeb - Intentionally Vulnerable Web Application

🎯 **VulnWeb** adalah aplikasi web yang sengaja dibuat vulnerable untuk keperluan edukasi dan pelatihan keamanan siber, khususnya dalam menerapkan metodologi **Cyber Kill Chain**.

## ⚠️ PERINGATAN

**Aplikasi ini sangat berbahaya dan hanya boleh digunakan untuk tujuan edukasi dalam lingkungan yang terkontrol. JANGAN deploy di sistem produksi atau jaringan publik!**

## 🚀 Quick Start

### Menjalankan dengan Docker

1. Clone atau download aplikasi ini
2. Pastikan Docker dan Docker Compose terinstall
3. Jalankan perintah berikut:

```bash
# Build dan jalankan aplikasi
docker-compose up -d

# Akses aplikasi di browser
http://localhost:8080
```

### Akun Testing

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Administrator |
| user1 | password123 | User |
| user2 | mypassword | User |
| moderator | mod123 | Moderator |

## 🎯 Vulnerabilities yang Tersedia

### 1. SQL Injection
- **Lokasi**: Login form, product search, orders page
- **Impact**: Authentication bypass, data extraction, privilege escalation
- **Testing**: `' OR '1'='1`, `' UNION SELECT ...`

### 2. Cross-Site Scripting (XSS)
- **Lokasi**: Comment system, profile updates
- **Impact**: Session hijacking, credential theft
- **Testing**: `<script>alert('XSS')</script>`, `<img src=x onerror=alert('XSS')>`

### 3. Broken Authentication
- **Vulnerabilities**: Weak passwords, predictable sessions, no account lockout
- **Impact**: Account takeover, unauthorized access
- **Testing**: Brute force, session prediction

### 4. Broken Access Control
- **Vulnerabilities**: IDOR, privilege escalation, missing authorization
- **Impact**: Unauthorized data access, privilege escalation
- **Testing**: URL manipulation, parameter tampering

## 📚 Cyber Kill Chain Implementation

### Phase 1: Reconnaissance
- Port scanning dan technology fingerprinting
- Directory enumeration
- Information gathering melalui debug mode (`?debug=1`)

### Phase 2: Weaponization
- Menyiapkan SQL injection payloads
- Membuat XSS payloads
- Menyiapkan privilege escalation exploits

### Phase 3: Delivery
- Injeksi melalui form login
- XSS melalui sistem komentar
- Parameter manipulation di URL

### Phase 4: Exploitation
- Eksekusi SQL injection
- Eksekusi XSS payload
- Authentication bypass
- IDOR exploitation

### Phase 5: Installation
- Membuat persistent XSS
- Injeksi admin accounts
- Session fixation

### Phase 6: Command & Control
- Akses admin panel
- Penggunaan SQL console
- User management

### Phase 7: Actions on Objectives
- Data exfiltration
- Account manipulation
- System compromise

## 🛠️ Struktur Aplikasi

```
vulnweb/
├── docker-compose.yml          # Docker orchestration
├── Dockerfile                  # Container definition
├── apache-config.conf          # Apache configuration
├── database/
│   └── init.sql               # Database initialization
└── src/
    ├── config.php             # Database & core functions
    ├── header.php             # Common header
    ├── footer.php             # Common footer
    ├── index.php              # Homepage
    ├── login.php              # Login system (SQL injection)
    ├── register.php           # Registration (privilege escalation)
    ├── products.php           # Product listing (SQL injection)
    ├── comments.php           # Comment system (XSS)
    ├── orders.php             # Order management (broken access control)
    ├── admin.php              # Admin panel (multiple vulnerabilities)
    ├── profile.php            # User profile
    ├── logout.php             # Logout functionality
    └── vulnerabilities.php    # Vulnerability guide
```

## 🔍 Testing Tools

### Recommended Tools:
- **Burp Suite**: Web application security testing
- **OWASP ZAP**: Automated vulnerability scanning
- **sqlmap**: Automated SQL injection testing
- **XSSHunter**: XSS testing platform
- **Nikto**: Web server scanner

### Manual Testing:
1. Akses `http://localhost:8080?debug=1` untuk debug mode
2. Test SQL injection di form login dan pencarian
3. Test XSS di sistem komentar
4. Test IDOR dengan mengubah parameter URL
5. Test privilege escalation saat registrasi

## 📖 Learning Objectives

Setelah menggunakan VulnWeb, mahasiswa diharapkan dapat:

1. **Memahami Cyber Kill Chain**: Menerapkan 7 fase dalam konteks web application security
2. **Identifikasi Vulnerabilities**: Mengenali berbagai jenis kerentanan web
3. **Exploitation Techniques**: Mempraktikkan teknik eksploitasi yang umum
4. **Impact Assessment**: Memahami dampak dari setiap vulnerability
5. **Mitigation Strategies**: Mengembangkan strategi pencegahan dan perbaikan

## 🏁 Skenario Ujian

### Scenario 1: Information Gathering
- Lakukan reconnaissance untuk mengidentifikasi teknologi yang digunakan
- Temukan endpoint dan parameter yang vulnerable
- Dokumentasikan temuan

### Scenario 2: Authentication Bypass
- Bypass sistem autentikasi menggunakan SQL injection
- Akses akun admin tanpa mengetahui password
- Dokumentasikan langkah-langkah exploit

### Scenario 3: Data Extraction
- Extract data sensitif dari database
- Temukan password pengguna lain
- Dokumentasikan data yang berhasil diambil

### Scenario 4: Privilege Escalation
- Escalate privilege dari user biasa ke admin
- Akses fungsi administratif
- Dokumentasikan metode yang digunakan

### Scenario 5: Persistent Attack
- Buat persistent XSS untuk steal cookies
- Maintain access menggunakan backdoor
- Dokumentasikan persistence mechanism

## 🛡️ Defensive Measures

Sebagai bagian dari pembelajaran, identifikasi dan implementasikan:

1. **Input Validation**: Proper sanitization dan validation
2. **Output Encoding**: Escape output untuk mencegah XSS
3. **Authentication**: Strong password policy, session management
4. **Authorization**: Proper access control implementation
5. **Error Handling**: Secure error messages
6. **Security Headers**: CSP, X-Frame-Options, dll

## 📝 Assessment Criteria

Penilaian berdasarkan:

1. **Technical Skills** (40%):
   - Kemampuan mengidentifikasi vulnerability
   - Teknik exploitation yang digunakan
   - Tools dan methodology

2. **Documentation** (30%):
   - Laporan yang jelas dan detail
   - Screenshot dan proof of concept
   - Risk assessment

3. **Understanding** (20%):
   - Pemahaman Cyber Kill Chain
   - Impact analysis
   - Mitigation recommendations

4. **Methodology** (10%):
   - Systematic approach
   - Ethical considerations
   - Professional conduct

## 📞 Support

Untuk pertanyaan atau bantuan:
- Buka issue di repository ini
- Konsultasi dengan instruktur
- Diskusi di forum kelas

## 📄 License

Aplikasi ini dibuat untuk tujuan edukasi. Gunakan dengan bijak dan bertanggung jawab.

---

**Selamat belajar dan semoga sukses dengan ujian Cyber Kill Chain! 🎯**