# Broken Access Control Hands-On Lab

🚨 **PERINGATAN: Aplikasi ini sengaja dibuat rentan untuk tujuan pembelajaran. Jangan pernah deploy di lingkungan produksi!**

## 📋 Deskripsi Proyek

Ini adalah hands-on lab untuk mempelajari kerentanan Broken Access Control menggunakan aplikasi web PHP yang berjalan di Docker. Aplikasi ini mengandung berbagai kerentanan keamanan yang umum ditemukan dalam kontrol akses.

## 🎯 Tujuan Pembelajaran

Setelah menyelesaikan lab ini, Anda akan memahami:

- **Insecure Direct Object References (IDOR)** - Mengakses data pengguna lain dengan mengubah parameter ID
- **Missing Function Level Access Control** - Mengakses fungsi admin tanpa otorisasi yang tepat
- **Horizontal Privilege Escalation** - Mengakses data pengguna lain pada level yang sama
- **Vertical Privilege Escalation** - Mendapatkan akses admin dari akun user biasa
- **Missing Authorization** - Fungsi yang tidak melakukan pengecekan permission

## 🛠️ Teknologi yang Digunakan

- **PHP 8.1** dengan Apache
- **MySQL 8.0** untuk database
- **Docker & Docker Compose** untuk containerization
- **Bootstrap CSS** untuk styling

## 📦 Instalasi dan Menjalankan

### Prerequisites

Pastikan Anda telah menginstall:
- Docker
- Docker Compose

### Langkah Instalasi

1. **Clone atau download proyek ini**
   ```bash
   git clone <repository-url>
   cd "Broken acess control"
   ```

2. **Jalankan dengan Docker Compose**
   ```bash
   docker-compose up -d
   ```

3. **Akses aplikasi**
   - Buka browser dan kunjungi: `http://localhost:8080`
   - Database MySQL tersedia di: `localhost:3306`

4. **Login dengan akun test**
   ```
   Admin: admin / password
   User: john_doe / password  
   Moderator: jane_smith / password
   ```

## 🔍 Struktur Aplikasi

```
src/
├── config.php          # Konfigurasi database dan fungsi auth
├── header.php          # Header dan navigasi
├── footer.php          # Footer
├── index.php           # Homepage dengan petunjuk
├── login.php           # Halaman login
├── register.php        # Halaman registrasi
├── logout.php          # Logout
├── profile.php         # Profil user (VULNERABLE - IDOR)
├── admin.php           # Panel admin (VULNERABLE - Missing Access Control)
├── documents.php       # Dokumen (VULNERABLE - IDOR)
└── vulnerabilities.php # Panduan kerentanan

database/
└── init.sql            # Schema database dan data sample

docker-compose.yml      # Konfigurasi Docker
Dockerfile             # Image PHP dengan Apache
```

## 🚨 Kerentanan yang Diimplementasikan

### 1. Insecure Direct Object References (IDOR)
**Lokasi:** `profile.php`, `documents.php`

**Cara test:**
- Login sebagai user biasa
- Akses `profile.php?user_id=1` untuk melihat profil admin
- Akses `documents.php?doc_id=2` untuk dokumen private HR

### 2. Missing Function Level Access Control
**Lokasi:** `admin.php`

**Cara test:**
- Login sebagai user biasa (john_doe/password)
- Akses langsung `admin.php`
- Coba delete user lain atau promote diri sendiri ke admin

### 3. Horizontal Privilege Escalation
**Lokasi:** Profil dan dokumen user lain

**Cara test:**
- Login sebagai john_doe
- Akses data jane_smith melalui parameter manipulation
- Lihat informasi sensitif seperti salary dan data pribadi

### 4. Vertical Privilege Escalation
**Lokasi:** Admin functions

**Cara test:**
- User biasa bisa mengakses dan mengeksekusi fungsi admin
- Promote diri sendiri menjadi admin
- Delete akun user lain

## 🧪 Hands-On Exercises

### Exercise 1: Profile Enumeration
1. Login sebagai 'john_doe'
2. Kunjungi profil Anda dan perhatikan struktur URL
3. Coba ubah parameter user_id untuk mengakses profil lain
4. Dokumentasikan informasi sensitif apa saja yang bisa diakses

### Exercise 2: Admin Panel Bypass
1. Login sebagai user biasa
2. Coba akses admin panel secara langsung
3. Coba delete user lain atau promote diri sendiri
4. Amati aksi mana saja yang benar-benar diproses sistem

### Exercise 3: Document Access
1. Identifikasi dokumen private di listing
2. Coba akses langsung menggunakan parameter doc_id
3. Test kemungkinan enumerasi dokumen
4. Evaluasi tingkat sensitivitas informasi yang terekspos

## 🛡️ Solusi Keamanan

### Cara memperbaiki IDOR:
```php
// Before (Vulnerable)
$user_id = $_GET['user_id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");

// After (Secure)
$user_id = $_GET['user_id'];
// Check if current user can access this profile
if ($user_id != $_SESSION['user_id'] && !isAdmin()) {
    die("Access denied");
}
```

### Cara memperbaiki Missing Access Control:
```php
// Before (Vulnerable)
if (!isAdmin()) {
    echo "Warning: You don't have admin privileges";
    // Page continues to load
}

// After (Secure)
if (!isAdmin()) {
    header('HTTP/1.1 403 Forbidden');
    die("Access denied");
}
```

## 📊 Database Schema

Database berisi tabel-tabel berikut:
- `users` - Data pengguna dan role
- `profiles` - Informasi pribadi user (termasuk salary)
- `documents` - Dokumen public dan private  
- `admin_logs` - Log aktivitas admin

## 🔧 Troubleshooting

### Aplikasi tidak bisa diakses
- Pastikan Docker sudah running
- Check port 8080 tidak digunakan aplikasi lain
- Jalankan `docker-compose logs` untuk melihat error

### Database connection error
- Tunggu beberapa detik hingga MySQL container siap
- Restart container: `docker-compose restart`

### Permission errors
- Pastikan Docker memiliki akses ke folder proyek
- Coba `docker-compose down` dan `docker-compose up -d`

## ⚠️ Disclaimer

Aplikasi ini dibuat khusus untuk tujuan edukasi keamanan siber. Kerentanan yang ada adalah SENGAJA dibuat untuk pembelajaran. 

**JANGAN PERNAH:**
- Deploy aplikasi ini di server production
- Gunakan pada data real atau sensitif
- Akses tanpa izin pada sistem yang bukan milik Anda

## 📚 Referensi Pembelajaran

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/access-control)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

## 📝 License

Proyek ini dibuat untuk tujuan edukasi. Gunakan dengan tanggung jawab sendiri.

---

**Happy Learning! 🚀**