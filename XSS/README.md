# Cross-Site Scripting (XSS) Hands-On Lab

Lab ini dirancang untuk memahami berbagai jenis serangan Cross-Site Scripting (XSS) dan cara pencegahannya menggunakan PHP dan Docker.

## 📋 Prerequisites

- Docker dan Docker Compose terinstall
- Text editor (VS Code, vim, dll)
- Web browser
- Pemahaman dasar HTML, JavaScript, dan PHP

## 🚀 Quick Start

1. Clone atau download repository ini
2. Jalankan lab dengan Docker Compose:

```bash
docker-compose up -d
```

3. Akses aplikasi di browser:
   - **Vulnerable App**: http://localhost:8080
   - **Secure App**: http://localhost:8081
   - **phpMyAdmin**: http://localhost:8082

## 📚 Struktur Lab

### 1. Reflected XSS
- **File**: `vulnerable/reflected.php`
- **Deskripsi**: XSS yang terjadi ketika input pengguna langsung ditampilkan di halaman tanpa sanitasi
- **Contoh Payload**: `<script>alert('XSS')</script>`

### 2. Stored XSS (Persistent)
- **File**: `vulnerable/stored.php`
- **Deskripsi**: XSS yang disimpan di database dan dieksekusi setiap kali halaman dimuat
- **Target**: Form komentar atau guestbook

### 3. DOM-based XSS
- **File**: `vulnerable/dom.php`
- **Deskripsi**: XSS yang terjadi melalui manipulasi DOM di sisi client
- **Target**: JavaScript yang menggunakan `innerHTML` atau `document.write`

### 4. XSS dalam Context yang Berbeda
- **File**: `vulnerable/contexts.php`
- **Deskripsi**: XSS dalam berbagai context HTML (attribute, JavaScript, CSS)

## 🛡️ Mitigasi XSS

Lab ini juga menyediakan contoh aplikasi yang aman dengan implementasi:

1. **Input Validation**: Validasi input di sisi server
2. **Output Encoding**: Encoding output sesuai context
3. **Content Security Policy (CSP)**: Header keamanan untuk mencegah eksekusi script
4. **HTML Purifier**: Library untuk membersihkan HTML

## 🎯 Learning Objectives

Setelah menyelesaikan lab ini, Anda akan memahami:

1. Berbagai jenis serangan XSS
2. Cara mengidentifikasi kerentanan XSS
3. Teknik mitigasi dan pencegahan XSS
4. Best practices dalam secure coding

## 📖 Panduan Penggunaan

1. Mulai dengan aplikasi vulnerable untuk memahami serangan
2. Coba berbagai payload XSS yang disediakan
3. Analisis kode untuk memahami penyebab kerentanan
4. Pelajari aplikasi secure untuk memahami mitigasi
5. Implementasikan fix pada aplikasi vulnerable

## ⚠️ Disclaimer

Lab ini dibuat untuk tujuan edukasi. Jangan gunakan pengetahuan ini untuk aktivitas ilegal atau merugikan pihak lain.

## 📞 Support

Jika ada pertanyaan atau masalah, silakan buat issue di repository ini.