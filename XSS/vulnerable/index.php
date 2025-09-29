<?php
// Database configuration
$host = $_ENV['MYSQL_HOST'] ?? 'mysql';
$username = $_ENV['MYSQL_USER'] ?? 'xsslab';
$password = $_ENV['MYSQL_PASSWORD'] ?? 'password123';
$database = $_ENV['MYSQL_DATABASE'] ?? 'xss_lab';

// Create connection
try {
    $pdo = new PDO("mysql:host=$host;dbname=$database;charset=utf8", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Start session
session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .vulnerability-badge { background-color: #dc3545; }
        .navbar-brand { font-weight: bold; }
        .card { margin-bottom: 20px; }
        .alert-danger { border-left: 4px solid #dc3545; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <span class="badge vulnerability-badge">VULNERABLE</span>
                XSS Lab
            </a>
            <div class="navbar-nav">
                <a class="nav-link" href="index.php">Home</a>
                <a class="nav-link" href="reflected.php">Reflected XSS</a>
                <a class="nav-link" href="stored.php">Stored XSS</a>
                <a class="nav-link" href="dom.php">DOM XSS</a>
                <a class="nav-link" href="contexts.php">XSS Contexts</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="alert alert-danger">
            <h4>⚠️ WARNING - VULNERABLE APPLICATION</h4>
            <p>This application contains intentional security vulnerabilities for educational purposes.</p>
            <p><strong>DO NOT deploy this application in production!</strong></p>
        </div>

        <h1>Cross-Site Scripting (XSS) Vulnerable Lab</h1>
        <p class="lead">Aplikasi ini sengaja dibuat vulnerable untuk pembelajaran XSS.</p>

        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>🎯 Reflected XSS</h5>
                    </div>
                    <div class="card-body">
                        <p>XSS yang terjadi ketika input pengguna langsung ditampilkan kembali.</p>
                        <a href="reflected.php" class="btn btn-danger">Coba Reflected XSS</a>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>💾 Stored XSS</h5>
                    </div>
                    <div class="card-body">
                        <p>XSS yang disimpan di database dan dieksekusi saat halaman dimuat.</p>
                        <a href="stored.php" class="btn btn-danger">Coba Stored XSS</a>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>🌐 DOM-based XSS</h5>
                    </div>
                    <div class="card-body">
                        <p>XSS yang terjadi melalui manipulasi DOM di client-side.</p>
                        <a href="dom.php" class="btn btn-danger">Coba DOM XSS</a>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>📝 XSS Contexts</h5>
                    </div>
                    <div class="card-body">
                        <p>XSS dalam berbagai context HTML yang berbeda.</p>
                        <a href="contexts.php" class="btn btn-danger">Coba Context XSS</a>
                    </div>
                </div>
            </div>
        </div>

        <div class="alert alert-info mt-4">
            <h5>📚 Contoh Payload XSS untuk Dicoba:</h5>
            <ul>
                <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                <li><code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                <li><code>&lt;svg onload=alert('XSS')&gt;</code></li>
                <li><code>&lt;iframe src="javascript:alert('XSS')"&gt;</code></li>
                <li><code>&lt;body onload=alert('XSS')&gt;</code></li>
            </ul>
        </div>

        <div class="alert alert-success mt-4">
            <h5>🛡️ Aplikasi Aman</h5>
            <p>Setelah memahami kerentanan, lihat implementasi yang aman di:</p>
            <a href="http://localhost:8081" target="_blank" class="btn btn-success">Buka Aplikasi Aman</a>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>