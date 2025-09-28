<?php
require_once 'vendor/autoload.php';
require_once 'src/Security.php';

use App\Security;

// Set security headers including CSP
$csp_headers = Security::getCSPHeader();
foreach ($csp_headers as $header => $value) {
    header("$header: $value");
}

// Additional security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Database configuration
$host = $_ENV['MYSQL_HOST'] ?? 'mysql';
$username = $_ENV['MYSQL_USER'] ?? 'xsslab';
$password = $_ENV['MYSQL_PASSWORD'] ?? 'password123';
$database = $_ENV['MYSQL_DATABASE'] ?? 'xss_lab_secure';

// Create connection
try {
    $pdo = new PDO("mysql:host=$host;dbname=$database;charset=utf8mb4", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
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
    <title>Secure XSS Prevention Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .security-badge { background-color: #28a745; }
        .navbar-brand { font-weight: bold; }
        .card { margin-bottom: 20px; }
        .alert-success { border-left: 4px solid #28a745; }
        .security-info { background-color: #e7f3ff; border: 1px solid #b3d9ff; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-success">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <span class="badge security-badge">🛡️ SECURE</span>
                XSS Prevention Lab
            </a>
            <div class="navbar-nav">
                <a class="nav-link text-white" href="index.php">Home</a>
                <a class="nav-link text-white" href="reflected.php">Secure Reflected</a>
                <a class="nav-link text-white" href="stored.php">Secure Stored</a>
                <a class="nav-link text-white" href="dom.php">Secure DOM</a>
                <a class="nav-link text-white" href="contexts.php">Secure Contexts</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="alert alert-success">
            <h4>✅ SECURE APPLICATION</h4>
            <p>This application implements proper XSS prevention techniques and security best practices.</p>
            <p><strong>All inputs are properly validated and outputs are correctly encoded!</strong></p>
        </div>

        <h1>🛡️ XSS Prevention - Secure Implementation</h1>
        <p class="lead">Aplikasi ini mendemonstrasikan cara yang benar untuk mencegah XSS attacks.</p>

        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-success text-white">
                        <h5>✅ Secure Reflected XSS Prevention</h5>
                    </div>
                    <div class="card-body">
                        <p>Input validation dan output encoding yang proper.</p>
                        <a href="reflected.php" class="btn btn-success">Lihat Implementasi Aman</a>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-success text-white">
                        <h5>✅ Secure Stored XSS Prevention</h5>
                    </div>
                    <div class="card-body">
                        <p>Database sanitization dan HTML purification.</p>
                        <a href="stored.php" class="btn btn-success">Lihat Implementasi Aman</a>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-success text-white">
                        <h5>✅ Secure DOM XSS Prevention</h5>
                    </div>
                    <div class="card-body">
                        <p>Safe JavaScript practices dan DOM manipulation.</p>
                        <a href="dom.php" class="btn btn-success">Lihat Implementasi Aman</a>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card">
                    <div class="card-header bg-success text-white">
                        <h5>✅ Secure Context Handling</h5>
                    </div>
                    <div class="card-body">
                        <p>Context-aware encoding untuk berbagai situasi.</p>
                        <a href="contexts.php" class="btn btn-success">Lihat Implementasi Aman</a>
                    </div>
                </div>
            </div>
        </div>

        <div class="security-info p-4 rounded mt-4">
            <h5>🔒 Security Features Implemented:</h5>
            <div class="row">
                <div class="col-md-6">
                    <ul>
                        <li><strong>Input Validation:</strong> Server-side validation untuk semua input</li>
                        <li><strong>Output Encoding:</strong> Context-aware encoding (HTML, JS, CSS, URL)</li>
                        <li><strong>Content Security Policy:</strong> CSP header untuk mencegah script injection</li>
                        <li><strong>HTML Purifier:</strong> Library untuk membersihkan HTML content</li>
                    </ul>
                </div>
                <div class="col-md-6">
                    <ul>
                        <li><strong>CSRF Protection:</strong> Token-based CSRF protection</li>
                        <li><strong>Security Headers:</strong> X-XSS-Protection, X-Frame-Options, dll</li>
                        <li><strong>Safe DOM Methods:</strong> textContent instead of innerHTML</li>
                        <li><strong>URL Validation:</strong> Whitelist approach untuk URL schemes</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="alert alert-info mt-4">
            <h5>📚 Coba Payload XSS - Semuanya Akan Aman!</h5>
            <p>Silakan coba payload XSS yang sama seperti di vulnerable app:</p>
            <div class="row">
                <div class="col-md-6">
                    <ul>
                        <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                        <li><code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                        <li><code>&lt;svg onload=alert('XSS')&gt;</code></li>
                    </ul>
                </div>
                <div class="col-md-6">
                    <ul>
                        <li><code>&lt;iframe src="javascript:alert('XSS')"&gt;</code></li>
                        <li><code>" onmouseover="alert('XSS')</code></li>
                        <li><code>'; alert('XSS'); //</code></li>
                    </ul>
                </div>
            </div>
            <p><strong>Hasil:</strong> Semua payload akan di-encode dengan aman dan ditampilkan sebagai text biasa!</p>
        </div>

        <div class="alert alert-warning mt-4">
            <h5>🔄 Perbandingan dengan Vulnerable App</h5>
            <p>Bandingkan behavior aplikasi ini dengan vulnerable version:</p>
            <a href="http://localhost:8080" target="_blank" class="btn btn-danger">Buka Aplikasi Vulnerable</a>
            <p class="mt-2"><small>Buka di tab terpisah untuk melihat perbedaan implementasi.</small></p>
        </div>

        <div class="card mt-4">
            <div class="card-header bg-primary text-white">
                <h5>📖 Source Code Examples</h5>
            </div>
            <div class="card-body">
                <h6>Before (Vulnerable):</h6>
                <pre><code class="text-danger">echo $_GET['input'];  // DANGEROUS!</code></pre>
                
                <h6>After (Secure):</h6>
                <pre><code class="text-success">echo Security::escapeHtml($_GET['input']);  // SAFE!</code></pre>
                
                <p class="mt-3">
                    <a href="https://github.com/your-repo/xss-lab" target="_blank" class="btn btn-outline-primary">
                        📋 View Complete Source Code
                    </a>
                </p>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>