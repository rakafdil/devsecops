<?php
// Database configuration
$host = $_ENV['MYSQL_HOST'] ?? 'mysql';
$username = $_ENV['MYSQL_USER'] ?? 'xsslab';
$password = $_ENV['MYSQL_PASSWORD'] ?? 'password123';
$database = $_ENV['MYSQL_DATABASE'] ?? 'xss_lab';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$database;charset=utf8", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reflected XSS - Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .vulnerability-badge { background-color: #dc3545; }
        .code-example { background-color: #f8f9fa; padding: 15px; border-left: 4px solid #dc3545; }
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
                <a class="nav-link active" href="reflected.php">Reflected XSS</a>
                <a class="nav-link" href="stored.php">Stored XSS</a>
                <a class="nav-link" href="dom.php">DOM XSS</a>
                <a class="nav-link" href="contexts.php">XSS Contexts</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h1>🎯 Reflected XSS Vulnerability</h1>
        <div class="alert alert-danger">
            <strong>Kerentanan:</strong> Input pengguna langsung ditampilkan tanpa sanitasi atau encoding.
        </div>

        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h5>Search Form (Vulnerable)</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <div class="mb-3">
                                <label for="search" class="form-label">Search Query:</label>
                                <input type="text" class="form-control" id="search" name="search" 
                                       value="<?php echo isset($_GET['search']) ? $_GET['search'] : ''; ?>"
                                       placeholder="Coba masukkan: <script>alert('XSS')</script>">
                            </div>
                            <button type="submit" class="btn btn-primary">Search</button>
                        </form>

                        <?php if (isset($_GET['search']) && !empty($_GET['search'])): ?>
                            <div class="mt-3">
                                <h6>Search Results:</h6>
                                <div class="alert alert-info">
                                    <!-- VULNERABLE CODE - Direct output without sanitization -->
                                    You searched for: <?php echo $_GET['search']; ?>
                                </div>
                                <p>No results found for your query.</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="card mt-4">
                    <div class="card-header">
                        <h5>User Profile (Vulnerable)</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="page" value="profile">
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" 
                                       value="<?php echo isset($_GET['username']) ? $_GET['username'] : ''; ?>"
                                       placeholder="Masukkan username">
                            </div>
                            <button type="submit" class="btn btn-success">Show Profile</button>
                        </form>

                        <?php if (isset($_GET['page']) && $_GET['page'] === 'profile' && isset($_GET['username'])): ?>
                            <div class="mt-3">
                                <div class="card">
                                    <div class="card-body">
                                        <!-- VULNERABLE CODE -->
                                        <h6>Welcome, <?php echo $_GET['username']; ?>!</h6>
                                        <p>This is your profile page.</p>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h5>💡 Payload Examples</h5>
                    </div>
                    <div class="card-body">
                        <h6>Basic Alert:</h6>
                        <div class="code-example">
                            <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
                        </div>

                        <h6 class="mt-3">Image Tag:</h6>
                        <div class="code-example">
                            <code>&lt;img src=x onerror=alert('XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">SVG Tag:</h6>
                        <div class="code-example">
                            <code>&lt;svg onload=alert('XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">Cookie Stealing:</h6>
                        <div class="code-example">
                            <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>
                        </div>

                        <h6 class="mt-3">Iframe:</h6>
                        <div class="code-example">
                            <code>&lt;iframe src="javascript:alert('XSS')"&gt;</code>
                        </div>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header">
                        <h5>🔍 Vulnerable Code</h5>
                    </div>
                    <div class="card-body">
                        <small>
                            <pre><code>// VULNERABLE PHP CODE:
echo $_GET['search'];
echo $_GET['username'];

// No input validation
// No output encoding
// No sanitization</code></pre>
                        </small>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header">
                        <h5>🛡️ How to Fix</h5>
                    </div>
                    <div class="card-body">
                        <small>
                            <pre><code>// SECURE PHP CODE:
echo htmlspecialchars($_GET['search'], 
    ENT_QUOTES, 'UTF-8');

// Or use filter_input:
$clean = filter_input(INPUT_GET, 
    'search', FILTER_SANITIZE_STRING);</code></pre>
                        </small>
                    </div>
                </div>
            </div>
        </div>

        <div class="alert alert-warning mt-4">
            <h5>📝 Learning Notes:</h5>
            <ul>
                <li><strong>Reflected XSS</strong> terjadi ketika input pengguna langsung ditampilkan kembali ke browser tanpa sanitasi</li>
                <li>Serangan ini tidak permanen - hanya terjadi ketika victim mengklik link yang sudah dimanipulasi</li>
                <li>Payload XSS biasanya dikirim melalui URL parameter atau form input</li>
                <li>Pencegahan: Selalu encode output dan validasi input</li>
            </ul>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>