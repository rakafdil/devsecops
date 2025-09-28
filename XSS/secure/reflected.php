<?php
require_once 'vendor/autoload.php';
require_once 'src/Security.php';

use App\Security;

// Set security headers
$csp_headers = Security::getCSPHeader();
foreach ($csp_headers as $header => $value) {
    header("$header: $value");
}
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Reflected XSS Prevention</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .security-badge { background-color: #28a745; }
        .code-example { background-color: #f8f9fa; padding: 15px; border-left: 4px solid #28a745; }
        .safe-output { border: 2px solid #28a745; padding: 15px; background-color: #f8fff9; }
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
                <a class="nav-link text-white" href="reflected.php" style="background-color: rgba(255,255,255,0.2);">Secure Reflected</a>
                <a class="nav-link text-white" href="stored.php">Secure Stored</a>
                <a class="nav-link text-white" href="dom.php">Secure DOM</a>
                <a class="nav-link text-white" href="contexts.php">Secure Contexts</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h1>✅ Secure Reflected XSS Prevention</h1>
        <div class="alert alert-success">
            <strong>Security Implementation:</strong> Proper input validation and output encoding prevents all XSS attacks.
        </div>

        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header bg-success text-white">
                        <h5>🔒 Secure Search Form</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <?php $csrf_token = Security::generateCSRFToken(); ?>
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            
                            <div class="mb-3">
                                <label for="search" class="form-label">Search Query:</label>
                                <input type="text" class="form-control" id="search" name="search" 
                                       value="<?php echo isset($_GET['search']) ? Security::escapeAttr($_GET['search']) : ''; ?>"
                                       placeholder="Coba masukkan: <script>alert('XSS')</script>">
                            </div>
                            <button type="submit" class="btn btn-success">Safe Search</button>
                        </form>

                        <?php 
                        if (isset($_GET['search']) && !empty($_GET['search'])) {
                            // CSRF Protection
                            if (!isset($_GET['csrf_token']) || !Security::validateCSRFToken($_GET['csrf_token'])) {
                                echo '<div class="alert alert-warning mt-3">Invalid CSRF token. Please try again.</div>';
                            } else {
                                // Input validation and sanitization
                                $search_term = Security::validateInput($_GET['search'], 'string', 500);
                                
                                if (!empty($search_term)) {
                        ?>
                            <div class="mt-3">
                                <h6>Search Results:</h6>
                                <div class="safe-output">
                                    <!-- SECURE CODE - Properly encoded output -->
                                    <strong>You searched for:</strong> <?php echo Security::escapeHtml($search_term); ?>
                                </div>
                                <p class="mt-2">No results found for your query. (This is a demo - no actual search performed)</p>
                                
                                <div class="alert alert-info mt-3">
                                    <strong>🛡️ Security Note:</strong> Your input was safely encoded using 
                                    <code>htmlspecialchars()</code> with proper flags to prevent XSS.
                                </div>
                            </div>
                        <?php 
                                } else {
                                    echo '<div class="alert alert-warning mt-3">Invalid search term provided.</div>';
                                }
                            }
                        } 
                        ?>
                    </div>
                </div>

                <div class="card mt-4">
                    <div class="card-header bg-success text-white">
                        <h5>🔒 Secure User Profile</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="page" value="profile">
                            <input type="hidden" name="csrf_token" value="<?php echo Security::generateCSRFToken(); ?>">
                            
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" class="form-control" id="username" name="username" 
                                       value="<?php echo isset($_GET['username']) ? Security::escapeAttr($_GET['username']) : ''; ?>"
                                       placeholder="Enter your username"
                                       pattern="[a-zA-Z0-9_-]+"
                                       title="Username can only contain letters, numbers, underscore, and dash"
                                       maxlength="50">
                            </div>
                            <button type="submit" class="btn btn-success">Show Secure Profile</button>
                        </form>

                        <?php 
                        if (isset($_GET['page']) && $_GET['page'] === 'profile' && isset($_GET['username'])) {
                            // CSRF Protection
                            if (!isset($_GET['csrf_token']) || !Security::validateCSRFToken($_GET['csrf_token'])) {
                                echo '<div class="alert alert-warning mt-3">Invalid CSRF token.</div>';
                            } else {
                                // Strict input validation for username
                                $username = $_GET['username'];
                                
                                // Validate username format (only alphanumeric, underscore, dash)
                                if (preg_match('/^[a-zA-Z0-9_-]{1,50}$/', $username)) {
                                    $clean_username = Security::escapeHtml($username);
                        ?>
                            <div class="mt-3">
                                <div class="card">
                                    <div class="card-body safe-output">
                                        <!-- SECURE CODE - Validated and encoded output -->
                                        <h6>Welcome, <?php echo $clean_username; ?>! 👋</h6>
                                        <p>This is your secure profile page.</p>
                                        <small class="text-muted">
                                            Username validated with regex: <code>/^[a-zA-Z0-9_-]{1,50}$/</code>
                                        </small>
                                    </div>
                                </div>
                            </div>
                        <?php 
                                } else {
                                    echo '<div class="alert alert-danger mt-3">Invalid username format. Only letters, numbers, underscore, and dash allowed (max 50 chars).</div>';
                                }
                            }
                        } 
                        ?>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h5>🧪 Test These Payloads</h5>
                    </div>
                    <div class="card-body">
                        <p>Semua payload ini akan aman:</p>
                        
                        <h6>Basic Script:</h6>
                        <div class="code-example">
                            <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
                        </div>

                        <h6 class="mt-3">Image Onerror:</h6>
                        <div class="code-example">
                            <code>&lt;img src=x onerror=alert('XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">SVG Onload:</h6>
                        <div class="code-example">
                            <code>&lt;svg onload=alert('XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">Event Handler:</h6>
                        <div class="code-example">
                            <code>" onmouseover="alert('XSS')</code>
                        </div>

                        <div class="alert alert-success mt-3">
                            <strong>✅ Result:</strong> Semua payload akan ditampilkan sebagai text biasa, tidak dieksekusi!
                        </div>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header bg-success text-white">
                        <h5>🔧 Security Implementation</h5>
                    </div>
                    <div class="card-body">
                        <h6>Input Validation:</h6>
                        <small>
                            <pre><code>// Validate input type & length
$input = Security::validateInput(
    $_GET['search'], 
    'string', 
    500
);

// Regex validation for usernames
preg_match('/^[a-zA-Z0-9_-]{1,50}$/', $input)</code></pre>
                        </small>

                        <h6 class="mt-3">Output Encoding:</h6>
                        <small>
                            <pre><code>// HTML context encoding
echo Security::escapeHtml($input);

// Attribute context encoding  
echo Security::escapeAttr($input);

// Implementation:
htmlspecialchars($input, 
    ENT_QUOTES | ENT_HTML5, 
    'UTF-8')</code></pre>
                        </small>

                        <h6 class="mt-3">CSRF Protection:</h6>
                        <small>
                            <pre><code>// Generate token
$token = Security::generateCSRFToken();

// Validate token
Security::validateCSRFToken($token)</code></pre>
                        </small>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header bg-primary text-white">
                        <h5>📊 Security Headers</h5>
                    </div>
                    <div class="card-body">
                        <small>
                            <ul>
                                <li><strong>CSP:</strong> Content-Security-Policy</li>
                                <li><strong>XSS:</strong> X-XSS-Protection: 1; mode=block</li>
                                <li><strong>Frame:</strong> X-Frame-Options: DENY</li>
                                <li><strong>Content:</strong> X-Content-Type-Options: nosniff</li>
                                <li><strong>Referrer:</strong> Referrer-Policy: strict-origin</li>
                            </ul>
                        </small>
                        
                        <button onclick="showHeaders()" class="btn btn-sm btn-outline-primary mt-2">
                            View Current Headers
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <div class="alert alert-info mt-4">
            <h5>📝 Learning Notes - Secure Implementation:</h5>
            <ul>
                <li><strong>Defense in Depth:</strong> Multiple layers of protection (validation + encoding + CSP + headers)</li>
                <li><strong>Input Validation:</strong> Strict server-side validation with whitelisting approach</li>
                <li><strong>Output Encoding:</strong> Context-aware encoding using proper PHP functions</li>
                <li><strong>CSRF Protection:</strong> Token-based protection against Cross-Site Request Forgery</li>
                <li><strong>Security Headers:</strong> Browser-level protection mechanisms</li>
                <li><strong>Fail-Safe:</strong> Default to secure behavior when validation fails</li>
            </ul>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Safe JavaScript implementation
        function showHeaders() {
            // Using alert is generally not recommended in production, but OK for demo
            const headerInfo = `
Security Headers Active:
• Content-Security-Policy: Restricts script sources
• X-XSS-Protection: Browser XSS filter enabled  
• X-Frame-Options: Prevents framing attacks
• X-Content-Type-Options: Prevents MIME sniffing
• Referrer-Policy: Controls referrer information

Check browser dev tools → Network → Response Headers
            `.trim();
            
            alert(headerInfo);
        }
        
        // Demonstrate safe DOM manipulation
        document.addEventListener('DOMContentLoaded', function() {
            // Example of SAFE DOM manipulation (if needed)
            // Always use textContent instead of innerHTML for user data
            // const safeElement = document.getElementById('safe-element');
            // safeElement.textContent = userInput; // SAFE
            // safeElement.innerHTML = userInput;   // DANGEROUS
        });
    </script>
</body>
</html>