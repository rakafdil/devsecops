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

// Database configuration
$host = $_ENV['MYSQL_HOST'] ?? 'mysql';
$username = $_ENV['MYSQL_USER'] ?? 'xsslab';
$password = $_ENV['MYSQL_PASSWORD'] ?? 'password123';
$database = $_ENV['MYSQL_DATABASE'] ?? 'xss_lab_secure';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$database;charset=utf8mb4", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

$success_message = '';
$error_message = '';

// Handle comment submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_comment'])) {
    // CSRF Protection
    if (!Security::validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error_message = "Invalid CSRF token. Please try again.";
    } else {
        // Validate and sanitize inputs
        $name = Security::validateInput($_POST['name'] ?? '', 'string', 100);
        $email = Security::validateInput($_POST['email'] ?? '', 'email', 255);
        $comment = Security::validateInput($_POST['comment'] ?? '', 'string', 1000);
        
        // Additional validation
        if (empty($name) || strlen($name) < 2) {
            $error_message = "Name must be at least 2 characters long.";
        } elseif (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error_message = "Please enter a valid email address.";
        } elseif (empty($comment) || strlen($comment) < 5) {
            $error_message = "Comment must be at least 5 characters long.";
        } else {
            // Further sanitization for HTML content (using HTMLPurifier would be better)
            $comment = strip_tags($comment, '<p><br><b><i><u><strong><em>');
            
            // SECURE CODE - Prepared statement with sanitized data
            try {
                $stmt = $pdo->prepare("INSERT INTO comments (name, email, comment) VALUES (?, ?, ?)");
                $stmt->execute([$name, $email, $comment]);
                $success_message = "Comment posted successfully and securely!";
            } catch (PDOException $e) {
                $error_message = "Database error occurred.";
                error_log("Database error: " . $e->getMessage());
            }
        }
    }
}

// Handle comment deletion (with additional security)
if (isset($_GET['delete']) && isset($_GET['csrf_token'])) {
    if (Security::validateCSRFToken($_GET['csrf_token'])) {
        $id = filter_var($_GET['delete'], FILTER_VALIDATE_INT);
        if ($id) {
            $stmt = $pdo->prepare("DELETE FROM comments WHERE id = ?");
            $stmt->execute([$id]);
            header("Location: stored.php");
            exit;
        }
    }
}

// Fetch all comments
$stmt = $pdo->query("SELECT * FROM comments ORDER BY created_at DESC");
$comments = $stmt->fetchAll(PDO::FETCH_ASSOC);

session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Stored XSS Prevention</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .security-badge { background-color: #28a745; }
        .code-example { background-color: #f8f9fa; padding: 15px; border-left: 4px solid #28a745; }
        .comment-card { border-left: 4px solid #28a745; background-color: #f8fff9; }
        .safe-content { background-color: #e8f5e8; }
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
                <a class="nav-link text-white" href="stored.php" style="background-color: rgba(255,255,255,0.2);">Secure Stored</a>
                <a class="nav-link text-white" href="dom.php">Secure DOM</a>
                <a class="nav-link text-white" href="contexts.php">Secure Contexts</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h1>✅ Secure Stored XSS Prevention</h1>
        <div class="alert alert-success">
            <strong>Security Implementation:</strong> Input validation, output encoding, HTML sanitization, and CSRF protection.
        </div>

        <?php if (!empty($success_message)): ?>
        <div class="alert alert-success">
            <i class="bi bi-check-circle"></i> <?php echo Security::escapeHtml($success_message); ?>
        </div>
        <?php endif; ?>

        <?php if (!empty($error_message)): ?>
        <div class="alert alert-danger">
            <i class="bi bi-exclamation-triangle"></i> <?php echo Security::escapeHtml($error_message); ?>
        </div>
        <?php endif; ?>

        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header bg-success text-white">
                        <h5>🔒 Secure Comment Form</h5>
                    </div>
                    <div class="card-body">
                        <form method="POST">
                            <!-- CSRF Protection -->
                            <input type="hidden" name="csrf_token" value="<?php echo Security::generateCSRFToken(); ?>">
                            
                            <div class="mb-3">
                                <label for="name" class="form-label">Name: <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" id="name" name="name" 
                                       required maxlength="100" pattern="[a-zA-Z\s]{2,100}"
                                       title="Name should contain only letters and spaces, 2-100 characters">
                            </div>
                            
                            <div class="mb-3">
                                <label for="email" class="form-label">Email: <span class="text-danger">*</span></label>
                                <input type="email" class="form-control" id="email" name="email" 
                                       required maxlength="255">
                            </div>
                            
                            <div class="mb-3">
                                <label for="comment" class="form-label">Comment: <span class="text-danger">*</span></label>
                                <textarea class="form-control" id="comment" name="comment" rows="4" 
                                          required maxlength="1000" minlength="5"
                                          placeholder="Share your thoughts... (HTML tags will be filtered)"></textarea>
                                <div class="form-text">Maximum 1000 characters. Basic HTML tags (b, i, u, strong, em) are allowed.</div>
                            </div>
                            
                            <button type="submit" name="submit_comment" class="btn btn-success">
                                🛡️ Post Secure Comment
                            </button>
                        </form>
                    </div>
                </div>

                <div class="card mt-4">
                    <div class="card-header bg-success text-white">
                        <h5>💬 Secure Comments (<?php echo count($comments); ?> total)</h5>
                    </div>
                    <div class="card-body">
                        <?php if (empty($comments)): ?>
                            <p class="text-muted">No comments yet. Be the first to leave a secure comment!</p>
                        <?php else: ?>
                            <?php foreach ($comments as $comment): ?>
                                <div class="card comment-card mb-3">
                                    <div class="card-body safe-content">
                                        <div class="d-flex justify-content-between">
                                            <h6 class="card-title">
                                                <!-- SECURE CODE - Properly encoded output -->
                                                <?php echo Security::escapeHtml($comment['name']); ?>
                                                <small class="text-muted">
                                                    (<?php echo Security::escapeHtml($comment['email']); ?>)
                                                </small>
                                            </h6>
                                            <small class="text-muted">
                                                <?php echo Security::escapeHtml(date('Y-m-d H:i', strtotime($comment['created_at']))); ?>
                                                <a href="?delete=<?php echo urlencode($comment['id']); ?>&csrf_token=<?php echo urlencode(Security::generateCSRFToken()); ?>" 
                                                   class="text-danger ms-2" 
                                                   onclick="return confirm('Delete this comment securely?')">Delete</a>
                                            </small>
                                        </div>
                                        <div class="card-text">
                                            <!-- SECURE CODE - HTML-encoded output (even though we already sanitized input) -->
                                            <?php echo Security::escapeHtml($comment['comment']); ?>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h5>🧪 Test Malicious Payloads</h5>
                    </div>
                    <div class="card-body">
                        <p>Try these XSS payloads - they will be safely handled:</p>
                        
                        <h6>Basic Script:</h6>
                        <div class="code-example">
                            <code>&lt;script&gt;alert('Stored XSS!')&lt;/script&gt;</code>
                        </div>

                        <h6 class="mt-3">Image Onerror:</h6>
                        <div class="code-example">
                            <code>&lt;img src=x onerror=alert('XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">SVG Attack:</h6>
                        <div class="code-example">
                            <code>&lt;svg onload=alert('XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">Event Handler:</h6>
                        <div class="code-example">
                            <code>&lt;div onmouseover=alert('XSS')&gt;Hover&lt;/div&gt;</code>
                        </div>

                        <div class="alert alert-success mt-3">
                            <strong>✅ Security Result:</strong> All payloads are safely encoded and displayed as text!
                        </div>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header bg-success text-white">
                        <h5>🔧 Security Implementation</h5>
                    </div>
                    <div class="card-body">
                        <h6>1. Input Validation:</h6>
                        <small>
                            <pre><code>// Length & format validation
$name = Security::validateInput($input, 'string', 100);
$email = Security::validateInput($input, 'email', 255);

// HTML tag filtering
$comment = strip_tags($comment, '&lt;p&gt;&lt;br&gt;&lt;b&gt;&lt;i&gt;&lt;u&gt;');</code></pre>
                        </small>

                        <h6 class="mt-3">2. Output Encoding:</h6>
                        <small>
                            <pre><code>// HTML context encoding
echo Security::escapeHtml($comment['name']);
echo Security::escapeHtml($comment['comment']);

// Double protection approach</code></pre>
                        </small>

                        <h6 class="mt-3">3. CSRF Protection:</h6>
                        <small>
                            <pre><code>// Token generation & validation
$token = Security::generateCSRFToken();
Security::validateCSRFToken($token);</code></pre>
                        </small>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header bg-warning text-dark">
                        <h5>⚡ Additional Security</h5>
                    </div>
                    <div class="card-body">
                        <ul class="small">
                            <li><strong>Prepared Statements:</strong> Prevents SQL injection</li>
                            <li><strong>Content Security Policy:</strong> Blocks unauthorized scripts</li>
                            <li><strong>Input Length Limits:</strong> Prevents buffer overflow</li>
                            <li><strong>HTML Sanitization:</strong> Strips dangerous tags</li>
                            <li><strong>Error Logging:</strong> Monitors suspicious activity</li>
                            <li><strong>Rate Limiting:</strong> Prevents spam (can be added)</li>
                        </ul>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header bg-primary text-white">
                        <h5>📊 Security Comparison</h5>
                    </div>
                    <div class="card-body">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>Feature</th>
                                    <th>Vulnerable</th>
                                    <th>Secure</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>Input Validation</td>
                                    <td>❌ None</td>
                                    <td>✅ Strict</td>
                                </tr>
                                <tr>
                                    <td>Output Encoding</td>
                                    <td>❌ None</td>
                                    <td>✅ HTML Encoded</td>
                                </tr>
                                <tr>
                                    <td>CSRF Protection</td>
                                    <td>❌ None</td>
                                    <td>✅ Token-based</td>
                                </tr>
                                <tr>
                                    <td>HTML Sanitization</td>
                                    <td>❌ None</td>
                                    <td>✅ Filtered</td>
                                </tr>
                                <tr>
                                    <td>Security Headers</td>
                                    <td>❌ None</td>
                                    <td>✅ Full Set</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div class="alert alert-info mt-4">
            <h5>📝 Learning Notes - Stored XSS Prevention:</h5>
            <ul>
                <li><strong>Double Protection:</strong> Sanitize on input AND encode on output</li>
                <li><strong>Context-Aware:</strong> Different encoding for different contexts</li>
                <li><strong>CSRF Protection:</strong> Prevents unauthorized comment posting</li>
                <li><strong>Input Validation:</strong> Server-side validation with strict rules</li>
                <li><strong>HTML Sanitization:</strong> Allow only safe HTML tags if needed</li>
                <li><strong>Error Handling:</strong> Graceful error handling without exposing internals</li>
                <li><strong>Logging:</strong> Monitor and log suspicious activities</li>
            </ul>
        </div>

        <div class="alert alert-secondary mt-4">
            <h5>🔄 Compare with Vulnerable Version</h5>
            <p>Test the same payloads in both applications:</p>
            <a href="http://localhost:8080/stored.php" target="_blank" class="btn btn-outline-danger">
                ⚠️ Test in Vulnerable App
            </a>
            <p class="mt-2"><small>Notice how the same inputs behave completely differently!</small></p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Client-side validation (defense in depth)
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.querySelector('form');
            const nameInput = document.getElementById('name');
            const emailInput = document.getElementById('email');
            const commentInput = document.getElementById('comment');
            
            form.addEventListener('submit', function(e) {
                let isValid = true;
                
                // Validate name (letters and spaces only)
                if (!/^[a-zA-Z\s]{2,100}$/.test(nameInput.value)) {
                    alert('Name should contain only letters and spaces (2-100 characters)');
                    isValid = false;
                }
                
                // Validate email format
                if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput.value)) {
                    alert('Please enter a valid email address');
                    isValid = false;
                }
                
                // Validate comment length
                if (commentInput.value.length < 5 || commentInput.value.length > 1000) {
                    alert('Comment must be between 5 and 1000 characters');
                    isValid = false;
                }
                
                if (!isValid) {
                    e.preventDefault();
                }
            });
        });
    </script>
</body>
</html>