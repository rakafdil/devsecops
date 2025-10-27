<?php
ob_start();
require_once 'config.php';

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// VULNERABLE: No authentication check for viewing comments
$product_id = $_GET['product_id'] ?? 1;

$error = '';
$success = '';

// Handle comment submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isLoggedIn()) {
    $comment = $_POST['comment'] ?? '';
    $user_id = $_SESSION['user_id'];
    
    if (!empty($comment)) {
        $conn = getConnection();
        
        // VULNERABLE: No input sanitization - XSS vulnerability
        // VULNERABLE: SQL Injection through direct interpolation
        $query = "INSERT INTO comments (user_id, product_id, comment) VALUES ($user_id, $product_id, '$comment')";
        
        if ($conn->query($query)) {
            $success = 'Comment added successfully!';
        } else {
            $error = 'Failed to add comment: ' . $conn->error;
        }
    } else {
        $error = 'Comment cannot be empty!';
    }
}

$title = 'Comments';
include 'header.php';
?>

<div class="row">
    <div class="col-md-8">
        <h3>💬 Product Comments</h3>
        
        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo $error; ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo $success; ?></div>
        <?php endif; ?>

        <!-- Product Selection -->
        <div class="card mb-4">
            <div class="card-header">
                <h5>Select Product</h5>
            </div>
            <div class="card-body">
                <form method="GET" action="comments.php">
                    <div class="row">
                        <div class="col-md-8">
                            <select class="form-control" name="product_id" onchange="this.form.submit()">
                                <?php
                                $conn = getConnection();
                                $products_query = "SELECT id, name FROM products ORDER BY name";
                                $products_result = $conn->query($products_query);
                                
                                while ($product = $products_result->fetch_assoc()) {
                                    $selected = $product['id'] == $product_id ? 'selected' : '';
                                    echo "<option value='{$product['id']}' $selected>{$product['name']}</option>";
                                }
                                ?>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <button type="submit" class="btn btn-primary">View Comments</button>
                        </div>
                    </div>
                </form>
            </div>
        </div>

        <!-- Add Comment Form -->
        <?php if (isLoggedIn()): ?>
        <div class="card mb-4">
            <div class="card-header">
                <h5>💭 Add Your Comment</h5>
            </div>
            <div class="card-body">
                <!-- VULNERABLE: No CSRF protection -->
                <form method="POST">
                    <div class="mb-3">
                        <textarea class="form-control" name="comment" rows="4" 
                                  placeholder="Share your thoughts about this product..." required></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Post Comment</button>
                </form>
                
                <div class="alert alert-warning mt-3">
                    <h6>🎯 XSS Testing Payloads</h6>
                    <p class="mb-2">Try these XSS payloads in the comment field:</p>
                    <ul class="mb-0 small">
                        <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
                        <li><code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                        <li><code>&lt;svg onload=alert('XSS')&gt;</code></li>
                        <li><code>&lt;iframe src=javascript:alert('XSS')&gt;&lt;/iframe&gt;</code></li>
                    </ul>
                </div>
            </div>
        </div>
        <?php else: ?>
        <div class="alert alert-info">
            <p class="mb-0">Please <a href="login.php">login</a> to post comments.</p>
        </div>
        <?php endif; ?>

        <!-- Display Comments -->
        <div class="card">
            <div class="card-header">
                <h5>📝 Comments</h5>
            </div>
            <div class="card-body">
                <?php
                $conn = getConnection();
                
                // Get product name
                $product_query = "SELECT name FROM products WHERE id = $product_id";
                $product_result = $conn->query($product_query);
                $product_name = $product_result ? $product_result->fetch_assoc()['name'] : 'Unknown Product';
                
                echo "<h6>Comments for: " . htmlspecialchars($product_name) . "</h6><hr>";
                
                // VULNERABLE: SQL Injection in comments query
                $comments_query = "SELECT c.*, u.username FROM comments c 
                                 JOIN users u ON c.user_id = u.id 
                                 WHERE c.product_id = $product_id 
                                 ORDER BY c.created_at DESC";
                
                if (isset($_GET['debug'])) {
                    echo "<div class='alert alert-info'><strong>Query:</strong> <code>$comments_query</code></div>";
                }
                
                $comments_result = $conn->query($comments_query);
                
                if ($comments_result && $comments_result->num_rows > 0) {
                    while ($comment = $comments_result->fetch_assoc()) {
                        ?>
                        <div class="card mb-3">
                            <div class="card-header d-flex justify-content-between">
                                <strong><?php echo htmlspecialchars($comment['username']); ?></strong>
                                <small class="text-muted"><?php echo date('M j, Y H:i', strtotime($comment['created_at'])); ?></small>
                            </div>
                            <div class="card-body">
                                <!-- VULNERABLE: Direct output without escaping - XSS vulnerability -->
                                <p><?php echo $comment['comment']; ?></p>
                            </div>
                        </div>
                        <?php
                    }
                } else {
                    echo "<div class='alert alert-info'>No comments yet for this product. Be the first to comment!</div>";
                }
                ?>
            </div>
        </div>
    </div>

    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h5>🎯 XSS Vulnerability Info</h5>
            </div>
            <div class="card-body">
                <p class="text-muted">This comment system is vulnerable to both:</p>
                <ul>
                    <li><strong>Stored XSS:</strong> Malicious scripts stored in database</li>
                    <li><strong>Reflected XSS:</strong> Scripts reflected in error messages</li>
                </ul>
                
                <h6>Common XSS Vectors:</h6>
                <ul class="small">
                    <li>Script tags</li>
                    <li>Event handlers (onclick, onload, etc.)</li>
                    <li>JavaScript URLs</li>
                    <li>HTML injection</li>
                    <li>CSS expression injection</li>
                </ul>
            </div>
        </div>

        <div class="card mt-3">
            <div class="card-header">
                <h5>🛡️ Defense Mechanisms</h5>
            </div>
            <div class="card-body">
                <p class="text-muted">Proper defenses would include:</p>
                <ul class="small">
                    <li>Input validation and sanitization</li>
                    <li>Output encoding/escaping</li>
                    <li>Content Security Policy (CSP)</li>
                    <li>HTTP-only cookies</li>
                    <li>X-XSS-Protection header</li>
                </ul>
            </div>
        </div>

        <!-- VULNERABLE: Information disclosure -->
        <?php if (isset($_GET['debug'])): ?>
        <div class="card mt-3">
            <div class="card-header">
                <h5>🐛 Debug Info</h5>
            </div>
            <div class="card-body">
                <p><strong>Current User:</strong></p>
                <pre><?php print_r(getCurrentUser()); ?></pre>
                <p><strong>Session Data:</strong></p>
                <pre><?php print_r($_SESSION); ?></pre>
            </div>
        </div>
        <?php endif; ?>
    </div>
</div>

<?php include 'footer.php'; ?>