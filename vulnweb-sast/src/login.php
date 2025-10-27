<?php
ob_start();
require_once 'config.php';

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // VULNERABLE: No input validation or sanitization
    if (empty($username) || empty($password)) {
        $error = 'Username and password are required';
    } else {
        // VULNERABLE: SQL Injection in authenticate function
        $user = authenticate($username, $password);
        
        if ($user) {
            createSession($user);
            $_SESSION['message'] = 'Login successful! Welcome back, ' . $user['username'];
            header('Location: index.php');
            exit;
        } else {
            // VULNERABLE: Information disclosure
            $error = "Login failed for user: $username. Check your credentials.";
        }
    }
}

$title = 'Login';
include 'header.php';
?>

<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header bg-primary text-white">
                <h4 class="mb-0">🔐 Login</h4>
                <small>Vulnerable Authentication System</small>
            </div>
            <div class="card-body">
                <?php if ($error): ?>
                    <div class="alert alert-danger"><?php echo $error; ?></div>
                <?php endif; ?>
                
                <?php if ($success): ?>
                    <div class="alert alert-success"><?php echo $success; ?></div>
                <?php endif; ?>

                <form method="POST" onsubmit="return validateForm(this)">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" 
                               value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" required>
                    </div>
                    
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    
                    <!-- VULNERABLE: No CSRF protection -->
                    <button type="submit" class="btn btn-primary">Login</button>
                    <a href="register.php" class="btn btn-outline-secondary">Register</a>
                </form>

                <hr>
                
                <div class="alert alert-info">
                    <h6>🎯 Testing Credentials</h6>
                    <p class="mb-2">For educational purposes, you can use these test accounts:</p>
                    <ul class="mb-0">
                        <li><strong>Admin:</strong> admin / admin123</li>
                        <li><strong>User:</strong> user1 / password123</li>
                        <li><strong>Moderator:</strong> moderator / mod123</li>
                    </ul>
                </div>

                <div class="alert alert-warning">
                    <h6>🔍 SQL Injection Hints</h6>
                    <p class="mb-2">This login form is vulnerable to SQL injection. Try:</p>
                    <ul class="mb-0">
                        <li>Username: <code>' OR '1'='1</code></li>
                        <li>Username: <code>admin'--</code></li>
                        <li>Username: <code>' UNION SELECT 1,2,3,4,5--</code></li>
                    </ul>
                </div>
            </div>
        </div>

        <!-- VULNERABLE: Password reset without proper validation -->
        <div class="card mt-3">
            <div class="card-header">
                <h5>🔄 Password Reset</h5>
            </div>
            <div class="card-body">
                <form method="GET" action="reset_password.php">
                    <div class="mb-3">
                        <label for="reset_username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="reset_username" name="username" 
                               placeholder="Enter username for password reset">
                    </div>
                    <button type="submit" class="btn btn-warning btn-sm">Reset Password</button>
                </form>
            </div>
        </div>
    </div>
</div>

<?php if (isset($_GET['debug'])): ?>
<div class="row mt-4">
    <div class="col-12">
        <div class="alert alert-secondary">
            <h5>🐛 Debug Information</h5>
            <p><strong>Current Session:</strong></p>
            <pre><?php print_r($_SESSION); ?></pre>
            <p><strong>POST Data:</strong></p>
            <pre><?php print_r($_POST); ?></pre>
        </div>
    </div>
</div>
<?php endif; ?>

<?php include 'footer.php'; ?>