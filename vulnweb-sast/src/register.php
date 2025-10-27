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
    $email = $_POST['email'] ?? '';
    $role = $_POST['role'] ?? 'user';
    
    // VULNERABLE: No input validation or sanitization
    if (empty($username) || empty($password) || empty($email)) {
        $error = 'All fields are required';
    } else {
        $conn = getConnection();
        
        // VULNERABLE: SQL Injection - Direct string interpolation
        $query = "INSERT INTO users (username, password, email, role) VALUES ('$username', '$password', '$email', '$role')";
        
        if ($conn->query($query)) {
            $success = "Registration successful! You can now login with username: $username";
        } else {
            // VULNERABLE: Information disclosure - showing database errors
            $error = "Registration failed: " . $conn->error;
        }
    }
}

$title = 'Register';
include 'header.php';
?>

<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header bg-success text-white">
                <h4 class="mb-0">📝 Register</h4>
                <small>Create New Account</small>
            </div>
            <div class="card-body">
                <?php if ($error): ?>
                    <div class="alert alert-danger"><?php echo $error; ?></div>
                <?php endif; ?>
                
                <?php if ($success): ?>
                    <div class="alert alert-success">
                        <?php echo $success; ?>
                        <br><a href="login.php" class="btn btn-sm btn-primary mt-2">Login Now</a>
                    </div>
                <?php endif; ?>

                <form method="POST">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" 
                               value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" required>
                    </div>
                    
                    <div class="mb-3">
                        <label for="email" class="form-label">Email</label>
                        <input type="email" class="form-control" id="email" name="email" 
                               value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" required>
                    </div>
                    
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    
                    <!-- VULNERABLE: Role can be manipulated by user -->
                    <div class="mb-3">
                        <label for="role" class="form-label">Role</label>
                        <select class="form-control" id="role" name="role">
                            <option value="user">User</option>
                            <option value="moderator">Moderator</option>
                            <option value="admin">Administrator</option>
                        </select>
                        <small class="text-muted">Users can select their own role (vulnerability)</small>
                    </div>
                    
                    <!-- VULNERABLE: No CSRF protection -->
                    <button type="submit" class="btn btn-success">Register</button>
                    <a href="login.php" class="btn btn-outline-primary">Back to Login</a>
                </form>

                <hr>
                
                <div class="alert alert-warning">
                    <h6>🔍 SQL Injection Testing</h6>
                    <p class="mb-2">This registration form is also vulnerable. Try injecting:</p>
                    <ul class="mb-0">
                        <li>Username: <code>testuser'); DROP TABLE users; --</code></li>
                        <li>Email: <code>test@example.com'); INSERT INTO users VALUES(999,'hacker','hacked','hacker@evil.com','admin'); --</code></li>
                    </ul>
                </div>

                <div class="alert alert-info">
                    <h6>🎯 Privilege Escalation</h6>
                    <p class="mb-0">Notice that users can select their own role during registration, including 'admin'. This is a privilege escalation vulnerability.</p>
                </div>
            </div>
        </div>
    </div>
</div>

<?php if (isset($_GET['debug'])): ?>
<div class="row mt-4">
    <div class="col-12">
        <div class="alert alert-secondary">
            <h5>🐛 Debug Information</h5>
            <p><strong>POST Data:</strong></p>
            <pre><?php print_r($_POST); ?></pre>
            <p><strong>Last Query:</strong></p>
            <pre><?php echo isset($query) ? $query : 'No query executed'; ?></pre>
        </div>
    </div>
</div>
<?php endif; ?>

<?php include 'footer.php'; ?>