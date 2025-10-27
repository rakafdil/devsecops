<?php
require_once 'config.php';

if (isLoggedIn()) {
    redirect('index.php');
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        $error = 'Please fill in all fields.';
    } else {
        $pdo = getConnection();
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            redirect('index.php');
        } else {
            $error = 'Invalid username or password.';
        }
    }
}

include 'header.php';
?>

<h2>Login</h2>

<?php if ($error): ?>
    <div class="alert alert-danger"><?php echo sanitizeInput($error); ?></div>
<?php endif; ?>

<form method="POST">
    <div class="form-group">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
    </div>
    
    <div class="form-group">
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
    </div>
    
    <button type="submit">Login</button>
</form>

<p>Don't have an account? <a href="register.php">Register here</a></p>

<div class="vulnerability-info">
    <h3>🔍 Test Accounts</h3>
    <div class="code-example">
        <strong>Admin:</strong> admin / password<br>
        <strong>User:</strong> john_doe / password<br>
        <strong>Moderator:</strong> jane_smith / password
    </div>
</div>

<?php include 'footer.php'; ?>