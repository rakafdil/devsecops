<?php
require_once 'config.php';

if (isLoggedIn()) {
    redirect('index.php');
}

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $email = trim($_POST['email'] ?? '');
    
    if (empty($username) || empty($password) || empty($email)) {
        $error = 'Please fill in all fields.';
    } else {
        $pdo = getConnection();
        
        // Check if username already exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);
        if ($stmt->fetch()) {
            $error = 'Username already exists.';
        } else {
            // Create new user
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
            
            if ($stmt->execute([$username, $hashedPassword, $email])) {
                $success = 'Account created successfully! You can now login.';
            } else {
                $error = 'Registration failed. Please try again.';
            }
        }
    }
}

include 'header.php';
?>

<h2>Register</h2>

<?php if ($success): ?>
    <div class="alert alert-success"><?php echo sanitizeInput($success); ?></div>
<?php endif; ?>

<?php if ($error): ?>
    <div class="alert alert-danger"><?php echo sanitizeInput($error); ?></div>
<?php endif; ?>

<form method="POST">
    <div class="form-group">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required value="<?php echo sanitizeInput($_POST['username'] ?? ''); ?>">
    </div>
    
    <div class="form-group">
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" required value="<?php echo sanitizeInput($_POST['email'] ?? ''); ?>">
    </div>
    
    <div class="form-group">
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
    </div>
    
    <button type="submit">Register</button>
</form>

<p>Already have an account? <a href="login.php">Login here</a></p>

<?php include 'footer.php'; ?>