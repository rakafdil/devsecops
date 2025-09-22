<?php
include 'config.php';

$error = '';
$success = '';

// Handle registration
if ($_POST && isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $email = $_POST['email'];
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    
    // Vulnerability 1: Weak password validation
    if (isWeakPassword($password)) {
        $error = "Password too weak! (But we allow it anyway)";
    }
    
    // Vulnerability 2: No password confirmation check
    // if ($password !== $confirm_password) {
    //     $error = "Passwords don't match";
    // }
    
    // Vulnerability 3: No email validation
    // No checking if email is valid format
    
    if (!$error) {
        try {
            // Vulnerability 4: Plain text password storage
            $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            $stmt->execute([$username, $email, $password]); // No hashing!
            
            $success = "Registration successful! Your password is stored in plain text.";
        } catch (PDOException $e) {
            if ($e->getCode() == 23000) { // Duplicate entry
                $error = "Username already exists";
            } else {
                $error = "Registration failed: " . $e->getMessage();
            }
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Registration - Broken Authentication Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="email"], input[type="password"] {
            width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box;
        }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .success { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .vulnerability { background: #ffebee; border: 1px solid #f44336; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 User Registration</h1>
        
        <?php if ($error): ?>
            <div class="error">Error: <?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <div class="form-group">
                <label for="confirm_password">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>
            
            <button type="submit">Register</button>
        </form>
        
        <div class="vulnerability">
            <h3>🚨 Registration Vulnerabilities:</h3>
            <ul>
                <li><strong>Weak Password Policy:</strong> Allows passwords like "a", "12", etc.</li>
                <li><strong>No Password Confirmation:</strong> Confirm password field ignored</li>
                <li><strong>Plain Text Storage:</strong> Passwords stored without hashing</li>
                <li><strong>No Email Validation:</strong> Accepts invalid email formats</li>
                <li><strong>No Rate Limiting:</strong> Unlimited registration attempts</li>
            </ul>
        </div>
        
        <p><a href="index.php">← Back to Login</a></p>
    </div>
</body>
</html>
