<?php
include 'config.php';

$error = '';
$success = '';
$step = $_GET['step'] ?? 1;

// Handle password reset request
if ($_POST && $step == 1) {
    $username = $_POST['username'];
    $user = getUserByUsername($username);

    if ($user) {
        // Vulnerability 1: Predictable reset tokens (6-digit numbers)
        $token = sprintf("%06d", rand(1, 999999)); // Very predictable!
        $expires = date('Y-m-d H:i:s', time() + 3600); // 1 hour

        // Store token
        $stmt = $pdo->prepare("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)");
        $stmt->execute([$user['id'], $token, $expires]);

        // Vulnerability 2: Token disclosed in response
        $success = "Password reset token generated: <strong>$token</strong><br>";
        $success .= "Token expires at: $expires<br>";
        $success .= "<a href='?step=2&token=$token'>Use this token to reset password</a>";
    } else {
        // Vulnerability 3: Username enumeration
        $error = "Username '$username' not found in our system";
    }
}

// Handle password reset
if ($_POST && $step == 2) {
    $token = $_POST['token'];
    $new_password = $_POST['new_password'];

    // Find token
    $stmt = $pdo->prepare("SELECT * FROM password_reset_tokens WHERE token = ? AND used = 0 AND expires_at > NOW()");
    $stmt->execute([$token]);
    $reset_token = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($reset_token) {
        // Vulnerability 4: No password strength validation during reset
        $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->execute([$new_password, $reset_token['user_id']]); // Plain text again!

        // Mark token as used
        $stmt = $pdo->prepare("UPDATE password_reset_tokens SET used = 1 WHERE id = ?");
        $stmt->execute([$reset_token['id']]);

        $success = "Password reset successful! New password: <strong>$new_password</strong>";
    } else {
        $error = "Invalid or expired token";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Password Reset - Broken Authentication Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] {
            width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box;
        }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .success { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .vulnerability { background: #ffebee; border: 1px solid #f44336; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .token-demo { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 Password Reset</h1>
        
        <?php if ($error): ?>
                <div class="error">Error: <?php echo $error; ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
                <div class="success"><?php echo $success; ?></div>
        <?php endif; ?>
        
        <?php if ($step == 1): ?>
                <!-- Step 1: Request Reset Token -->
                <h2>Step 1: Request Password Reset</h2>
                <form method="POST" action="">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <button type="submit">Generate Reset Token</button>
                </form>
            
                <div class="token-demo">
                    <h3>🔍 Demo: Common Tokens Generated</h3>
                    <p>This system generates predictable 6-digit tokens:</p>
                    <ul>
                        <li>123456</li>
                        <li>654321</li>
                        <li>111111</li>
                        <li>000001</li>
                        <li>999999</li>
                    </ul>
                    <p><strong>Try brute forcing these common tokens!</strong></p>
                </div>
            
        <?php elseif ($step == 2): ?>
                <!-- Step 2: Reset Password -->
                <h2>Step 2: Reset Password</h2>
                <form method="POST" action="?step=2">
                    <div class="form-group">
                        <label for="token">Reset Token:</label>
                        <input type="text" id="token" name="token" value="<?php echo htmlspecialchars($_GET['token'] ?? ''); ?>" required>
                    </div>
                    <div class="form-group">
                        <label for="new_password">New Password:</label>
                        <input type="password" id="new_password" name="new_password" required>
                    </div>
                    <button type="submit">Reset Password</button>
                </form>
        <?php endif; ?>
        
        <div class="vulnerability">
            <h3>🚨 Password Reset Vulnerabilities:</h3>
            <ul>
                <li><strong>Predictable Tokens:</strong> 6-digit sequential numbers</li>
                <li><strong>Token Disclosure:</strong> Token shown in response and URL</li>
                <li><strong>Username Enumeration:</strong> Different errors for valid/invalid users</li>
                <li><strong>No Rate Limiting:</strong> Unlimited token generation/validation attempts</li>
                <li><strong>Weak Password Policy:</strong> No validation during reset</li>
                <li><strong>Plain Text Storage:</strong> New passwords stored without hashing</li>
            </ul>
        </div>
        
        <div style="margin-top: 30px;">
            <h3>🎯 Attack Scenarios:</h3>
            <ol>
                <li><strong>Token Brute Force:</strong> Try common 6-digit patterns</li>
                <li><strong>Username Enumeration:</strong> Identify valid usernames</li>
                <li><strong>Token Prediction:</strong> Generate tokens and predict others</li>
            </ol>
        </div>
        
        <p><a href="index.php">← Back to Login</a></p>
    </div>
</body>
</html>
