<?php
include 'config.php';

// Simple logout - but with session fixation vulnerability
if (isset($_SESSION['user_id'])) {
    // Vulnerability: Session data cleared but session ID not destroyed
    $_SESSION = array();

    // This should be done but it's missing:
    // session_destroy();
    // session_regenerate_id();

    $message = "You have been logged out. But session ID remains the same!";
} else {
    $message = "You were not logged in.";
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Logout - Broken Authentication Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .message { background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .vulnerability { background: #ffebee; border: 1px solid #f44336; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Logout</h1>
        
        <div class="message">
            <?php echo htmlspecialchars($message); ?>
        </div>
        
        <div class="vulnerability">
            <h3>🚨 Vulnerability: Incomplete Logout</h3>
            <p><strong>Issue:</strong> Session data cleared but session ID preserved</p>
            <p><strong>Current Session ID:</strong> <code><?php echo session_id(); ?></code></p>
            <p><strong>Risk:</strong> Session can be reused if user logs back in</p>
        </div>
        
        <a href="index.php">← Back to Login</a>
    </div>
</body>
</html>
