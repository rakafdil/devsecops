<?php
include 'config.php';

$error = '';
$success = '';

// Vulnerability 1: Session Fixation
if (isset($_GET['sessionid'])) {
    session_id($_GET['sessionid']); // Vulnerable: Allows session fixation
    session_start();
}

// Handle login
if ($_POST && isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $ip = getClientIP();
    
    // Vulnerability 2: No rate limiting, allows brute force
    $user = getUserByUsername($username);
    
    if ($user) {
        // Vulnerability 3: Plain text password comparison
        if ($user['password'] === $password) {
            // Successful login
            logLoginAttempt($username, $ip, true);
            updateLoginAttempts($username, false);
            
            // Vulnerability 4: Predictable session management
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['login_time'] = time();
            
            // Vulnerability 5: Session not regenerated after login
            // session_regenerate_id(); // This should be here but it's missing!
            
            $success = "Login successful! Welcome " . htmlspecialchars($user['username']);
        } else {
            // Failed login
            logLoginAttempt($username, $ip, false);
            updateLoginAttempts($username, true);
            $error = "Invalid credentials";
        }
    } else {
        logLoginAttempt($username, $ip, false);
        $error = "Invalid credentials";
    }
}

// Check if user is logged in
$isLoggedIn = isset($_SESSION['user_id']);
$currentUser = null;
if ($isLoggedIn) {
    $currentUser = getUserByUsername($_SESSION['username']);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Broken Authentication Demo</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .vulnerability {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .success {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .error {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }
        button {
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            margin-right: 10px;
        }
        button:hover {
            background-color: #0056b3;
        }
        .logout-btn {
            background-color: #dc3545;
        }
        .logout-btn:hover {
            background-color: #c82333;
        }
        .session-info {
            background-color: #e7f3ff;
            border: 1px solid #bee5eb;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .user-info {
            background-color: #e7f3ff;
            border: 1px solid #bee5eb;
            padding: 15px;
            border-radius: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        .attack-examples {
            background-color: #fff;
            border: 2px solid #dc3545;
            padding: 20px;
            border-radius: 5px;
            margin-top: 30px;
        }
        .payload {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 Broken Authentication & Session Management Demo</h1>
        
        <div class="warning">
            <strong>⚠️ WARNING:</strong> This application contains multiple authentication vulnerabilities for educational purposes only. 
            <strong>DO NOT</strong> use any of these patterns in production!
        </div>

        <?php if ($error): ?>
            <div class="error">
                <strong>Error:</strong> <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="success">
                <strong>Success:</strong> <?php echo $success; ?>
            </div>
        <?php endif; ?>

        <?php if (!$isLoggedIn): ?>
            <!-- Login Form -->
            <h2>Login</h2>
            <form method="POST" action="">
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

            <!-- Common Credentials for Testing -->
            <div style="margin-top: 30px;">
                <h3>🔍 Test Credentials (Weak Passwords!):</h3>
                <table>
                    <tr><th>Username</th><th>Password</th><th>Role</th></tr>
                    <tr><td>admin</td><td>admin</td><td>Admin</td></tr>
                    <tr><td>john</td><td>password</td><td>User</td></tr>
                    <tr><td>jane</td><td>123456</td><td>User</td></tr>
                    <tr><td>bob</td><td>qwerty</td><td>User</td></tr>
                    <tr><td>charlie</td><td>password123</td><td>Moderator</td></tr>
                </table>
            </div>
        <?php else: ?>
            <!-- User Dashboard -->
            <div class="success">
                <h2>✅ Logged in as: <?php echo htmlspecialchars($currentUser['username']); ?></h2>
            </div>

            <div class="user-info">
                <h3>User Information:</h3>
                <p><strong>ID:</strong> <?php echo $currentUser['id']; ?></p>
                <p><strong>Username:</strong> <?php echo htmlspecialchars($currentUser['username']); ?></p>
                <p><strong>Email:</strong> <?php echo htmlspecialchars($currentUser['email']); ?></p>
                <p><strong>Role:</strong> <?php echo htmlspecialchars($currentUser['role']); ?></p>
                <p><strong>Last Login:</strong> <?php echo $currentUser['last_login']; ?></p>
                <p><strong>Failed Attempts:</strong> <?php echo $currentUser['failed_login_attempts']; ?></p>
            </div>

            <div class="session-info">
                <h3>🔍 Session Information (Exposed for Educational Purposes):</h3>
                <p><strong>Session ID:</strong> <code><?php echo session_id(); ?></code></p>
                <p><strong>Session Data:</strong></p>
                <pre><?php print_r($_SESSION); ?></pre>
            </div>

            <a href="logout.php"><button class="logout-btn">Logout</button></a>
            <a href="profile.php"><button>View Profile</button></a>
            <a href="admin.php"><button>Admin Panel</button></a>
        <?php endif; ?>

        <!-- Vulnerability Demonstrations -->
        <div class="attack-examples">
            <h2>🚨 Identified Vulnerabilities & Attack Examples</h2>
            
            <div class="vulnerability">
                <h3>1. Session Fixation</h3>
                <p><strong>Vulnerability:</strong> Application accepts session ID from URL parameter</p>
                <div class="payload">
                    Test URL: <?php echo "http://localhost:8081/index.php?sessionid=ATTACKER_SESSION_ID"; ?>
                </div>
                <p><strong>Impact:</strong> Attacker can fixate session ID and hijack user session after login</p>
            </div>

            <div class="vulnerability">
                <h3>2. Weak Password Policy</h3>
                <p><strong>Vulnerability:</strong> No password complexity requirements</p>
                <div class="payload">
                    Common passwords: admin, password, 123456, qwerty
                </div>
                <p><strong>Impact:</strong> Easy brute force and dictionary attacks</p>
            </div>

            <div class="vulnerability">
                <h3>3. Plain Text Password Storage</h3>
                <p><strong>Vulnerability:</strong> Passwords stored without hashing</p>
                <div class="payload">
                    Database: SELECT password FROM users; -- Shows plain text passwords
                </div>
                <p><strong>Impact:</strong> Complete credential exposure if database is compromised</p>
            </div>

            <div class="vulnerability">
                <h3>4. No Rate Limiting</h3>
                <p><strong>Vulnerability:</strong> Unlimited login attempts allowed</p>
                <div class="payload">
                    Brute force tool: hydra -l admin -P passwords.txt http://localhost:8081
                </div>
                <p><strong>Impact:</strong> Successful brute force attacks</p>
            </div>

            <div class="vulnerability">
                <h3>5. Insecure Session Management</h3>
                <p><strong>Vulnerability:</strong> Session ID not regenerated after login</p>
                <div class="payload">
                    Session Cookie: HttpOnly=false, Secure=false
                </div>
                <p><strong>Impact:</strong> Session hijacking via XSS or network interception</p>
            </div>

            <div class="vulnerability">
                <h3>6. Predictable Session IDs</h3>
                <p><strong>Vulnerability:</strong> Session IDs generated with weak randomness</p>
                <div class="payload">
                    Pattern: md5(timestamp + small_random_number)
                </div>
                <p><strong>Impact:</strong> Session prediction and hijacking</p>
            </div>
        </div>

        <div style="margin-top: 30px;">
            <h3>🔗 Additional Vulnerable Endpoints:</h3>
            <ul>
                <li><a href="register.php">Registration (Weak validation)</a></li>
                <li><a href="forgot-password.php">Password Reset (Predictable tokens)</a></li>
                <li><a href="profile.php">Profile Management (Session issues)</a></li>
                <li><a href="admin.php">Admin Panel (Privilege escalation)</a></li>
            </ul>
        </div>
    </div>

    <script>
        // Vulnerability: Session ID exposed to JavaScript
        console.log("Session ID exposed in JS:", "<?php echo session_id(); ?>");
        
        // Demonstrate session cookie access
        console.log("All cookies:", document.cookie);
    </script>
</body>
</html>
