<?php
include 'config.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$error = '';
$success = '';

// Get current user
$currentUser = getUserByUsername($_SESSION['username']);

// Handle profile updates
if ($_POST && isset($_POST['action'])) {
    $action = $_POST['action'];
    
    if ($action === 'update_profile') {
        $new_username = $_POST['username'];
        $new_email = $_POST['email'];
        
        // Vulnerability 1: No validation of username uniqueness
        // Vulnerability 2: No email format validation
        try {
            $stmt = $pdo->prepare("UPDATE users SET username = ?, email = ? WHERE id = ?");
            $stmt->execute([$new_username, $new_email, $currentUser['id']]);
            
            // Vulnerability 3: Session not updated after username change
            // $_SESSION['username'] should be updated but it's not!
            
            $success = "Profile updated successfully!";
            // Refresh user data
            $currentUser = getUserByUsername($_SESSION['username']); // Still uses old username!
        } catch (PDOException $e) {
            $error = "Update failed: " . $e->getMessage();
        }
    }
    
    if ($action === 'change_password') {
        $old_password = $_POST['old_password'];
        $new_password = $_POST['new_password'];
        $confirm_password = $_POST['confirm_password'];
        
        // Vulnerability 4: No verification of old password
        // if ($currentUser['password'] !== $old_password) {
        //     $error = "Old password incorrect";
        // }
        
        // Vulnerability 5: No password confirmation check
        // if ($new_password !== $confirm_password) {
        //     $error = "New passwords don't match";
        // }
        
        if (!$error) {
            // Vulnerability 6: Plain text password storage
            $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
            $stmt->execute([$new_password, $currentUser['id']]);
            $success = "Password changed successfully! New password: $new_password";
        }
    }
    
    if ($action === 'escalate_privileges') {
        // Vulnerability 7: Client-side privilege escalation
        $new_role = $_POST['role'];
        
        // This should never be allowed, but here it is!
        $stmt = $pdo->prepare("UPDATE users SET role = ? WHERE id = ?");
        $stmt->execute([$new_role, $currentUser['id']]);
        
        // Update session
        $_SESSION['role'] = $new_role;
        
        $success = "Role updated to: $new_role";
    }
}

// Vulnerability 8: Expose other users' information
if (isset($_GET['user_id'])) {
    // No authorization check!
    $user_id = $_GET['user_id'];
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $viewUser = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($viewUser) {
        $currentUser = $viewUser; // Show other user's profile!
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Profile - Broken Authentication Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .profile-section { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="email"], input[type="password"], select {
            width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box;
        }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-right: 10px; }
        .btn-danger { background: #dc3545; }
        .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .success { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .vulnerability { background: #ffebee; border: 1px solid #f44336; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .session-info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>👤 User Profile</h1>
        
        <?php if ($error): ?>
            <div class="error">Error: <?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>
        
        <!-- Current User Information -->
        <div class="profile-section">
            <h2>Current Profile Information</h2>
            <p><strong>ID:</strong> <?php echo $currentUser['id']; ?></p>
            <p><strong>Username:</strong> <?php echo htmlspecialchars($currentUser['username']); ?></p>
            <p><strong>Email:</strong> <?php echo htmlspecialchars($currentUser['email']); ?></p>
            <p><strong>Password:</strong> <code><?php echo htmlspecialchars($currentUser['password']); ?></code></p>
            <p><strong>Role:</strong> <?php echo htmlspecialchars($currentUser['role']); ?></p>
            <p><strong>Failed Login Attempts:</strong> <?php echo $currentUser['failed_login_attempts']; ?></p>
            <p><strong>Last Login:</strong> <?php echo $currentUser['last_login']; ?></p>
            <p><strong>Created:</strong> <?php echo $currentUser['created_at']; ?></p>
        </div>
        
        <!-- Session Information -->
        <div class="session-info">
            <h3>🔍 Session Information</h3>
            <p><strong>Session ID:</strong> <code><?php echo session_id(); ?></code></p>
            <p><strong>Session Data:</strong></p>
            <pre><?php print_r($_SESSION); ?></pre>
        </div>
        
        <!-- Update Profile Form -->
        <div class="profile-section">
            <h2>Update Profile</h2>
            <form method="POST" action="">
                <input type="hidden" name="action" value="update_profile">
                
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($currentUser['username']); ?>">
                </div>
                
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($currentUser['email']); ?>">
                </div>
                
                <button type="submit">Update Profile</button>
            </form>
        </div>
        
        <!-- Change Password Form -->
        <div class="profile-section">
            <h2>Change Password</h2>
            <form method="POST" action="">
                <input type="hidden" name="action" value="change_password">
                
                <div class="form-group">
                    <label for="old_password">Old Password:</label>
                    <input type="password" id="old_password" name="old_password" placeholder="Not verified anyway">
                </div>
                
                <div class="form-group">
                    <label for="new_password">New Password:</label>
                    <input type="password" id="new_password" name="new_password">
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm Password:</label>
                    <input type="password" id="confirm_password" name="confirm_password" placeholder="Not checked anyway">
                </div>
                
                <button type="submit">Change Password</button>
            </form>
        </div>
        
        <!-- Privilege Escalation Form -->
        <div class="profile-section">
            <h2>🚨 Change Role (Should NOT be here!)</h2>
            <form method="POST" action="">
                <input type="hidden" name="action" value="escalate_privileges">
                
                <div class="form-group">
                    <label for="role">Role:</label>
                    <select id="role" name="role">
                        <option value="user" <?php echo $currentUser['role'] === 'user' ? 'selected' : ''; ?>>User</option>
                        <option value="moderator" <?php echo $currentUser['role'] === 'moderator' ? 'selected' : ''; ?>>Moderator</option>
                        <option value="admin" <?php echo $currentUser['role'] === 'admin' ? 'selected' : ''; ?>>Admin</option>
                    </select>
                </div>
                
                <button type="submit" class="btn-danger">Change Role</button>
            </form>
        </div>
        
        <div class="vulnerability">
            <h3>🚨 Profile Management Vulnerabilities:</h3>
            <ul>
                <li><strong>Insecure Direct Object References:</strong> Can view other users via ?user_id=X</li>
                <li><strong>Password Exposure:</strong> Plain text password displayed</li>
                <li><strong>No Old Password Verification:</strong> Can change password without knowing current one</li>
                <li><strong>Session Inconsistency:</strong> Username change doesn't update session</li>
                <li><strong>Client-Side Privilege Escalation:</strong> User can change their own role</li>
                <li><strong>No CSRF Protection:</strong> All forms vulnerable to CSRF attacks</li>
                <li><strong>Information Disclosure:</strong> Session data exposed to user</li>
                <li><strong>No Input Validation:</strong> No checks on username/email format</li>
            </ul>
        </div>
        
        <div style="margin-top: 30px;">
            <h3>🎯 Attack Scenarios:</h3>
            <ol>
                <li><strong>IDOR:</strong> Try <code>profile.php?user_id=1</code> to view admin profile</li>
                <li><strong>Privilege Escalation:</strong> Change role to 'admin' using the form</li>
                <li><strong>Session Hijacking:</strong> Extract session ID from displayed information</li>
                <li><strong>Password Reset:</strong> Change password without knowing current one</li>
            </ol>
            
            <h3>🔧 Test URLs:</h3>
            <ul>
                <li><a href="profile.php?user_id=1">View Admin Profile (ID=1)</a></li>
                <li><a href="profile.php?user_id=2">View User Profile (ID=2)</a></li>
                <li><a href="profile.php?user_id=3">View User Profile (ID=3)</a></li>
            </ul>
        </div>
        
        <p>
            <a href="index.php">← Back to Dashboard</a> | 
            <a href="admin.php">Admin Panel</a> |
            <a href="logout.php">Logout</a>
        </p>
    </div>
    
    <script>
        // Vulnerability: Session manipulation via JavaScript
        console.log("Session ID:", "<?php echo session_id(); ?>");
        console.log("User Role:", "<?php echo $_SESSION['role']; ?>");
        
        // Example: Modify session data (if XSS exists)
        function escalatePrivileges() {
            // This would work if there's an XSS vulnerability
            document.cookie = "role=admin; path=/";
            alert("Role escalation attempted via JavaScript!");
        }
        
        // Add button for demonstration
        setTimeout(() => {
            const escalateBtn = document.createElement('button');
            escalateBtn.innerHTML = '🚨 JS Privilege Escalation Demo';
            escalateBtn.onclick = escalatePrivileges;
            escalateBtn.style.background = '#dc3545';
            escalateBtn.style.color = 'white';
            escalateBtn.style.padding = '10px';
            escalateBtn.style.border = 'none';
            escalateBtn.style.borderRadius = '5px';
            escalateBtn.style.cursor = 'pointer';
            escalateBtn.style.marginTop = '20px';
            
            document.querySelector('.container').appendChild(escalateBtn);
        }, 1000);
    </script>
</body>
</html>
