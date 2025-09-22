<?php
include 'config.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$currentUser = getUserByUsername($_SESSION['username']);

// Vulnerability 1: No proper role-based access control
// This should check if user is admin, but it doesn't!
$isAdmin = $_SESSION['role'] === 'admin'; // Can be manipulated!

// Handle user management actions
if ($_POST && isset($_POST['action'])) {
    $action = $_POST['action'];
    
    if ($action === 'promote_user' && isset($_POST['user_id'])) {
        // Vulnerability 2: No authorization check for critical actions
        $user_id = $_POST['user_id'];
        $stmt = $pdo->prepare("UPDATE users SET role = 'admin' WHERE id = ?");
        $stmt->execute([$user_id]);
        $message = "User promoted to admin!";
    }
    
    if ($action === 'delete_user' && isset($_POST['user_id'])) {
        // Vulnerability 3: No confirmation for destructive actions
        $user_id = $_POST['user_id'];
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $message = "User deleted!";
    }
    
    if ($action === 'reset_password' && isset($_POST['user_id'])) {
        // Vulnerability 4: Admin can set any password without validation
        $user_id = $_POST['user_id'];
        $new_password = $_POST['new_password'] ?? 'admin123';
        $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->execute([$new_password, $user_id]);
        $message = "Password reset to: $new_password";
    }
}

// Get all users
$stmt = $pdo->query("SELECT * FROM users ORDER BY id");
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get login statistics
$stmt = $pdo->query("SELECT * FROM user_login_stats");
$stats = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - Broken Authentication Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        button { padding: 5px 10px; margin: 2px; border: none; border-radius: 3px; cursor: pointer; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-warning { background: #ffc107; color: black; }
        .btn-info { background: #17a2b8; color: white; }
        .vulnerability { background: #ffebee; border: 1px solid #f44336; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .message { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .access-denied { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Admin Panel</h1>
        
        <div class="warning">
            <strong>Current User:</strong> <?php echo htmlspecialchars($currentUser['username']); ?> 
            (Role: <?php echo htmlspecialchars($currentUser['role']); ?>)
        </div>
        
        <?php if (isset($message)): ?>
            <div class="message"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        
        <?php if (!$isAdmin): ?>
            <div class="access-denied">
                <h3>⚠️ Access Denied</h3>
                <p>You don't have admin privileges. But the page still loads...</p>
                <p><strong>Vulnerability:</strong> Improper access control implementation</p>
            </div>
        <?php endif; ?>
        
        <!-- This section loads regardless of admin status - VULNERABILITY! -->
        <h2>👥 User Management</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Password</th>
                <th>Role</th>
                <th>Failed Attempts</th>
                <th>Last Login</th>
                <th>Actions</th>
            </tr>
            <?php foreach ($users as $user): ?>
                <tr>
                    <td><?php echo $user['id']; ?></td>
                    <td><?php echo htmlspecialchars($user['username']); ?></td>
                    <td><?php echo htmlspecialchars($user['email']); ?></td>
                    <td><code><?php echo htmlspecialchars($user['password']); ?></code></td>
                    <td><?php echo htmlspecialchars($user['role']); ?></td>
                    <td><?php echo $user['failed_login_attempts']; ?></td>
                    <td><?php echo $user['last_login']; ?></td>
                    <td>
                        <form method="POST" style="display: inline;">
                            <input type="hidden" name="action" value="promote_user">
                            <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                            <button type="submit" class="btn-warning">Promote to Admin</button>
                        </form>
                        
                        <form method="POST" style="display: inline;">
                            <input type="hidden" name="action" value="reset_password">
                            <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                            <input type="text" name="new_password" placeholder="New password" style="width: 80px;">
                            <button type="submit" class="btn-info">Reset Password</button>
                        </form>
                        
                        <form method="POST" style="display: inline;">
                            <input type="hidden" name="action" value="delete_user">
                            <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                            <button type="submit" class="btn-danger" onclick="return true;">Delete</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
        </table>
        
        <h2>📊 Login Statistics</h2>
        <table>
            <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Total Attempts</th>
                <th>Successful</th>
                <th>Failed</th>
                <th>Current Failed Count</th>
                <th>Last Login</th>
            </tr>
            <?php foreach ($stats as $stat): ?>
                <tr>
                    <td><?php echo htmlspecialchars($stat['username']); ?></td>
                    <td><?php echo htmlspecialchars($stat['email']); ?></td>
                    <td><?php echo $stat['total_login_attempts']; ?></td>
                    <td><?php echo $stat['successful_logins']; ?></td>
                    <td><?php echo $stat['failed_logins']; ?></td>
                    <td><?php echo $stat['failed_login_attempts']; ?></td>
                    <td><?php echo $stat['last_login']; ?></td>
                </tr>
            <?php endforeach; ?>
        </table>
        
        <div class="vulnerability">
            <h3>🚨 Admin Panel Vulnerabilities:</h3>
            <ul>
                <li><strong>Insecure Direct Object References:</strong> User IDs directly exposed in forms</li>
                <li><strong>Missing Function Level Access Control:</strong> Non-admin users can access admin functions</li>
                <li><strong>No CSRF Protection:</strong> All forms vulnerable to cross-site request forgery</li>
                <li><strong>Password Exposure:</strong> Plain text passwords visible in admin panel</li>
                <li><strong>No Confirmation:</strong> Critical actions (delete, promote) executed without confirmation</li>
                <li><strong>Session Role Manipulation:</strong> Role stored in session can be modified</li>
                <li><strong>Information Disclosure:</strong> Sensitive statistics exposed to all users</li>
            </ul>
        </div>
        
        <div style="margin-top: 30px;">
            <h3>🎯 Attack Scenarios:</h3>
            <ol>
                <li><strong>Privilege Escalation:</strong> Modify session role via browser tools</li>
                <li><strong>IDOR:</strong> Change user_id parameters to affect other users</li>
                <li><strong>CSRF:</strong> Trick admin into executing malicious forms</li>
                <li><strong>Session Manipulation:</strong> Modify $_SESSION['role'] via XSS</li>
            </ol>
            
            <h3>🔧 Test Commands:</h3>
            <p><strong>Modify session in browser console:</strong></p>
            <code>document.cookie = "PHPSESSID=<?php echo session_id(); ?>; role=admin"</code>
        </div>
        
        <p>
            <a href="index.php">← Back to Dashboard</a> | 
            <a href="profile.php">View Profile</a> |
            <a href="logout.php">Logout</a>
        </p>
    </div>
</body>
</html>
