<?php
require_once 'config.php';
requireLogin();

// VULNERABILITY: Missing Function Level Access Control
// This page doesn't properly check if the user has admin privileges
$current_user = getCurrentUser();

// Weak check - can be bypassed by manipulating session or URL parameters
if (!isAdmin()) {
    // VULNERABILITY: This warning can be ignored or bypassed
    echo "<div class='alert alert-warning'>⚠️ You don't have admin privileges, but the page loads anyway!</div>";
}

$message = '';
$error = '';

// Handle admin actions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'];
    $target_user_id = $_POST['user_id'] ?? 0;
    
    $pdo = getConnection();
    
    switch ($action) {
        case 'delete_user':
            // VULNERABILITY: No proper authorization check
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = ? AND id != 1"); // Protect admin account
            if ($stmt->execute([$target_user_id])) {
                $message = "User deleted successfully!";
                
                // Log admin action (but don't verify admin status)
                $log_stmt = $pdo->prepare("INSERT INTO admin_logs (admin_id, action, target_user_id) VALUES (?, ?, ?)");
                $log_stmt->execute([$_SESSION['user_id'], 'delete_user', $target_user_id]);
            } else {
                $error = "Failed to delete user.";
            }
            break;
            
        case 'promote_user':
            // VULNERABILITY: Anyone can promote users to admin
            $stmt = $pdo->prepare("UPDATE users SET role = 'admin' WHERE id = ?");
            if ($stmt->execute([$target_user_id])) {
                $message = "User promoted to admin!";
                
                $log_stmt = $pdo->prepare("INSERT INTO admin_logs (admin_id, action, target_user_id) VALUES (?, ?, ?)");
                $log_stmt->execute([$_SESSION['user_id'], 'promote_user', $target_user_id]);
            } else {
                $error = "Failed to promote user.";
            }
            break;
    }
}

// Get all users
$pdo = getConnection();
$stmt = $pdo->query("SELECT * FROM users ORDER BY id");
$users = $stmt->fetchAll();

// Get admin logs
$log_stmt = $pdo->query("
    SELECT al.*, u.username as admin_username, u2.username as target_username 
    FROM admin_logs al 
    LEFT JOIN users u ON al.admin_id = u.id 
    LEFT JOIN users u2 ON al.target_user_id = u2.id 
    ORDER BY al.timestamp DESC 
    LIMIT 10
");
$logs = $log_stmt->fetchAll();

include 'header.php';
?>

<h2>Admin Panel</h2>

<?php if (!isAdmin()): ?>
    <div class="alert alert-danger">
        <strong>🚨 ACCESS CONTROL VULNERABILITY:</strong> You are accessing the admin panel without proper authorization! 
        This demonstrates a critical security flaw where function-level access controls are missing or ineffective.
    </div>
<?php endif; ?>

<?php if ($message): ?>
    <div class="alert alert-success"><?php echo sanitizeInput($message); ?></div>
<?php endif; ?>

<?php if ($error): ?>
    <div class="alert alert-danger"><?php echo sanitizeInput($error); ?></div>
<?php endif; ?>

<h3>User Management</h3>
<table class="table">
    <thead>
        <tr>
            <th>ID</th>
            <th>Username</th>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($users as $user): ?>
        <tr>
            <td><?php echo $user['id']; ?></td>
            <td>
                <a href="profile.php?user_id=<?php echo $user['id']; ?>">
                    <?php echo sanitizeInput($user['username']); ?>
                </a>
            </td>
            <td><?php echo sanitizeInput($user['email']); ?></td>
            <td>
                <span style="color: <?php echo $user['role'] === 'admin' ? 'red' : ($user['role'] === 'moderator' ? 'orange' : 'green'); ?>;">
                    <?php echo sanitizeInput($user['role']); ?>
                </span>
            </td>
            <td><?php echo $user['is_active'] ? 'Active' : 'Inactive'; ?></td>
            <td>
                <?php if ($user['id'] != 1): // Protect main admin account ?>
                    <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure?');">
                        <input type="hidden" name="action" value="delete_user">
                        <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                        <button type="submit" class="btn-danger" style="font-size: 12px; padding: 5px 8px;">Delete</button>
                    </form>
                    
                    <?php if ($user['role'] !== 'admin'): ?>
                        <form method="POST" style="display: inline; margin-left: 5px;">
                            <input type="hidden" name="action" value="promote_user">
                            <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                            <button type="submit" style="font-size: 12px; padding: 5px 8px; background-color: orange;">Promote to Admin</button>
                        </form>
                    <?php endif; ?>
                <?php endif; ?>
            </td>
        </tr>
        <?php endforeach; ?>
    </tbody>
</table>

<h3>Recent Admin Actions</h3>
<?php if (empty($logs)): ?>
    <p>No admin actions recorded.</p>
<?php else: ?>
    <table class="table">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Admin</th>
                <th>Action</th>
                <th>Target User</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($logs as $log): ?>
            <tr>
                <td><?php echo date('Y-m-d H:i:s', strtotime($log['timestamp'])); ?></td>
                <td><?php echo sanitizeInput($log['admin_username'] ?? 'Unknown'); ?></td>
                <td><?php echo sanitizeInput($log['action']); ?></td>
                <td><?php echo sanitizeInput($log['target_username'] ?? 'N/A'); ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
<?php endif; ?>

<div class="vulnerability-info" style="margin-top: 30px;">
    <h3>🔍 Missing Function Level Access Control</h3>
    <p>This page demonstrates several critical vulnerabilities:</p>
    <ul>
        <li><strong>Weak Authorization:</strong> Non-admin users can access this page</li>
        <li><strong>Missing Server-Side Validation:</strong> Actions are processed even for unauthorized users</li>
        <li><strong>Privilege Escalation:</strong> Regular users can promote themselves or others to admin</li>
        <li><strong>Inadequate Logging:</strong> Actions are logged but not prevented</li>
    </ul>
    
    <h4>Test the vulnerability:</h4>
    <div class="code-example">
        1. Login as a regular user (john_doe/password)<br>
        2. Navigate directly to: <a href="admin.php">admin.php</a><br>
        3. Try promoting yourself to admin<br>
        4. Try deleting other users<br>
        5. Check how the system responds
    </div>
</div>

<?php include 'footer.php'; ?>