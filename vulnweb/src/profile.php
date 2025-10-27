<?php
ob_start();
require_once 'config.php';

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

$user = getCurrentUser();
$message = '';
$error = '';

// Handle profile update
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $new_username = $_POST['username'] ?? '';
    $new_email = $_POST['email'] ?? '';
    $new_password = $_POST['password'] ?? '';
    
    if (!empty($new_username) && !empty($new_email)) {
        $conn = getConnection();
        
        // VULNERABLE: SQL Injection
        $query = "UPDATE users SET username = '$new_username', email = '$new_email'";
        
        if (!empty($new_password)) {
            $query .= ", password = '$new_password'";
        }
        
        $query .= " WHERE id = {$user['id']}";
        
        if ($conn->query($query)) {
            $message = 'Profile updated successfully!';
            // Update session
            $_SESSION['username'] = $new_username;
        } else {
            $error = 'Failed to update profile: ' . $conn->error;
        }
    } else {
        $error = 'Username and email are required!';
    }
}

$title = 'Profile';
include 'header.php';
?>

<div class="row">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h4>👤 User Profile</h4>
            </div>
            <div class="card-body">
                <?php if ($message): ?>
                    <div class="alert alert-success"><?php echo $message; ?></div>
                <?php endif; ?>
                
                <?php if ($error): ?>
                    <div class="alert alert-danger"><?php echo $error; ?></div>
                <?php endif; ?>

                <!-- VULNERABLE: No CSRF protection -->
                <form method="POST">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" 
                               value="<?php echo htmlspecialchars($user['username']); ?>" required>
                    </div>
                    
                    <div class="mb-3">
                        <label for="email" class="form-label">Email</label>
                        <input type="email" class="form-control" id="email" name="email" 
                               value="<?php echo htmlspecialchars($user['email']); ?>" required>
                    </div>
                    
                    <div class="mb-3">
                        <label for="password" class="form-label">New Password (leave blank to keep current)</label>
                        <input type="password" class="form-control" id="password" name="password" 
                               placeholder="Enter new password...">
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Update Profile</button>
                    <a href="index.php" class="btn btn-secondary">Back to Home</a>
                </form>
            </div>
        </div>
    </div>

    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h5>📊 Account Information</h5>
            </div>
            <div class="card-body">
                <p><strong>User ID:</strong> <?php echo $user['id']; ?></p>
                <p><strong>Role:</strong> 
                    <span class="badge bg-<?php echo $user['role'] === 'admin' ? 'danger' : ($user['role'] === 'moderator' ? 'warning' : 'secondary'); ?>">
                        <?php echo ucfirst($user['role']); ?>
                    </span>
                </p>
                <p><strong>Account Created:</strong> <?php echo date('M j, Y', strtotime($user['created_at'])); ?></p>
                <p><strong>Status:</strong> 
                    <span class="badge bg-<?php echo $user['is_active'] ? 'success' : 'danger'; ?>">
                        <?php echo $user['is_active'] ? 'Active' : 'Inactive'; ?>
                    </span>
                </p>
            </div>
        </div>

        <div class="card mt-3">
            <div class="card-header">
                <h5>🔗 Quick Actions</h5>
            </div>
            <div class="card-body">
                <a href="orders.php" class="btn btn-primary btn-sm d-block mb-2">View My Orders</a>
                <a href="products.php" class="btn btn-success btn-sm d-block mb-2">Browse Products</a>
                <a href="comments.php" class="btn btn-info btn-sm d-block mb-2">My Comments</a>
                <?php if (isAdmin()): ?>
                    <a href="admin.php" class="btn btn-danger btn-sm d-block mb-2">Admin Panel</a>
                <?php endif; ?>
                <a href="logout.php" class="btn btn-outline-dark btn-sm d-block">Logout</a>
            </div>
        </div>
    </div>
</div>

<?php include 'footer.php'; ?>