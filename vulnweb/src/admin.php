<?php
ob_start();
require_once 'config.php';

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// VULNERABLE: Weak admin check - can be bypassed
if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

// VULNERABLE: Simple role check that can be manipulated
if (!isAdmin()) {
    // VULNERABLE: Information disclosure
    die("Access denied. Current role: " . ($_SESSION['role'] ?? 'none'));
}

$message = '';
$error = '';

// Handle user management actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'create_user':
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';
            $email = $_POST['email'] ?? '';
            $role = $_POST['role'] ?? 'user';
            
            if (!empty($username) && !empty($password) && !empty($email)) {
                $conn = getConnection();
                // VULNERABLE: SQL Injection
                $query = "INSERT INTO users (username, password, email, role) VALUES ('$username', '$password', '$email', '$role')";
                
                if ($conn->query($query)) {
                    $message = "User '$username' created successfully!";
                } else {
                    $error = "Failed to create user: " . $conn->error;
                }
            } else {
                $error = "All fields are required!";
            }
            break;
            
        case 'delete_user':
            $user_id = $_POST['user_id'] ?? '';
            if (!empty($user_id)) {
                $conn = getConnection();
                // VULNERABLE: SQL Injection
                $query = "DELETE FROM users WHERE id = $user_id";
                
                if ($conn->query($query)) {
                    $message = "User deleted successfully!";
                } else {
                    $error = "Failed to delete user: " . $conn->error;
                }
            }
            break;
            
        case 'execute_sql':
            // EXTREMELY VULNERABLE: Direct SQL execution
            $sql = $_POST['sql'] ?? '';
            if (!empty($sql)) {
                $conn = getConnection();
                $result = $conn->query($sql);
                
                if ($result) {
                    $message = "SQL executed successfully!";
                } else {
                    $error = "SQL Error: " . $conn->error;
                }
            }
            break;
    }
}

$title = 'Admin Panel';
include 'header.php';
?>

<div class="row">
    <div class="col-md-12">
        <div class="alert alert-danger">
            <h4>⚠️ ADMIN PANEL - HIGH PRIVILEGE AREA</h4>
            <p class="mb-0">This panel contains multiple severe vulnerabilities for educational purposes.</p>
        </div>
        
        <?php if ($message): ?>
            <div class="alert alert-success"><?php echo $message; ?></div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo $error; ?></div>
        <?php endif; ?>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <!-- User Management -->
        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5>👥 User Management</h5>
            </div>
            <div class="card-body">
                <h6>Create New User</h6>
                <form method="POST">
                    <input type="hidden" name="action" value="create_user">
                    <div class="mb-2">
                        <input type="text" class="form-control form-control-sm" name="username" placeholder="Username" required>
                    </div>
                    <div class="mb-2">
                        <input type="email" class="form-control form-control-sm" name="email" placeholder="Email" required>
                    </div>
                    <div class="mb-2">
                        <input type="password" class="form-control form-control-sm" name="password" placeholder="Password" required>
                    </div>
                    <div class="mb-2">
                        <select class="form-control form-control-sm" name="role">
                            <option value="user">User</option>
                            <option value="moderator">Moderator</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-success btn-sm">Create User</button>
                </form>
            </div>
        </div>

        <!-- SQL Console -->
        <div class="card mb-4">
            <div class="card-header bg-danger text-white">
                <h5>💻 SQL Console</h5>
            </div>
            <div class="card-body">
                <p class="text-muted">EXTREMELY DANGEROUS: Execute raw SQL queries</p>
                <form method="POST">
                    <input type="hidden" name="action" value="execute_sql">
                    <div class="mb-2">
                        <textarea class="form-control" name="sql" rows="3" placeholder="Enter SQL query..."></textarea>
                    </div>
                    <button type="submit" class="btn btn-danger btn-sm">Execute SQL</button>
                </form>
                
                <div class="alert alert-warning mt-2">
                    <small>
                        <strong>Example queries:</strong><br>
                        <code>SELECT * FROM users;</code><br>
                        <code>UPDATE users SET role='admin' WHERE id=2;</code><br>
                        <code>DROP TABLE comments;</code>
                    </small>
                </div>
            </div>
        </div>
    </div>

    <div class="col-md-6">
        <!-- User List -->
        <div class="card">
            <div class="card-header bg-info text-white">
                <h5>📋 User List</h5>
            </div>
            <div class="card-body">
                <?php
                $conn = getConnection();
                $users_query = "SELECT * FROM users ORDER BY id";
                $users_result = $conn->query($users_query);
                
                if ($users_result && $users_result->num_rows > 0) {
                    ?>
                    <div class="table-responsive">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Username</th>
                                    <th>Email</th>
                                    <th>Role</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php while ($user = $users_result->fetch_assoc()): ?>
                                <tr>
                                    <td><?php echo $user['id']; ?></td>
                                    <td><?php echo htmlspecialchars($user['username']); ?></td>
                                    <td><?php echo htmlspecialchars($user['email']); ?></td>
                                    <td>
                                        <span class="badge bg-<?php echo $user['role'] === 'admin' ? 'danger' : ($user['role'] === 'moderator' ? 'warning' : 'secondary'); ?>">
                                            <?php echo $user['role']; ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?php if ($user['id'] != $_SESSION['user_id']): ?>
                                            <form method="POST" style="display:inline;">
                                                <input type="hidden" name="action" value="delete_user">
                                                <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                                <button type="submit" class="btn btn-danger btn-xs" 
                                                        onclick="return confirm('Delete this user?')">Delete</button>
                                            </form>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php endwhile; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php
                } else {
                    echo "<div class='alert alert-warning'>No users found.</div>";
                }
                ?>
            </div>
        </div>

        <!-- System Information -->
        <div class="card mt-3">
            <div class="card-header bg-secondary text-white">
                <h5>🖥️ System Information</h5>
            </div>
            <div class="card-body">
                <p><strong>PHP Version:</strong> <?php echo phpversion(); ?></p>
                <p><strong>Server:</strong> <?php echo $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'; ?></p>
                <p><strong>Document Root:</strong> <?php echo $_SERVER['DOCUMENT_ROOT'] ?? 'Unknown'; ?></p>
                <p><strong>Current User:</strong> <?php echo get_current_user(); ?></p>
                
                <!-- VULNERABLE: File system access -->
                <h6>Configuration Files:</h6>
                <ul class="small">
                    <li><a href="?file=config.php">config.php</a></li>
                    <li><a href="?file=/etc/passwd">/etc/passwd</a></li>
                    <li><a href="?file=../database/init.sql">database/init.sql</a></li>
                </ul>
            </div>
        </div>
    </div>
</div>

<!-- File viewer (VULNERABLE: Local File Inclusion) -->
<?php if (isset($_GET['file'])): ?>
<div class="row mt-4">
    <div class="col-12">
        <div class="card">
            <div class="card-header bg-warning">
                <h5>📄 File Viewer: <?php echo htmlspecialchars($_GET['file']); ?></h5>
            </div>
            <div class="card-body">
                <pre><?php
                $file = $_GET['file'];
                // VULNERABLE: No path validation - Local File Inclusion
                if (file_exists($file)) {
                    echo htmlspecialchars(file_get_contents($file));
                } else {
                    echo "File not found or access denied.";
                }
                ?></pre>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<?php if (isset($_GET['debug'])): ?>
<div class="row mt-4">
    <div class="col-12">
        <div class="alert alert-secondary">
            <h5>🐛 Debug Information</h5>
            <p><strong>Session Data:</strong></p>
            <pre><?php print_r($_SESSION); ?></pre>
            <p><strong>Server Variables:</strong></p>
            <pre><?php print_r($_SERVER); ?></pre>
        </div>
    </div>
</div>
<?php endif; ?>

<?php include 'footer.php'; ?>