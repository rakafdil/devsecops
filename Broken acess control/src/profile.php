<?php
require_once 'config.php';
requireLogin();

// VULNERABILITY: Insecure Direct Object Reference (IDOR)
// The application doesn't verify if the user should have access to the requested profile
$user_id = $_GET['user_id'] ?? $_SESSION['user_id'];

$pdo = getConnection();
$stmt = $pdo->prepare("SELECT u.*, p.* FROM users u LEFT JOIN profiles p ON u.id = p.user_id WHERE u.id = ?");
$stmt->execute([$user_id]);
$profile_user = $stmt->fetch();

if (!$profile_user) {
    $error = "User not found.";
}

$current_user = getCurrentUser();
$is_viewing_own_profile = ($user_id == $_SESSION['user_id']);

include 'header.php';
?>

<h2><?php echo $is_viewing_own_profile ? 'My Profile' : 'User Profile'; ?></h2>

<?php if (isset($error)): ?>
    <div class="alert alert-danger"><?php echo sanitizeInput($error); ?></div>
<?php else: ?>
    
    <?php if (!$is_viewing_own_profile): ?>
        <div class="alert alert-warning">
            <strong>🚨 VULNERABILITY DETECTED:</strong> You are viewing another user's profile! 
            This is an Insecure Direct Object Reference (IDOR) vulnerability.
        </div>
    <?php endif; ?>

    <h3>Basic Information</h3>
    <table class="table">
        <tr>
            <th>Username</th>
            <td><?php echo sanitizeInput($profile_user['username']); ?></td>
        </tr>
        <tr>
            <th>Email</th>
            <td><?php echo sanitizeInput($profile_user['email']); ?></td>
        </tr>
        <tr>
            <th>Role</th>
            <td><?php echo sanitizeInput($profile_user['role']); ?></td>
        </tr>
        <tr>
            <th>Account Status</th>
            <td><?php echo $profile_user['is_active'] ? 'Active' : 'Inactive'; ?></td>
        </tr>
        <tr>
            <th>Member Since</th>
            <td><?php echo date('F j, Y', strtotime($profile_user['created_at'])); ?></td>
        </tr>
    </table>

    <?php if ($profile_user['full_name']): ?>
        <h3>Personal Information</h3>
        <table class="table">
            <tr>
                <th>Full Name</th>
                <td><?php echo sanitizeInput($profile_user['full_name']); ?></td>
            </tr>
            <tr>
                <th>Phone</th>
                <td><?php echo sanitizeInput($profile_user['phone']); ?></td>
            </tr>
            <tr>
                <th>Address</th>
                <td><?php echo sanitizeInput($profile_user['address']); ?></td>
            </tr>
            <tr>
                <th>Department</th>
                <td><?php echo sanitizeInput($profile_user['department']); ?></td>
            </tr>
            <?php if ($profile_user['salary']): ?>
                <tr>
                    <th>Salary</th>
                    <td style="color: red; font-weight: bold;">$<?php echo number_format($profile_user['salary'], 2); ?></td>
                </tr>
            <?php endif; ?>
        </table>
    <?php endif; ?>

    <div style="margin-top: 20px;">
        <?php if ($is_viewing_own_profile): ?>
            <a href="edit_profile.php"><button>Edit Profile</button></a>
        <?php endif; ?>
        
        <!-- VULNERABILITY: Missing authorization check for admin actions -->
        <?php if (isAdmin() || !$is_viewing_own_profile): ?>
            <a href="admin.php?action=edit&user_id=<?php echo $user_id; ?>">
                <button class="btn-danger">Admin: Edit User</button>
            </a>
        <?php endif; ?>
    </div>

    <div class="vulnerability-info" style="margin-top: 30px;">
        <h3>🔍 IDOR Vulnerability Explanation</h3>
        <p>This page demonstrates an <strong>Insecure Direct Object Reference (IDOR)</strong> vulnerability:</p>
        <ul>
            <li>The URL parameter <code>user_id</code> can be manipulated to access other users' profiles</li>
            <li>No authorization check verifies if the current user should have access to the requested profile</li>
            <li>Sensitive information like salary data is exposed to unauthorized users</li>
        </ul>
        
        <h4>Try these URLs:</h4>
        <div class="code-example">
            <a href="profile.php?user_id=1">profile.php?user_id=1</a> (Admin)<br>
            <a href="profile.php?user_id=2">profile.php?user_id=2</a> (John Doe)<br>
            <a href="profile.php?user_id=3">profile.php?user_id=3</a> (Jane Smith)<br>
            <a href="profile.php?user_id=4">profile.php?user_id=4</a> (Bob Wilson)<br>
            <a href="profile.php?user_id=5">profile.php?user_id=5</a> (Alice Brown)
        </div>
    </div>

<?php endif; ?>

<?php include 'footer.php'; ?>