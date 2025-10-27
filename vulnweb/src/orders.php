<?php
ob_start(); // Start output buffering to prevent header issues
require_once 'config.php';

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// VULNERABLE: No proper authentication check
if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

// VULNERABLE: Broken Access Control - Users can view any order by manipulating URL
$user_id = $_GET['user_id'] ?? $_SESSION['user_id'];

$title = 'Orders';
include 'header.php';
?>

<div class="row">
    <div class="col-md-9">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h3>📋 Orders</h3>
            <?php if (isAdmin()): ?>
                <div>
                    <a href="?view=all" class="btn btn-info btn-sm">View All Orders</a>
                    <a href="admin.php" class="btn btn-danger btn-sm">Admin Panel</a>
                </div>
            <?php endif; ?>
        </div>

        <!-- VULNERABLE: User can change user_id in URL to view other users' orders -->
        <?php if (isset($_GET['user_id']) && $_GET['user_id'] != $_SESSION['user_id']): ?>
            <div class="alert alert-warning">
                <h6>🔍 Viewing orders for User ID: <?php echo htmlspecialchars($_GET['user_id']); ?></h6>
                <p class="mb-0">This demonstrates <strong>Broken Access Control</strong> - you can view other users' orders!</p>
            </div>
        <?php endif; ?>

        <?php
        $conn = getConnection();
        
        // VULNERABLE: SQL Injection and Broken Access Control
        if (isset($_GET['view']) && $_GET['view'] === 'all' && isAdmin()) {
            // Admin viewing all orders
            $query = "SELECT o.*, u.username, p.name as product_name 
                     FROM orders o 
                     JOIN users u ON o.user_id = u.id 
                     JOIN products p ON o.product_id = p.id 
                     ORDER BY o.created_at DESC";
        } else {
            // VULNERABLE: Direct user input in SQL query
            $query = "SELECT o.*, u.username, p.name as product_name 
                     FROM orders o 
                     JOIN users u ON o.user_id = u.id 
                     JOIN products p ON o.product_id = p.id 
                     WHERE o.user_id = $user_id 
                     ORDER BY o.created_at DESC";
        }
        
        if (isset($_GET['debug'])) {
            echo "<div class='alert alert-info'><strong>Query:</strong> <code>$query</code></div>";
        }
        
        $result = $conn->query($query);
        
        if (!$result) {
            echo "<div class='alert alert-danger'>Database Error: " . $conn->error . "</div>";
        } else {
            if ($result->num_rows === 0) {
                echo "<div class='alert alert-warning'>No orders found.</div>";
            } else {
                ?>
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Order ID</th>
                                <th>Customer</th>
                                <th>Product</th>
                                <th>Quantity</th>
                                <th>Total Price</th>
                                <th>Status</th>
                                <th>Date</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while ($order = $result->fetch_assoc()): ?>
                            <tr>
                                <td><?php echo $order['id']; ?></td>
                                <td><?php echo htmlspecialchars($order['username']); ?></td>
                                <td><?php echo htmlspecialchars($order['product_name']); ?></td>
                                <td><?php echo $order['quantity']; ?></td>
                                <td>Rp <?php echo number_format($order['total_price'], 0, ',', '.'); ?></td>
                                <td>
                                    <span class="badge bg-<?php 
                                        echo $order['status'] === 'delivered' ? 'success' : 
                                            ($order['status'] === 'shipped' ? 'primary' : 
                                            ($order['status'] === 'paid' ? 'info' : 'warning')); 
                                    ?>">
                                        <?php echo ucfirst($order['status']); ?>
                                    </span>
                                </td>
                                <td><?php echo date('M j, Y', strtotime($order['created_at'])); ?></td>
                                <td>
                                    <!-- VULNERABLE: No authorization check for actions -->
                                    <a href="order_detail.php?id=<?php echo $order['id']; ?>" class="btn btn-sm btn-outline-primary">View</a>
                                    <?php if (isAdmin() || $order['user_id'] == $_SESSION['user_id']): ?>
                                        <a href="cancel_order.php?id=<?php echo $order['id']; ?>" class="btn btn-sm btn-outline-danger">Cancel</a>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
                <?php
            }
        }
        ?>
    </div>

    <div class="col-md-3">
        <div class="card">
            <div class="card-header">
                <h5>🎯 Access Control Testing</h5>
            </div>
            <div class="card-body">
                <p class="text-muted">Test Broken Access Control by modifying URLs:</p>
                
                <h6>Try these URLs:</h6>
                <ul class="small">
                    <li><a href="?user_id=1">orders.php?user_id=1</a></li>
                    <li><a href="?user_id=2">orders.php?user_id=2</a></li>
                    <li><a href="?user_id=3">orders.php?user_id=3</a></li>
                    <li><a href="?user_id=999">orders.php?user_id=999</a></li>
                </ul>
                
                <h6>SQL Injection:</h6>
                <ul class="small">
                    <li><a href="?user_id=1 OR 1=1">user_id=1 OR 1=1</a></li>
                    <li><a href="?user_id=1 UNION SELECT 1,2,3,4,5,6,7,8">UNION attack</a></li>
                </ul>
            </div>
        </div>

        <div class="card mt-3">
            <div class="card-header">
                <h5>👤 Current User Info</h5>
            </div>
            <div class="card-body">
                <?php $current_user = getCurrentUser(); ?>
                <p><strong>Username:</strong> <?php echo htmlspecialchars($current_user['username']); ?></p>
                <p><strong>Role:</strong> <?php echo htmlspecialchars($current_user['role']); ?></p>
                <p><strong>User ID:</strong> <?php echo $current_user['id']; ?></p>
                
                <hr>
                
                <h6>🔗 Quick Links</h6>
                <a href="?user_id=<?php echo $current_user['id']; ?>" class="btn btn-primary btn-sm d-block mb-2">My Orders</a>
                <a href="profile.php" class="btn btn-secondary btn-sm d-block mb-2">Profile</a>
                <a href="products.php" class="btn btn-success btn-sm d-block mb-2">Shop More</a>
            </div>
        </div>

        <?php if (isset($_GET['debug'])): ?>
        <div class="card mt-3">
            <div class="card-header">
                <h5>🐛 Debug Information</h5>
            </div>
            <div class="card-body">
                <p><strong>Current Session:</strong></p>
                <pre class="small"><?php print_r($_SESSION); ?></pre>
                <p><strong>GET Parameters:</strong></p>
                <pre class="small"><?php print_r($_GET); ?></pre>
                <p><strong>Query:</strong></p>
                <pre class="small"><?php echo $query ?? 'No query'; ?></pre>
            </div>
        </div>
        <?php endif; ?>
    </div>
</div>

<?php include 'footer.php'; ?>