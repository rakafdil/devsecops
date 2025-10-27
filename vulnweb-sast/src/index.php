<?php
ob_start();
require_once 'config.php';

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

$title = 'Home';
include 'header.php';
?>

<div class="row">
    <div class="col-lg-8">
        <div class="jumbotron bg-primary text-white p-5 rounded">
            <h1 class="display-4">🎯 Welcome to VulnWeb!</h1>
            <p class="lead">
                This is an intentionally vulnerable web application designed for learning and testing 
                cybersecurity skills, particularly in implementing the <strong>Cyber Kill Chain</strong> methodology.
            </p>
            <hr class="my-4">
            <p>
                Explore various security vulnerabilities and practice your penetration testing skills 
                in a safe, controlled environment.
            </p>
            <?php if (!isLoggedIn()): ?>
                <a class="btn btn-light btn-lg" href="login.php" role="button">Get Started</a>
            <?php else: ?>
                <a class="btn btn-light btn-lg" href="products.php" role="button">Browse Products</a>
            <?php endif; ?>
        </div>

        <div class="row mt-4">
            <div class="col-md-12">
                <h3>🔍 Available Vulnerabilities</h3>
                <p class="text-muted">This application contains the following security vulnerabilities for educational purposes:</p>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6 mb-3">
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <h5><i class="fas fa-database"></i> SQL Injection</h5>
                    </div>
                    <div class="card-body">
                        <p>Product search and user authentication vulnerable to SQL injection attacks.</p>
                        <a href="products.php" class="btn btn-outline-danger btn-sm">Explore</a>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6 mb-3">
                <div class="card">
                    <div class="card-header bg-warning text-dark">
                        <h5><i class="fas fa-code"></i> Cross-Site Scripting (XSS)</h5>
                    </div>
                    <div class="card-body">
                        <p>Comment system vulnerable to stored and reflected XSS attacks.</p>
                        <a href="comments.php" class="btn btn-outline-warning btn-sm">Explore</a>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6 mb-3">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h5><i class="fas fa-key"></i> Broken Authentication</h5>
                    </div>
                    <div class="card-body">
                        <p>Weak session management and authentication bypass vulnerabilities.</p>
                        <a href="login.php" class="btn btn-outline-info btn-sm">Explore</a>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6 mb-3">
                <div class="card">
                    <div class="card-header bg-secondary text-white">
                        <h5><i class="fas fa-shield-alt"></i> Broken Access Control</h5>
                    </div>
                    <div class="card-body">
                        <p>Unauthorized access to user data and administrative functions.</p>
                        <a href="orders.php" class="btn btn-outline-secondary btn-sm">Explore</a>
                    </div>
                </div>
            </div>
        </div>

        <?php if (isset($_GET['debug'])): ?>
        <div class="alert alert-warning mt-4">
            <h5>🐛 Debug Information</h5>
            <p><strong>Current PHP Version:</strong> <?php echo phpversion(); ?></p>
            <p><strong>Server Info:</strong> <?php echo $_SERVER['SERVER_SOFTWARE']; ?></p>
            <p><strong>Database Status:</strong> 
                <?php 
                $conn = getConnection();
                echo $conn ? "Connected" : "Not Connected";
                ?>
            </p>
            <p><strong>Session ID:</strong> <?php echo session_id(); ?></p>
            <p><strong>Current User:</strong> <?php debugInfo(getCurrentUser()); ?></p>
        </div>
        <?php endif; ?>
    </div>

    <div class="col-lg-4">
        <div class="card">
            <div class="card-header">
                <h5>📚 Cyber Kill Chain Phases</h5>
            </div>
            <div class="card-body">
                <ol class="list-group list-group-numbered">
                    <li class="list-group-item">Reconnaissance</li>
                    <li class="list-group-item">Weaponization</li>
                    <li class="list-group-item">Delivery</li>
                    <li class="list-group-item">Exploitation</li>
                    <li class="list-group-item">Installation</li>
                    <li class="list-group-item">Command & Control</li>
                    <li class="list-group-item">Actions on Objectives</li>
                </ol>
            </div>
        </div>

        <div class="card mt-3">
            <div class="card-header">
                <h5>⚠️ Disclaimer</h5>
            </div>
            <div class="card-body">
                <p class="text-muted small">
                    This application is intentionally vulnerable and should only be used for 
                    educational purposes in a controlled environment. Do not deploy this 
                    application on any production system or public network.
                </p>
            </div>
        </div>

        <?php if (isLoggedIn()): ?>
        <div class="card mt-3">
            <div class="card-header">
                <h5>👤 Quick Actions</h5>
            </div>
            <div class="card-body">
                <a href="profile.php" class="btn btn-primary btn-sm d-block mb-2">View Profile</a>
                <a href="orders.php" class="btn btn-secondary btn-sm d-block mb-2">My Orders</a>
                <?php if (isAdmin()): ?>
                    <a href="admin.php" class="btn btn-danger btn-sm d-block mb-2">Admin Panel</a>
                <?php endif; ?>
                <a href="logout.php" class="btn btn-outline-dark btn-sm d-block">Logout</a>
            </div>
        </div>
        <?php endif; ?>
    </div>
</div>

<?php include 'footer.php'; ?>