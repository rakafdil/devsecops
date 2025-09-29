<?php
// Database configuration
define('DB_HOST', $_ENV['DB_HOST'] ?? 'db');
define('DB_NAME', $_ENV['DB_NAME'] ?? 'vulnerable_app');
define('DB_USER', $_ENV['DB_USER'] ?? 'root');
define('DB_PASS', $_ENV['DB_PASS'] ?? 'password123');

// Application configuration
define('BASE_URL', 'http://localhost:8080');
define('APP_NAME', 'Vulnerable App - Broken Access Control Demo');

// Session configuration
session_start();

// Database connection
function getConnection() {
    static $pdo = null;
    
    if ($pdo === null) {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4";
            $pdo = new PDO($dsn, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        } catch (PDOException $e) {
            die("Connection failed: " . $e->getMessage());
        }
    }
    
    return $pdo;
}

// Authentication functions
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function getCurrentUser() {
    if (!isLoggedIn()) {
        return null;
    }
    
    $pdo = getConnection();
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    return $stmt->fetch();
}

function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit;
    }
}

// VULNERABILITY: Weak authorization check
function isAdmin() {
    $user = getCurrentUser();
    return $user && $user['role'] === 'admin';
}

// VULNERABILITY: No proper role checking
function hasRole($role) {
    $user = getCurrentUser();
    return $user && $user['role'] === $role;
}

// Utility functions
function redirect($url) {
    header("Location: $url");
    exit;
}

function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// VULNERABILITY: Weak CSRF protection (easily bypassed)
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}
?>