<?php
// Database configuration - VULNERABLE: Hardcoded credentials
define('DB_HOST', $_ENV['DB_HOST'] ?? 'db');
define('DB_USER', $_ENV['DB_USER'] ?? 'vulnuser');
define('DB_PASS', $_ENV['DB_PASS'] ?? 'vulnpass123');
define('DB_NAME', $_ENV['DB_NAME'] ?? 'vulnwebdb');

// VULNERABLE: Weak session configuration
ini_set('session.cookie_httponly', 0); // Should be 1
ini_set('session.cookie_secure', 0);   // Should be 1 for HTTPS
ini_set('session.use_strict_mode', 0); // Should be 1

// Database connection - VULNERABLE: No error handling
function getConnection() {
    static $connection = null;
    
    if ($connection === null) {
        $connection = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        
        // VULNERABLE: Displaying database errors to users
        if ($connection->connect_error) {
            die("Connection failed: " . $connection->connect_error);
        }
    }
    
    return $connection;
}

// VULNERABLE: Simple authentication without proper validation
function authenticate($username, $password) {
    $conn = getConnection();
    
    // VULNERABLE: SQL Injection - Direct string concatenation
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $conn->query($query);
    
    if ($result && $result->num_rows > 0) {
        return $result->fetch_assoc();
    }
    
    return false;
}

// VULNERABLE: Weak session management
function createSession($user) {
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['role'] = $user['role'];
    
    // VULNERABLE: Predictable session token
    $token = md5($user['username'] . time());
    $_SESSION['token'] = $token;
    
    // Store session in database (vulnerable implementation)
    $conn = getConnection();
    $query = "INSERT INTO user_sessions (user_id, session_token, expires_at) 
              VALUES ({$user['id']}, '$token', DATE_ADD(NOW(), INTERVAL 1 HOUR))";
    $conn->query($query);
}

// VULNERABLE: No proper session validation
function isLoggedIn() {
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    return isset($_SESSION['user_id']);
}

// VULNERABLE: No proper authorization check
function isAdmin() {
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

// VULNERABLE: No CSRF protection
function getCurrentUser() {
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    if (isset($_SESSION['user_id'])) {
        $conn = getConnection();
        $query = "SELECT * FROM users WHERE id = {$_SESSION['user_id']}";
        $result = $conn->query($query);
        return $result ? $result->fetch_assoc() : null;
    }
    return null;
}

// VULNERABLE: No input sanitization
function executeQuery($query) {
    $conn = getConnection();
    return $conn->query($query);
}

// VULNERABLE: Direct output without escaping
function displayError($message) {
    echo "<div class='alert alert-danger'>Error: $message</div>";
}

// VULNERABLE: Information disclosure
function debugInfo($data) {
    if (isset($_GET['debug'])) {
        echo "<pre>";
        print_r($data);
        echo "</pre>";
    }
}
?>