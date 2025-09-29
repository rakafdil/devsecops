<?php
// Database configuration
$host = $_ENV['DB_HOST'] ?? 'db';
$dbname = $_ENV['DB_NAME'] ?? 'broken_auth_app';
$username = $_ENV['DB_USER'] ?? 'root';
$password = $_ENV['DB_PASS'] ?? 'password123';

// Create connection
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Insecure session configuration
ini_set('session.cookie_httponly', 1); // Vulnerable: JS can access session cookie
ini_set('session.cookie_secure', 1);   // Vulnerable: No HTTPS requirement
ini_set('session.use_strict_mode', 'Strict'); // Vulnerable: Allows session fixation

// Start session with predictable session ID
session_start();

// Helper functions
function logLoginAttempt($username, $ip, $success)
{
    global $pdo;
    // Convert success to proper boolean value
    $successValue = $success === true || $success === 1 || $success === '1' ? 1 : 0;
    $stmt = $pdo->prepare("INSERT INTO login_attempts (username, ip_address, user_agent, success) VALUES (?, ?, ?, ?)");
    $stmt->execute([$username, $ip, $_SERVER['HTTP_USER_AGENT'] ?? '', $successValue]);
}

function getUserByUsername($username)
{
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function updateLoginAttempts($username, $increment = true)
{
    global $pdo;
    if ($increment) {
        $stmt = $pdo->prepare("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?");
    } else {
        $stmt = $pdo->prepare("UPDATE users SET failed_login_attempts = 0, last_login = NOW() WHERE username = ?");
    }
    $stmt->execute([$username]);
}

// Rate limiter using Redis (jika tersedia)
function isRedisRateLimited($ip, $maxAttempts = 5, $timeWindow = 300)
{
    if (!class_exists('Redis')) {
        return false; // Redis not available, allow request
    }

    try {
        $redis = new Redis();
        $redis->connect('redis', 6379);

        $key = "rate_limit:" . $ip;
        $current = $redis->incr($key);

        if ($current === 1) {
            $redis->expire($key, $timeWindow);
        }

        return $current > $maxAttempts;
    } catch (Exception $e) {
        return false; // Redis connection failed, allow request
    }
}

// Vulnerable: Predictable session ID generation
function generatePredictableSessionId()
{
    return md5(time() . rand(1, 1000)); // Very predictable!
}

// Vulnerable: Weak password validation
function isWeakPassword($password)
{
    return strlen($password) < 3; // Extremely weak validation
}

// Get client IP (for logging)
function getClientIP()
{
    return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}
?>
