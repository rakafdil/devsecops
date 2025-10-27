<?php
ob_start();
require_once 'config.php';

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// VULNERABLE: Session hijacking possibility
session_destroy();

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// VULNERABLE: No proper session cleanup
$_SESSION = array();

// VULNERABLE: Cookie not properly cleared
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

session_destroy();

// Redirect to login page
header('Location: login.php?message=You have been logged out successfully');
exit;
?>