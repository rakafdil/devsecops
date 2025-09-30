<?php
namespace App;

class Security {
    
    /**
     * Safely encode HTML output to prevent XSS
     */
    public static function escapeHtml($input, $encoding = 'UTF-8') {
        if (is_null($input)) {
            return '';
        }
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, $encoding);
    }
    
    /**
     * Safely encode for JavaScript context
     */
    public static function escapeJs($input) {
        if (is_null($input)) {
            return '';
        }
        return json_encode($input, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    }
    
    /**
     * Safely encode for HTML attribute context
     */
    public static function escapeAttr($input) {
        if (is_null($input)) {
            return '';
        }
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
    
    /**
     * Sanitize CSS values
     */
    public static function escapeCss($input) {
        if (is_null($input)) {
            return '';
        }
        // Only allow alphanumeric, hash, and basic CSS values
        return preg_replace('/[^a-zA-Z0-9#\-_\s%.]/', '', $input);
    }
    
    /**
     * Validate and sanitize URLs
     */
    public static function sanitizeUrl($url) {
        if (is_null($url)) {
            return '';
        }
        
        // Filter dangerous schemes
        $dangerous_schemes = ['javascript:', 'data:', 'vbscript:', 'file:', 'about:'];
        $url_lower = strtolower(trim($url));
        
        foreach ($dangerous_schemes as $scheme) {
            if (strpos($url_lower, $scheme) === 0) {
                return '#';
            }
        }
        
        // Validate URL format
        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            return '#';
        }
        
        return $url;
    }
    
    /**
     * Generate Content Security Policy header
     */
    public static function getCSPHeader() {
        return [
            'Content-Security-Policy' => "default-src 'self'; " .
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " .
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " .
                "img-src 'self' data: https:; " .
                "font-src 'self' https://fonts.gstatic.com; " .
                "connect-src 'self'; " .
                "frame-src 'none'; " .
                "object-src 'none'; " .
                "base-uri 'self';"
        ];
    }
    
    /**
     * Validate and sanitize input
     */
    public static function validateInput($input, $type = 'string', $max_length = 1000) {
        if (is_null($input)) {
            return '';
        }
        
        // Trim whitespace
        $input = trim($input);
        
        // Check length
        if (strlen($input) > $max_length) {
            $input = substr($input, 0, $max_length);
        }
        
        switch ($type) {
            case 'email':
                return filter_var($input, FILTER_VALIDATE_EMAIL) ? $input : '';
            case 'int':
                return filter_var($input, FILTER_VALIDATE_INT) !== false ? (int)$input : 0;
            case 'url':
                return self::sanitizeUrl($input);
            case 'string':
            default:
                // Remove null bytes and control characters (PHP 8.1+ compatible)
                $input = str_replace("\0", '', $input);
                $input = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $input);
                return $input;
        }
    }
    
    /**
     * Generate CSRF token
     */
    public static function generateCSRFToken() {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        
        return $_SESSION['csrf_token'];
    }
    
    /**
     * Validate CSRF token
     */
    public static function validateCSRFToken($token) {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
}
?>