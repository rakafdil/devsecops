# XSS Prevention Techniques

Panduan lengkap untuk mencegah Cross-Site Scripting (XSS) attacks.

## 1. Input Validation

### Server-Side Validation
```php
<?php
// Whitelist validation
function validateInput($input, $type) {
    switch ($type) {
        case 'username':
            return preg_match('/^[a-zA-Z0-9_]{3,20}$/', $input);
        case 'email':
            return filter_var($input, FILTER_VALIDATE_EMAIL);
        case 'numeric':
            return filter_var($input, FILTER_VALIDATE_INT);
        default:
            return false;
    }
}

// Length validation
function validateLength($input, $maxLength = 1000) {
    return strlen($input) <= $maxLength;
}

// Sanitize input
function sanitizeInput($input) {
    // Remove null bytes
    $input = str_replace("\0", '', $input);
    
    // Remove control characters
    $input = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $input);
    
    return trim($input);
}
?>
```

### Client-Side Validation (Defense in Depth)
```javascript
function validateInput(input, type) {
    switch (type) {
        case 'username':
            return /^[a-zA-Z0-9_]{3,20}$/.test(input);
        case 'email':
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
        default:
            return false;
    }
}
```

## 2. Output Encoding

### HTML Context Encoding
```php
<?php
// Basic HTML encoding
echo htmlspecialchars($userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');

// Using security class
class Security {
    public static function escapeHtml($input) {
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}

echo Security::escapeHtml($userInput);
?>
```

### JavaScript Context Encoding
```php
<?php
// JSON encoding for JavaScript
echo json_encode($userInput, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

// Manual escaping
function escapeJs($input) {
    $map = [
        '\\' => '\\\\',
        '"' => '\\"',
        '\'' => '\\\'',
        '\n' => '\\n',
        '\r' => '\\r',
        '\t' => '\\t'
    ];
    return strtr($input, $map);
}
?>
```

### CSS Context Encoding
```php
<?php
function escapeCss($input) {
    // Only allow safe CSS values
    return preg_replace('/[^a-zA-Z0-9#\-_\s%.]/', '', $input);
}

// Or use whitelist approach
function validateCssColor($color) {
    $allowedColors = ['red', 'blue', 'green', 'black', 'white'];
    return in_array(strtolower($color), $allowedColors) ? $color : 'black';
}
?>
```

### URL Context Encoding
```php
<?php
function sanitizeUrl($url) {
    // Check for dangerous schemes
    $dangerousSchemes = ['javascript:', 'data:', 'vbscript:'];
    $urlLower = strtolower(trim($url));
    
    foreach ($dangerousSchemes as $scheme) {
        if (strpos($urlLower, $scheme) === 0) {
            return '#'; // Safe default
        }
    }
    
    // Validate URL
    if (filter_var($url, FILTER_VALIDATE_URL) === false) {
        return '#';
    }
    
    return $url;
}
?>
```

## 3. Content Security Policy (CSP)

### Basic CSP Header
```php
<?php
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-src 'none'; object-src 'none';");
?>
```

### Strict CSP (Recommended)
```php
<?php
$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce'; style-src 'self' 'nonce-$nonce'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self';");
?>

<!-- Use nonce in HTML -->
<script nonce="<?php echo $nonce; ?>">
    // Your safe JavaScript here
</script>
```

### CSP Violation Reporting
```php
<?php
header("Content-Security-Policy: default-src 'self'; report-uri /csp-report.php;");
?>
```

```php
<?php
// csp-report.php
$json = file_get_contents('php://input');
$report = json_decode($json, true);

// Log CSP violations
error_log("CSP Violation: " . json_encode($report));

// Or save to database
// saveCSPViolation($report);
?>
```

## 4. HTML Sanitization

### Using HTML Purifier
```php
<?php
require_once 'HTMLPurifier.auto.php';

$config = HTMLPurifier_Config::createDefault();
$config->set('HTML.Allowed', 'p,b,i,u,strong,em,br');
$config->set('HTML.AllowedAttributes', '');
$purifier = new HTMLPurifier($config);

$cleanHtml = $purifier->purify($dirtyHtml);
echo $cleanHtml;
?>
```

### Custom HTML Sanitizer
```php
<?php
function sanitizeHtml($input) {
    // Allow only specific tags
    $allowedTags = '<p><b><i><u><strong><em><br>';
    $input = strip_tags($input, $allowedTags);
    
    // Remove all attributes
    $input = preg_replace('/<([^>]+?)[\s\S]*?>/', '<$1>', $input);
    
    return $input;
}
?>
```

## 5. Safe DOM Manipulation

### JavaScript Best Practices
```javascript
// SAFE: Using textContent
element.textContent = userInput;

// SAFE: Using createTextNode
const textNode = document.createTextNode(userInput);
element.appendChild(textNode);

// SAFE: Using setAttribute
element.setAttribute('title', userInput);

// DANGEROUS: Don't use these with user input
// element.innerHTML = userInput;
// element.outerHTML = userInput;
// document.write(userInput);
```

### Safe Event Handling
```javascript
// SAFE: Add event listeners programmatically
button.addEventListener('click', function() {
    // Safe event handler
});

// DANGEROUS: Don't use onclick attributes with user input
// element.onclick = userInput;
```

## 6. Framework-Specific Protection

### React
```jsx
// SAFE: JSX automatically escapes
const Component = ({ userInput }) => (
    <div>{userInput}</div>
);

// DANGEROUS: dangerouslySetInnerHTML
const DangerousComponent = ({ userInput }) => (
    <div dangerouslySetInnerHTML={{__html: userInput}} />
);
```

### Vue.js
```vue
<!-- SAFE: Template interpolation is escaped -->
<template>
    <div>{{ userInput }}</div>
</template>

<!-- DANGEROUS: v-html directive -->
<template>
    <div v-html="userInput"></div>
</template>
```

### Angular
```typescript
// SAFE: Template interpolation is escaped
@Component({
    template: `<div>{{userInput}}</div>`
})

// Angular sanitizes by default, but be careful with:
// - innerHTML property
// - bypassSecurityTrust methods
```

## 7. Security Headers

### Complete Security Headers
```php
<?php
// XSS Protection
header('X-XSS-Protection: 1; mode=block');

// Prevent MIME sniffing
header('X-Content-Type-Options: nosniff');

// Frame options
header('X-Frame-Options: DENY');

// Referrer policy
header('Referrer-Policy: strict-origin-when-cross-origin');

// HTTPS enforcement (if using HTTPS)
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
?>
```

## 8. CSRF Protection

### Token-Based Protection
```php
<?php
session_start();

// Generate CSRF token
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Validate CSRF token
function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && 
           hash_equals($_SESSION['csrf_token'], $token);
}
?>

<!-- Use in forms -->
<form method="post">
    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
    <!-- other form fields -->
</form>
```

## 9. Testing XSS Prevention

### Automated Testing
```php
<?php
class XSSTest extends PHPUnit\Framework\TestCase {
    public function testHTMLEscaping() {
        $maliciousInput = '<script>alert("XSS")</script>';
        $escaped = Security::escapeHtml($maliciousInput);
        
        $this->assertStringNotContains('<script>', $escaped);
        $this->assertStringContains('&lt;script&gt;', $escaped);
    }
    
    public function testJSEscaping() {
        $maliciousInput = '"; alert("XSS"); //';
        $escaped = Security::escapeJs($maliciousInput);
        
        $this->assertStringNotContains('"; alert(', $escaped);
    }
}
?>
```

### Manual Testing Payloads
```
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
" onmouseover="alert('XSS')
'; alert('XSS'); //
javascript:alert('XSS')
```

## 10. Monitoring and Logging

### Log Suspicious Activity
```php
<?php
function logSuspiciousInput($input, $type) {
    $suspiciousPatterns = [
        '/<script/',
        '/javascript:/',
        '/on\w+\s*=/',
        '/<iframe/',
        '/<object/',
        '/<embed/'
    ];
    
    foreach ($suspiciousPatterns as $pattern) {
        if (preg_match($pattern, $input)) {
            error_log("Suspicious input detected: $type - $input");
            // Could also send alerts, block IP, etc.
            break;
        }
    }
}
?>
```

## 11. Configuration Examples

### Apache .htaccess
```apache
# Security headers
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# CSP header
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
```

### Nginx Configuration
```nginx
# Security headers
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options DENY;
add_header X-XSS-Protection "1; mode=block";
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';";
```

## 12. Best Practices Summary

1. **Validate Input**: Use whitelist validation on server-side
2. **Encode Output**: Use context-appropriate encoding
3. **Use CSP**: Implement Content Security Policy
4. **Set Headers**: Use security headers as defense-in-depth
5. **Sanitize HTML**: Use trusted libraries for HTML sanitization
6. **Safe DOM**: Use safe JavaScript methods for DOM manipulation
7. **CSRF Protection**: Implement token-based CSRF protection
8. **Test Regularly**: Automated and manual security testing
9. **Monitor**: Log and monitor suspicious activities
10. **Keep Updated**: Stay updated with latest security practices

## 13. Common Mistakes to Avoid

- Don't rely only on client-side validation
- Don't use blacklist filtering (use whitelist instead)
- Don't trust user input in any context
- Don't use `innerHTML` with user data
- Don't disable XSS protection headers
- Don't use `eval()` or similar functions with user input
- Don't forget to encode output in all contexts
- Don't use outdated security practices