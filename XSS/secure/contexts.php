<?php
require_once 'vendor/autoload.php';
require_once 'src/Security.php';

use App\Security;

// Set security headers
$csp_headers = Security::getCSPHeader();
foreach ($csp_headers as $header => $value) {
    header("$header: $value");
}
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure XSS Context Prevention</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .security-badge { background-color: #28a745; }
        .code-example { background-color: #f8f9fa; padding: 15px; border-left: 4px solid #28a745; }
        .context-example { border: 2px solid #28a745; padding: 15px; margin: 10px 0; background-color: #f8fff9; }
        .safe-output { background-color: #e8f5e8; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-success">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <span class="badge security-badge">🛡️ SECURE</span>
                XSS Prevention Lab
            </a>
            <div class="navbar-nav">
                <a class="nav-link text-white" href="index.php">Home</a>
                <a class="nav-link text-white" href="reflected.php">Secure Reflected</a>
                <a class="nav-link text-white" href="stored.php">Secure Stored</a>
                <a class="nav-link text-white" href="dom.php">Secure DOM</a>
                <a class="nav-link text-white" href="contexts.php" style="background-color: rgba(255,255,255,0.2);">Secure Contexts</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h1>✅ Secure XSS Context Prevention</h1>
        <div class="alert alert-success">
            <strong>Security Implementation:</strong> Context-aware encoding and input validation for all HTML contexts.
        </div>

        <div class="row">
            <div class="col-md-8">
                <!-- HTML Context -->
                <div class="card">
                    <div class="card-header bg-success text-white">
                        <h5>🔒 Secure HTML Context</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="context" value="html">
                            <input type="hidden" name="csrf_token" value="<?php echo Security::generateCSRFToken(); ?>">
                            <div class="mb-3">
                                <label class="form-label">HTML Content Input:</label>
                                <input type="text" class="form-control" name="html_input" 
                                       value="<?php echo isset($_GET['html_input']) ? Security::escapeAttr($_GET['html_input']) : ''; ?>"
                                       maxlength="200"
                                       placeholder="Try: <script>alert('HTML Context XSS')</script>">
                            </div>
                            <button type="submit" class="btn btn-success">🛡️ Safe Submit</button>
                        </form>
                        
                        <?php 
                        if (isset($_GET['context']) && $_GET['context'] === 'html' && isset($_GET['html_input'])) {
                            // CSRF check
                            if (isset($_GET['csrf_token']) && Security::validateCSRFToken($_GET['csrf_token'])) {
                                // Input validation and sanitization
                                $html_input = Security::validateInput($_GET['html_input'], 'string', 200);
                        ?>
                        <div class="context-example safe-output">
                            <strong>Secure HTML Context Output:</strong><br>
                            <div>
                                <!-- SECURE - HTML-encoded output -->
                                User said: <?php echo Security::escapeHtml($html_input); ?>
                            </div>
                            <small class="text-success">
                                🛡️ Protected with: <code>htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8')</code>
                            </small>
                        </div>
                        <?php 
                            } else {
                                echo '<div class="alert alert-warning">Invalid CSRF token or input.</div>';
                            }
                        } 
                        ?>
                    </div>
                </div>

                <!-- Attribute Context -->
                <div class="card mt-4">
                    <div class="card-header bg-success text-white">
                        <h5>🔒 Secure HTML Attribute Context</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="context" value="attribute">
                            <input type="hidden" name="csrf_token" value="<?php echo Security::generateCSRFToken(); ?>">
                            <div class="mb-3">
                                <label class="form-label">Link Title/Alt Text:</label>
                                <input type="text" class="form-control" name="attr_input" 
                                       value="<?php echo isset($_GET['attr_input']) ? Security::escapeAttr($_GET['attr_input']) : ''; ?>"
                                       maxlength="100"
                                       pattern="[a-zA-Z0-9\s\-_.,!?]{1,100}"
                                       title="Only letters, numbers, spaces, and basic punctuation allowed"
                                       placeholder="Try: \" onmouseover=\"alert('Attribute XSS')">
                            </div>
                            <button type="submit" class="btn btn-success">🛡️ Safe Submit</button>
                        </form>
                        
                        <?php 
                        if (isset($_GET['context']) && $_GET['context'] === 'attribute' && isset($_GET['attr_input'])) {
                            if (isset($_GET['csrf_token']) && Security::validateCSRFToken($_GET['csrf_token'])) {
                                $attr_input = Security::validateInput($_GET['attr_input'], 'string', 100);
                                // Additional validation for attributes
                                if (preg_match('/^[a-zA-Z0-9\s\-_.,!?]{1,100}$/', $attr_input)) {
                        ?>
                        <div class="context-example safe-output">
                            <strong>Secure Attribute Context Output:</strong><br>
                            <!-- SECURE - Properly encoded attributes -->
                            <img src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='50'%3E%3Crect width='100' height='50' fill='lightblue'/%3E%3Ctext x='10' y='30'%3EImage%3C/text%3E%3C/svg%3E" 
                                 alt="<?php echo Security::escapeAttr($attr_input); ?>" 
                                 style="border: 1px solid #ccc;">
                            <br><br>
                            <a href="#safe-link" title="<?php echo Security::escapeAttr($attr_input); ?>">Hover over this safe link</a>
                            <br><br>
                            <small class="text-success">
                                🛡️ Protected with: Strict regex validation + <code>htmlspecialchars()</code> for attributes
                            </small>
                        </div>
                        <?php 
                                } else {
                                    echo '<div class="alert alert-danger">Invalid characters in input. Only alphanumeric and basic punctuation allowed.</div>';
                                }
                            } else {
                                echo '<div class="alert alert-warning">Invalid CSRF token.</div>';
                            }
                        } 
                        ?>
                    </div>
                </div>

                <!-- JavaScript Context -->
                <div class="card mt-4">
                    <div class="card-header bg-success text-white">
                        <h5>🔒 Secure JavaScript Context</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="context" value="javascript">
                            <input type="hidden" name="csrf_token" value="<?php echo Security::generateCSRFToken(); ?>">
                            <div class="mb-3">
                                <label class="form-label">JavaScript Variable Value:</label>
                                <input type="text" class="form-control" name="js_input" 
                                       value="<?php echo isset($_GET['js_input']) ? Security::escapeAttr($_GET['js_input']) : ''; ?>"
                                       maxlength="50"
                                       pattern="[a-zA-Z0-9\s]{1,50}"
                                       title="Only letters, numbers, and spaces allowed"
                                       placeholder="Try: '; alert('JS Context XSS'); //">
                            </div>
                            <button type="submit" class="btn btn-success">🛡️ Safe Submit</button>
                        </form>
                        
                        <?php 
                        if (isset($_GET['context']) && $_GET['context'] === 'javascript' && isset($_GET['js_input'])) {
                            if (isset($_GET['csrf_token']) && Security::validateCSRFToken($_GET['csrf_token'])) {
                                $js_input = Security::validateInput($_GET['js_input'], 'string', 50);
                                // Strict validation for JavaScript context
                                if (preg_match('/^[a-zA-Z0-9\s]{1,50}$/', $js_input)) {
                        ?>
                        <div class="context-example safe-output">
                            <strong>Secure JavaScript Context Output:</strong>
                            <div id="js-output-<?php echo uniqid(); ?>"></div>
                            <script>
                                // SECURE - Using JSON encoding for JavaScript context
                                (function() {
                                    var userInput = <?php echo Security::escapeJs($js_input); ?>;
                                    var outputDiv = document.getElementById('js-output-<?php echo substr(md5($js_input), 0, 8); ?>');
                                    if (outputDiv) {
                                        outputDiv.textContent = 'JavaScript processed safely: ' + userInput;
                                        outputDiv.style.padding = '10px';
                                        outputDiv.style.backgroundColor = '#e8f5e8';
                                        outputDiv.style.border = '1px solid #28a745';
                                    }
                                })();
                            </script>
                            <small class="text-success">
                                🛡️ Protected with: Strict regex validation + <code>json_encode()</code> with security flags
                            </small>
                        </div>
                        <?php 
                                } else {
                                    echo '<div class="alert alert-danger">Invalid input for JavaScript context. Only alphanumeric characters and spaces allowed.</div>';
                                }
                            } else {
                                echo '<div class="alert alert-warning">Invalid CSRF token.</div>';
                            }
                        } 
                        ?>
                    </div>
                </div>

                <!-- CSS Context -->
                <div class="card mt-4">
                    <div class="card-header bg-success text-white">
                        <h5>🔒 Secure CSS Context</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="context" value="css">
                            <input type="hidden" name="csrf_token" value="<?php echo Security::generateCSRFToken(); ?>">
                            <div class="mb-3">
                                <label class="form-label">CSS Color Value:</label>
                                <select class="form-select" name="css_input">
                                    <option value="">Select a color</option>
                                    <option value="red" <?php echo (isset($_GET['css_input']) && $_GET['css_input'] === 'red') ? 'selected' : ''; ?>>Red</option>
                                    <option value="blue" <?php echo (isset($_GET['css_input']) && $_GET['css_input'] === 'blue') ? 'selected' : ''; ?>>Blue</option>
                                    <option value="green" <?php echo (isset($_GET['css_input']) && $_GET['css_input'] === 'green') ? 'selected' : ''; ?>>Green</option>
                                    <option value="purple" <?php echo (isset($_GET['css_input']) && $_GET['css_input'] === 'purple') ? 'selected' : ''; ?>>Purple</option>
                                    <option value="orange" <?php echo (isset($_GET['css_input']) && $_GET['css_input'] === 'orange') ? 'selected' : ''; ?>>Orange</option>
                                </select>
                                <small class="form-text text-muted">Using dropdown instead of text input for maximum security</small>
                            </div>
                            <button type="submit" class="btn btn-success">🛡️ Safe Submit</button>
                        </form>
                        
                        <?php 
                        if (isset($_GET['context']) && $_GET['context'] === 'css' && isset($_GET['css_input'])) {
                            if (isset($_GET['csrf_token']) && Security::validateCSRFToken($_GET['csrf_token'])) {
                                // Whitelist validation for CSS colors
                                $allowed_colors = ['red', 'blue', 'green', 'purple', 'orange'];
                                $css_input = $_GET['css_input'];
                                
                                if (in_array($css_input, $allowed_colors)) {
                        ?>
                        <div class="context-example safe-output">
                            <strong>Secure CSS Context Output:</strong>
                            <style>
                                /* SECURE - Whitelisted CSS value only */
                                .safe-user-style-<?php echo md5($css_input); ?> {
                                    color: <?php echo $css_input; ?>;
                                    border: 2px solid <?php echo $css_input; ?>;
                                    padding: 10px;
                                    background-color: rgba(0,0,0,0.1);
                                }
                            </style>
                            <div class="safe-user-style-<?php echo md5($css_input); ?>">
                                This text uses the selected color: <?php echo Security::escapeHtml($css_input); ?>
                            </div>
                            <small class="text-success">
                                🛡️ Protected with: Whitelist validation - only predefined colors allowed
                            </small>
                        </div>
                        <?php 
                                } else {
                                    echo '<div class="alert alert-danger">Invalid color selection.</div>';
                                }
                            } else {
                                echo '<div class="alert alert-warning">Invalid CSRF token.</div>';
                            }
                        } 
                        ?>
                    </div>
                </div>

                <!-- URL Context -->
                <div class="card mt-4">
                    <div class="card-header bg-success text-white">
                        <h5>🔒 Secure URL Context</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="context" value="url">
                            <input type="hidden" name="csrf_token" value="<?php echo Security::generateCSRFToken(); ?>">
                            <div class="mb-3">
                                <label class="form-label">External Link URL:</label>
                                <input type="url" class="form-control" name="url_input" 
                                       value="<?php echo isset($_GET['url_input']) ? Security::escapeAttr($_GET['url_input']) : ''; ?>"
                                       placeholder="https://example.com"
                                       pattern="https://.*"
                                       title="Only HTTPS URLs are allowed">
                                <small class="form-text text-muted">Only HTTPS URLs are accepted for security</small>
                            </div>
                            <button type="submit" class="btn btn-success">🛡️ Safe Submit</button>
                        </form>
                        
                        <?php 
                        if (isset($_GET['context']) && $_GET['context'] === 'url' && isset($_GET['url_input'])) {
                            if (isset($_GET['csrf_token']) && Security::validateCSRFToken($_GET['csrf_token'])) {
                                $url_input = Security::sanitizeUrl($_GET['url_input']);
                                
                                // Additional HTTPS validation
                                if (filter_var($url_input, FILTER_VALIDATE_URL) && strpos($url_input, 'https://') === 0) {
                        ?>
                        <div class="context-example safe-output">
                            <strong>Secure URL Context Output:</strong><br>
                            <!-- SECURE - Validated and sanitized URL -->
                            <a href="<?php echo Security::escapeAttr($url_input); ?>" 
                               target="_blank" rel="noopener noreferrer"
                               style="color: green; text-decoration: underline;">
                               Visit: <?php echo Security::escapeHtml($url_input); ?>
                            </a>
                            <br><br>
                            <small class="text-success">
                                🛡️ Protected with: HTTPS-only validation + <code>rel="noopener noreferrer"</code> + URL sanitization
                            </small>
                        </div>
                        <?php 
                                } else {
                                    echo '<div class="alert alert-danger">Invalid URL. Only HTTPS URLs are allowed.</div>';
                                }
                            } else {
                                echo '<div class="alert alert-warning">Invalid CSRF token.</div>';
                            }
                        } 
                        ?>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h5>🧪 Test Malicious Payloads</h5>
                    </div>
                    <div class="card-body">
                        <p>All context-specific XSS payloads are safely handled:</p>
                        
                        <h6>HTML Context:</h6>
                        <div class="code-example">
                            <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
                            <code>&lt;img src=x onerror=alert('XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">Attribute Context:</h6>
                        <div class="code-example">
                            <code>" onmouseover="alert('XSS')</code><br>
                            <code>' onfocus='alert('XSS')</code>
                        </div>

                        <h6 class="mt-3">JavaScript Context:</h6>
                        <div class="code-example">
                            <code>'; alert('XSS'); //</code><br>
                            <code>\"; alert('XSS'); //</code>
                        </div>

                        <h6 class="mt-3">URL Context:</h6>
                        <div class="code-example">
                            <code>javascript:alert('XSS')</code><br>
                            <code>data:text/html,&lt;script&gt;alert('XSS')</code>
                        </div>

                        <div class="alert alert-success mt-3">
                            <strong>✅ Result:</strong> All payloads are blocked or safely encoded!
                        </div>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header bg-success text-white">
                        <h5>🔧 Security Implementations</h5>
                    </div>
                    <div class="card-body">
                        <h6>HTML Context:</h6>
                        <small>
                            <pre><code>Security::escapeHtml($input)
// htmlspecialchars($input, 
//   ENT_QUOTES | ENT_HTML5, 'UTF-8')</code></pre>
                        </small>

                        <h6 class="mt-3">Attribute Context:</h6>
                        <small>
                            <pre><code>Security::escapeAttr($input)
// + regex validation
preg_match('/^[a-zA-Z0-9\s\-_.,!?]+$/', $input)</code></pre>
                        </small>

                        <h6 class="mt-3">JavaScript Context:</h6>
                        <small>
                            <pre><code>Security::escapeJs($input)
// json_encode($input, JSON_HEX_TAG | 
//   JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)</code></pre>
                        </small>

                        <h6 class="mt-3">CSS Context:</h6>
                        <small>
                            <pre><code>// Whitelist approach
$allowed = ['red', 'blue', 'green'];
in_array($input, $allowed)</code></pre>
                        </small>

                        <h6 class="mt-3">URL Context:</h6>
                        <small>
                            <pre><code>Security::sanitizeUrl($input)
// + HTTPS-only validation
// + rel="noopener noreferrer"</code></pre>
                        </small>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header bg-warning text-dark">
                        <h5>📋 Context-Specific Security</h5>
                    </div>
                    <div class="card-body">
                        <ul class="small">
                            <li><strong>HTML:</strong> Encode &lt;, &gt;, &amp;, ", '</li>
                            <li><strong>Attribute:</strong> Encode quotes + regex validation</li>
                            <li><strong>JavaScript:</strong> JSON encode + strict validation</li>
                            <li><strong>CSS:</strong> Whitelist values only</li>
                            <li><strong>URL:</strong> HTTPS-only + dangerous scheme blocking</li>
                            <li><strong>All:</strong> CSRF tokens + input length limits</li>
                        </ul>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header bg-primary text-white">
                        <h5>🛡️ Defense Layers</h5>
                    </div>
                    <div class="card-body">
                        <ol class="small">
                            <li><strong>Input Validation:</strong> Server-side validation</li>
                            <li><strong>Context Detection:</strong> Identify output context</li>
                            <li><strong>Appropriate Encoding:</strong> Context-specific encoding</li>
                            <li><strong>Whitelist Validation:</strong> Only allow safe values</li>
                            <li><strong>CSRF Protection:</strong> Prevent unauthorized requests</li>
                            <li><strong>Security Headers:</strong> CSP, X-XSS-Protection</li>
                            <li><strong>Content Filtering:</strong> Remove dangerous elements</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <div class="alert alert-info mt-4">
            <h5>📝 Learning Notes - Context-Aware XSS Prevention:</h5>
            <ul>
                <li><strong>Different Contexts, Different Rules:</strong> Each HTML context requires specific encoding</li>
                <li><strong>Layered Security:</strong> Input validation + context-aware encoding + security headers</li>
                <li><strong>Whitelist > Blacklist:</strong> Use whitelist validation whenever possible</li>
                <li><strong>Strict Validation:</strong> Validate input format, length, and content</li>
                <li><strong>CSRF Protection:</strong> Always include CSRF tokens in forms</li>
                <li><strong>Safe Defaults:</strong> Fail securely when validation fails</li>
                <li><strong>Regular Testing:</strong> Test with various payloads and contexts</li>
            </ul>
        </div>

        <div class="alert alert-secondary mt-4">
            <h5>🔄 Compare Context Handling</h5>
            <p>See how context-specific payloads behave in vulnerable vs secure implementations:</p>
            <a href="http://localhost:8080/contexts.php" target="_blank" class="btn btn-outline-danger">
                ⚠️ Test in Vulnerable App
            </a>
            <p class="mt-2"><small>Try the same context-specific payloads in both applications!</small></p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Additional client-side validation (defense in depth)
        document.addEventListener('DOMContentLoaded', function() {
            // HTML context validation
            const htmlInput = document.querySelector('input[name="html_input"]');
            if (htmlInput) {
                htmlInput.addEventListener('input', function() {
                    if (this.value.includes('<') || this.value.includes('>')) {
                        this.setCustomValidity('HTML tags are not allowed');
                        this.style.borderColor = 'red';
                    } else {
                        this.setCustomValidity('');
                        this.style.borderColor = '';
                    }
                });
            }
            
            // Attribute context validation
            const attrInput = document.querySelector('input[name="attr_input"]');
            if (attrInput) {
                attrInput.addEventListener('input', function() {
                    if (!/^[a-zA-Z0-9\s\-_.,!?]*$/.test(this.value)) {
                        this.setCustomValidity('Only letters, numbers, spaces, and basic punctuation allowed');
                        this.style.borderColor = 'red';
                    } else {
                        this.setCustomValidity('');
                        this.style.borderColor = '';
                    }
                });
            }
            
            // JavaScript context validation
            const jsInput = document.querySelector('input[name="js_input"]');
            if (jsInput) {
                jsInput.addEventListener('input', function() {
                    if (!/^[a-zA-Z0-9\s]*$/.test(this.value)) {
                        this.setCustomValidity('Only letters, numbers, and spaces allowed');
                        this.style.borderColor = 'red';
                    } else {
                        this.setCustomValidity('');
                        this.style.borderColor = '';
                    }
                });
            }
            
            // URL context validation
            const urlInput = document.querySelector('input[name="url_input"]');
            if (urlInput) {
                urlInput.addEventListener('input', function() {
                    if (this.value && !this.value.startsWith('https://')) {
                        this.setCustomValidity('Only HTTPS URLs are allowed');
                        this.style.borderColor = 'red';
                    } else {
                        this.setCustomValidity('');
                        this.style.borderColor = '';
                    }
                });
            }
        });
        
        // Security information display
        function showContextSecurity() {
            const info = `
🛡️ Context-Aware XSS Prevention:

📍 HTML Context:
• htmlspecialchars() with ENT_QUOTES
• Encodes: < > & " '

📍 Attribute Context:  
• HTML encoding + regex validation
• Prevents quote-breaking attacks

📍 JavaScript Context:
• JSON encoding with security flags
• Prevents script injection

📍 CSS Context:
• Whitelist validation only
• No user input in CSS expressions

📍 URL Context:
• HTTPS-only validation
• Dangerous scheme blocking
• rel="noopener noreferrer"

🔒 All contexts include CSRF protection!
            `.trim();
            
            alert(info);
        }
        
        // Make function globally available
        window.showContextSecurity = showContextSecurity;
    </script>
</body>
</html>