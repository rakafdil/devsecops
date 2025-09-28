<?php
session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Contexts - Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .vulnerability-badge { background-color: #dc3545; }
        .code-example { background-color: #f8f9fa; padding: 15px; border-left: 4px solid #dc3545; }
        .context-example { border: 2px solid #007bff; padding: 15px; margin: 10px 0; }
        .dangerous { border-color: #dc3545 !important; background-color: #fff5f5; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <span class="badge vulnerability-badge">VULNERABLE</span>
                XSS Lab
            </a>
            <div class="navbar-nav">
                <a class="nav-link" href="index.php">Home</a>
                <a class="nav-link" href="reflected.php">Reflected XSS</a>
                <a class="nav-link" href="stored.php">Stored XSS</a>
                <a class="nav-link" href="dom.php">DOM XSS</a>
                <a class="nav-link active" href="contexts.php">XSS Contexts</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h1>📝 XSS in Different Contexts</h1>
        <div class="alert alert-danger">
            <strong>Kerentanan:</strong> XSS dapat terjadi dalam berbagai context HTML, membutuhkan payload yang berbeda-beda.
        </div>

        <div class="row">
            <div class="col-md-8">
                <!-- HTML Context -->
                <div class="card">
                    <div class="card-header">
                        <h5>🏷️ HTML Context XSS</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="context" value="html">
                            <div class="mb-3">
                                <label class="form-label">HTML Content Input:</label>
                                <input type="text" class="form-control" name="html_input" 
                                       value="<?php echo isset($_GET['html_input']) ? $_GET['html_input'] : ''; ?>"
                                       placeholder="Coba: <script>alert('HTML Context XSS')</script>">
                            </div>
                            <button type="submit" class="btn btn-primary">Submit</button>
                        </form>
                        
                        <?php if (isset($_GET['context']) && $_GET['context'] === 'html' && isset($_GET['html_input'])): ?>
                        <div class="context-example dangerous">
                            <strong>Output dalam HTML Context:</strong><br>
                            <div>
                                <!-- VULNERABLE - Direct output in HTML context -->
                                User said: <?php echo $_GET['html_input']; ?>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Attribute Context -->
                <div class="card mt-4">
                    <div class="card-header">
                        <h5>🔗 HTML Attribute Context XSS</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="context" value="attribute">
                            <div class="mb-3">
                                <label class="form-label">Link Title/Alt Text:</label>
                                <input type="text" class="form-control" name="attr_input" 
                                       value="<?php echo isset($_GET['attr_input']) ? $_GET['attr_input'] : ''; ?>"
                                       placeholder="Coba: \" onmouseover=\"alert('Attribute XSS')">
                            </div>
                            <button type="submit" class="btn btn-primary">Submit</button>
                        </form>
                        
                        <?php if (isset($_GET['context']) && $_GET['context'] === 'attribute' && isset($_GET['attr_input'])): ?>
                        <div class="context-example dangerous">
                            <strong>Output dalam Attribute Context:</strong><br>
                            <!-- VULNERABLE - Direct output in attribute -->
                            <img src="placeholder.jpg" alt="<?php echo $_GET['attr_input']; ?>" style="display: none;">
                            <a href="#" title="<?php echo $_GET['attr_input']; ?>">Hover over this link</a>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- JavaScript Context -->
                <div class="card mt-4">
                    <div class="card-header">
                        <h5>⚡ JavaScript Context XSS</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="context" value="javascript">
                            <div class="mb-3">
                                <label class="form-label">JavaScript Variable:</label>
                                <input type="text" class="form-control" name="js_input" 
                                       value="<?php echo isset($_GET['js_input']) ? $_GET['js_input'] : ''; ?>"
                                       placeholder="Coba: '; alert('JS Context XSS'); //">
                            </div>
                            <button type="submit" class="btn btn-primary">Submit</button>
                        </form>
                        
                        <?php if (isset($_GET['context']) && $_GET['context'] === 'javascript' && isset($_GET['js_input'])): ?>
                        <div class="context-example dangerous">
                            <strong>Output dalam JavaScript Context:</strong>
                            <script>
                                // VULNERABLE - Direct output in JavaScript
                                var userInput = '<?php echo $_GET['js_input']; ?>';
                                console.log('User input: ' + userInput);
                                document.write('<p>JavaScript processed: ' + userInput + '</p>');
                            </script>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- CSS Context -->
                <div class="card mt-4">
                    <div class="card-header">
                        <h5>🎨 CSS Context XSS</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="context" value="css">
                            <div class="mb-3">
                                <label class="form-label">CSS Color Value:</label>
                                <input type="text" class="form-control" name="css_input" 
                                       value="<?php echo isset($_GET['css_input']) ? $_GET['css_input'] : ''; ?>"
                                       placeholder="Coba: red; } body { background: url('javascript:alert(\"CSS XSS\")')">
                            </div>
                            <button type="submit" class="btn btn-primary">Submit</button>
                        </form>
                        
                        <?php if (isset($_GET['context']) && $_GET['context'] === 'css' && isset($_GET['css_input'])): ?>
                        <div class="context-example dangerous">
                            <strong>Output dalam CSS Context:</strong>
                            <style>
                                /* VULNERABLE - Direct output in CSS */
                                .user-style {
                                    color: <?php echo $_GET['css_input']; ?>;
                                    border: 1px solid black;
                                }
                            </style>
                            <div class="user-style">This text uses user-defined CSS color</div>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- URL Context -->
                <div class="card mt-4">
                    <div class="card-header">
                        <h5>🌐 URL Context XSS</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="context" value="url">
                            <div class="mb-3">
                                <label class="form-label">URL/Redirect:</label>
                                <input type="text" class="form-control" name="url_input" 
                                       value="<?php echo isset($_GET['url_input']) ? $_GET['url_input'] : ''; ?>"
                                       placeholder="Coba: javascript:alert('URL XSS')">
                            </div>
                            <button type="submit" class="btn btn-primary">Submit</button>
                        </form>
                        
                        <?php if (isset($_GET['context']) && $_GET['context'] === 'url' && isset($_GET['url_input'])): ?>
                        <div class="context-example dangerous">
                            <strong>Output dalam URL Context:</strong><br>
                            <!-- VULNERABLE - Direct output in href -->
                            <a href="<?php echo $_GET['url_input']; ?>">Click this link</a><br>
                            <iframe src="<?php echo $_GET['url_input']; ?>" style="width: 100%; height: 100px; border: 1px solid #ccc;" title="URL Frame"></iframe>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Event Handler Context -->
                <div class="card mt-4">
                    <div class="card-header">
                        <h5>🖱️ Event Handler Context XSS</h5>
                    </div>
                    <div class="card-body">
                        <form method="GET">
                            <input type="hidden" name="context" value="event">
                            <div class="mb-3">
                                <label class="form-label">Event Handler Code:</label>
                                <input type="text" class="form-control" name="event_input" 
                                       value="<?php echo isset($_GET['event_input']) ? $_GET['event_input'] : ''; ?>"
                                       placeholder="Coba: alert('Event Handler XSS')">
                            </div>
                            <button type="submit" class="btn btn-primary">Submit</button>
                        </form>
                        
                        <?php if (isset($_GET['context']) && $_GET['context'] === 'event' && isset($_GET['event_input'])): ?>
                        <div class="context-example dangerous">
                            <strong>Output dalam Event Handler Context:</strong><br>
                            <!-- VULNERABLE - Direct output in event handler -->
                            <button onclick="<?php echo $_GET['event_input']; ?>">Click Me</button>
                            <div onmouseover="<?php echo $_GET['event_input']; ?>" style="padding: 10px; border: 1px solid blue; cursor: pointer;">
                                Hover over this div
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h5>💡 Context-Specific Payloads</h5>
                    </div>
                    <div class="card-body">
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

                        <h6 class="mt-3">CSS Context:</h6>
                        <div class="code-example">
                            <code>red; } body { background: url('javascript:alert(1)')</code>
                        </div>

                        <h6 class="mt-3">URL Context:</h6>
                        <div class="code-example">
                            <code>javascript:alert('XSS')</code><br>
                            <code>data:text/html,&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
                        </div>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header">
                        <h5>🛡️ Context-Specific Fixes</h5>
                    </div>
                    <div class="card-body">
                        <small>
                            <h6>HTML Context:</h6>
                            <code>htmlspecialchars($input, ENT_QUOTES)</code>

                            <h6 class="mt-2">Attribute Context:</h6>
                            <code>htmlspecialchars($input, ENT_QUOTES)</code>

                            <h6 class="mt-2">JavaScript Context:</h6>
                            <code>json_encode($input)</code>

                            <h6 class="mt-2">CSS Context:</h6>
                            <code>preg_replace('/[^a-zA-Z0-9#]/', '', $input)</code>

                            <h6 class="mt-2">URL Context:</h6>
                            <code>filter_var($input, FILTER_VALIDATE_URL)</code>
                        </small>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header">
                        <h5>📋 Context Identification</h5>
                    </div>
                    <div class="card-body">
                        <ul class="small">
                            <li><strong>HTML Body:</strong> Between tags</li>
                            <li><strong>Attribute:</strong> Inside tag attributes</li>
                            <li><strong>JavaScript:</strong> Inside &lt;script&gt; tags</li>
                            <li><strong>CSS:</strong> Inside &lt;style&gt; tags</li>
                            <li><strong>URL:</strong> In href, src attributes</li>
                            <li><strong>Event Handler:</strong> onclick, onload, etc.</li>
                        </ul>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header">
                        <h5>⚠️ Key Points</h5>
                    </div>
                    <div class="card-body">
                        <ul class="small">
                            <li>Different contexts need different encoding</li>
                            <li>HTML encoding ≠ JavaScript encoding</li>
                            <li>Always identify the output context</li>
                            <li>Use context-appropriate sanitization</li>
                            <li>Consider using CSP as defense-in-depth</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="alert alert-warning mt-4">
            <h5>📝 Learning Notes:</h5>
            <ul>
                <li><strong>Context matters!</strong> Setiap context HTML membutuhkan encoding yang berbeda</li>
                <li><strong>HTML Context:</strong> &lt;, &gt;, &amp;, " perlu di-encode</li>
                <li><strong>Attribute Context:</strong> Quotes dan event handlers berbahaya</li>
                <li><strong>JavaScript Context:</strong> String escaping dan code injection</li>
                <li><strong>CSS Context:</strong> Expression() dan url() functions berbahaya</li>
                <li><strong>URL Context:</strong> javascript:, data: schemes berbahaya</li>
                <li>Gunakan encoding library yang tepat untuk setiap context</li>
            </ul>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>