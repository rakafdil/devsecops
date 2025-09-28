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
    <title>Secure DOM XSS Prevention</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .security-badge { background-color: #28a745; }
        .code-example { background-color: #f8f9fa; padding: 15px; border-left: 4px solid #28a745; }
        .output-box { min-height: 100px; border: 2px solid #28a745; padding: 15px; background-color: #f8fff9; }
        .safe-demo { background-color: #e8f5e8; }
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
                <a class="nav-link text-white" href="dom.php" style="background-color: rgba(255,255,255,0.2);">Secure DOM</a>
                <a class="nav-link text-white" href="contexts.php">Secure Contexts</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h1>✅ Secure DOM XSS Prevention</h1>
        <div class="alert alert-success">
            <strong>Security Implementation:</strong> Safe JavaScript practices, input validation, and secure DOM manipulation.
        </div>

        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header bg-success text-white">
                        <h5>🔒 Safe URL Fragment Handling</h5>
                    </div>
                    <div class="card-body safe-demo">
                        <p>This example safely handles URL fragments using <code>textContent</code> instead of <code>innerHTML</code>.</p>
                        <p><strong>Try URL:</strong> <code>dom.php#&lt;script&gt;alert('DOM XSS!')&lt;/script&gt;</code></p>
                        
                        <div id="welcome-message" class="output-box">
                            <em>Loading safe welcome message...</em>
                        </div>

                        <button onclick="safeUpdateWelcome()" class="btn btn-success mt-2">🛡️ Safe Refresh Message</button>
                        
                        <div class="alert alert-info mt-3">
                            <strong>🛡️ Security:</strong> Using <code>textContent</code> - all HTML/JavaScript is displayed as plain text.
                        </div>
                    </div>
                </div>

                <div class="card mt-4">
                    <div class="card-header bg-success text-white">
                        <h5>🔒 Safe User Input Display</h5>
                    </div>
                    <div class="card-body safe-demo">
                        <p>Input is validated and safely displayed using secure JavaScript methods.</p>
                        <form id="safeUrlParamForm">
                            <div class="mb-3">
                                <label for="userInput" class="form-label">User Input:</label>
                                <input type="text" class="form-control" id="userInput" 
                                       maxlength="500"
                                       placeholder="Try: <img src=x onerror=alert('DOM XSS')>">
                            </div>
                            <button type="button" onclick="safeDisplayUserInput()" class="btn btn-success">🛡️ Safe Display</button>
                        </form>

                        <div id="user-output" class="output-box mt-3">
                            <em>Secure output will be displayed here...</em>
                        </div>
                        
                        <div class="alert alert-info mt-3">
                            <strong>🛡️ Security:</strong> Input is validated and HTML-encoded before display.
                        </div>
                    </div>
                </div>

                <div class="card mt-4">
                    <div class="card-header bg-success text-white">
                        <h5>🔒 Safe Dynamic Content Loading</h5>
                    </div>
                    <div class="card-body safe-demo">
                        <p>Content loaded using whitelisted values and safe DOM methods.</p>
                        <div class="btn-group" role="group">
                            <button onclick="safeLoadPage('home')" class="btn btn-outline-success">Home</button>
                            <button onclick="safeLoadPage('about')" class="btn btn-outline-success">About</button>
                            <button onclick="safeLoadPage('contact')" class="btn btn-outline-success">Contact</button>
                        </div>
                        
                        <div class="mt-3">
                            <strong>Manual Page (Validated):</strong>
                            <select id="manualPageSelect" class="form-select d-inline-block" style="width: 200px;">
                                <option value="home">Home</option>
                                <option value="about">About</option>
                                <option value="contact">Contact</option>
                                <option value="invalid">Invalid Option</option>
                            </select>
                            <button onclick="safeLoadPageFromSelect()" class="btn btn-warning">🛡️ Safe Load</button>
                        </div>

                        <div id="page-content" class="output-box mt-3">
                            <em>Select a page to load secure content...</em>
                        </div>
                        
                        <div class="alert alert-info mt-3">
                            <strong>🛡️ Security:</strong> Whitelist validation - only predefined pages can be loaded.
                        </div>
                    </div>
                </div>

                <div class="card mt-4">
                    <div class="card-header bg-success text-white">
                        <h5>🔒 Safe Search Implementation</h5>
                    </div>
                    <div class="card-body safe-demo">
                        <input type="text" id="searchInput" placeholder="Search term" class="form-control" maxlength="100">
                        <button onclick="safePerformSearch()" class="btn btn-success mt-2">🛡️ Safe Search</button>
                        
                        <div id="search-results" class="output-box mt-3">
                            <em>Safe search results will appear here...</em>
                        </div>
                        
                        <div class="alert alert-info mt-3">
                            <strong>🛡️ Security:</strong> Using safe DOM manipulation methods instead of innerHTML.
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h5>🧪 Test Malicious Payloads</h5>
                    </div>
                    <div class="card-body">
                        <p>All these DOM XSS payloads are safely handled:</p>
                        
                        <h6>Fragment-based:</h6>
                        <div class="code-example">
                            <code>#&lt;script&gt;alert('DOM XSS')&lt;/script&gt;</code>
                        </div>

                        <h6 class="mt-3">Image Onerror:</h6>
                        <div class="code-example">
                            <code>&lt;img src=x onerror=alert('DOM XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">SVG Onload:</h6>
                        <div class="code-example">
                            <code>&lt;svg onload=alert('DOM XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">Event Handler:</h6>
                        <div class="code-example">
                            <code>&lt;div onmouseover=alert('XSS')&gt;Hover&lt;/div&gt;</code>
                        </div>

                        <div class="alert alert-success mt-3">
                            <strong>✅ Result:</strong> All payloads displayed as safe text!
                        </div>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header bg-success text-white">
                        <h5>🔧 Secure JavaScript Patterns</h5>
                    </div>
                    <div class="card-body">
                        <h6>Safe DOM Manipulation:</h6>
                        <small>
                            <pre><code>// SAFE methods
element.textContent = userInput;
element.appendChild(textNode);
element.setAttribute('title', cleanInput);

// Create elements safely
const div = document.createElement('div');
div.textContent = userInput;</code></pre>
                        </small>

                        <h6 class="mt-3">Input Validation:</h6>
                        <small>
                            <pre><code>// Whitelist validation
function validatePage(page) {
    const allowed = ['home', 'about', 'contact'];
    return allowed.includes(page);
}

// HTML encoding function
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}</code></pre>
                        </small>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header bg-danger text-white">
                        <h5>⚠️ Avoided Dangerous Methods</h5>
                    </div>
                    <div class="card-body">
                        <ul class="small">
                            <li><strike><code>innerHTML</code></strike> → <code>textContent</code></li>
                            <li><strike><code>outerHTML</code></strike> → Safe DOM methods</li>
                            <li><strike><code>document.write()</code></strike> → <code>appendChild()</code></li>
                            <li><strike><code>eval()</code></strike> → Proper parsing</li>
                            <li><strike><code>setTimeout(string)</code></strike> → Function refs</li>
                            <li><strike>Direct URL params</strike> → Validation first</li>
                        </ul>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header bg-warning text-dark">
                        <h5>📋 Security Checklist</h5>
                    </div>
                    <div class="card-body">
                        <ul class="small">
                            <li>✅ Input validation & sanitization</li>
                            <li>✅ Whitelist approach for dynamic content</li>
                            <li>✅ Safe DOM manipulation methods</li>
                            <li>✅ No eval() or innerHTML with user data</li>
                            <li>✅ Content Security Policy headers</li>
                            <li>✅ HTML encoding for display</li>
                            <li>✅ Length limits on inputs</li>
                            <li>✅ Error handling without data exposure</li>
                        </ul>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header bg-primary text-white">
                        <h5>📖 Code Comparison</h5>
                    </div>
                    <div class="card-body">
                        <h6>Vulnerable (DON'T DO):</h6>
                        <small>
                            <pre style="color: red;"><code>// DANGEROUS
element.innerHTML = userInput;
document.write(userInput);
eval(userInput);</code></pre>
                        </small>
                        
                        <h6>Secure (DO THIS):</h6>
                        <small>
                            <pre style="color: green;"><code>// SAFE
element.textContent = userInput;
element.appendChild(textNode);
validateInput(userInput);</code></pre>
                        </small>
                    </div>
                </div>
            </div>
        </div>

        <div class="alert alert-info mt-4">
            <h5>📝 Learning Notes - DOM XSS Prevention:</h5>
            <ul>
                <li><strong>Use Safe Methods:</strong> textContent, appendChild, createElement instead of innerHTML</li>
                <li><strong>Validate Inputs:</strong> Use whitelist validation for all user inputs</li>
                <li><strong>Avoid Dangerous Functions:</strong> Never use eval(), innerHTML, document.write() with user data</li>
                <li><strong>CSP Protection:</strong> Content Security Policy as additional protection layer</li>
                <li><strong>HTML Encoding:</strong> Encode data when displaying, even with safe methods</li>
                <li><strong>URL Validation:</strong> Always validate and sanitize URL parameters</li>
                <li><strong>Error Handling:</strong> Fail securely without exposing sensitive information</li>
            </ul>
        </div>

        <div class="alert alert-secondary mt-4">
            <h5>🔄 Compare Implementations</h5>
            <p>See how the same user inputs behave differently:</p>
            <a href="http://localhost:8080/dom.php" target="_blank" class="btn btn-outline-danger">
                ⚠️ Test Vulnerable DOM XSS
            </a>
            <p class="mt-2"><small>Try the same payloads in both versions to see the difference!</small></p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // SECURE JavaScript Implementation - DOM XSS Prevention
        
        // HTML encoding function (for safe display)
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Input validation function
        function validateInput(input, maxLength = 500) {
            if (typeof input !== 'string') return false;
            if (input.length > maxLength) return false;
            if (input.length === 0) return false;
            return true;
        }
        
        // Page validation function (whitelist approach)
        function validatePage(page) {
            const allowedPages = ['home', 'about', 'contact'];
            return allowedPages.includes(page);
        }
        
        // SECURE: Safe URL Fragment handling
        function safeUpdateWelcome() {
            const fragment = window.location.hash.substring(1);
            const welcomeDiv = document.getElementById('welcome-message');
            
            if (fragment && validateInput(fragment, 100)) {
                // SECURE - Using textContent instead of innerHTML
                welcomeDiv.textContent = "Welcome, " + decodeURIComponent(fragment) + "! (Safely displayed)";
            } else {
                welcomeDiv.textContent = "Welcome! Add your name to URL fragment (safely handled)";
            }
        }

        // SECURE: Safe user input display  
        function safeDisplayUserInput() {
            const input = document.getElementById('userInput').value;
            const outputDiv = document.getElementById('user-output');
            
            // Input validation
            if (!validateInput(input)) {
                outputDiv.textContent = "Invalid input! Please enter valid text (max 500 chars).";
                outputDiv.style.color = 'red';
                return;
            }
            
            // SECURE - Using textContent, not innerHTML
            outputDiv.textContent = "You entered: " + input + " (safely displayed)";
            outputDiv.style.color = 'green';
        }

        // SECURE: Safe dynamic content loading with whitelist
        function safeLoadPage(page) {
            const contentDiv = document.getElementById('page-content');
            
            // SECURE - Whitelist validation
            if (!validatePage(page)) {
                contentDiv.textContent = "Error: Invalid page requested. Only 'home', 'about', and 'contact' are allowed.";
                contentDiv.style.color = 'red';
                return;
            }
            
            // Clear previous content
            contentDiv.innerHTML = '';
            contentDiv.style.color = 'black';
            
            // SECURE - Create elements safely
            const title = document.createElement('h4');
            const content = document.createElement('p');
            
            switch(page) {
                case 'home':
                    title.textContent = "Home Page (Secure)";
                    content.textContent = "Welcome to our secure home page!";
                    break;
                case 'about':
                    title.textContent = "About Page (Secure)";
                    content.textContent = "Learn more about our security practices.";
                    break;
                case 'contact':
                    title.textContent = "Contact Page (Secure)";
                    content.textContent = "Get in touch with us securely.";
                    break;
            }
            
            // SECURE - Using appendChild instead of innerHTML
            contentDiv.appendChild(title);
            contentDiv.appendChild(content);
        }
        
        // SECURE: Safe page loading from select dropdown
        function safeLoadPageFromSelect() {
            const select = document.getElementById('manualPageSelect');
            const selectedValue = select.value;
            safeLoadPage(selectedValue);
        }

        // SECURE: Safe search implementation
        function safePerformSearch() {
            const searchTerm = document.getElementById('searchInput').value;
            const resultsDiv = document.getElementById('search-results');
            
            // Input validation
            if (!validateInput(searchTerm, 100)) {
                resultsDiv.textContent = "Invalid search term! Please enter valid text (max 100 chars).";
                resultsDiv.style.color = 'red';
                return;
            }
            
            // Clear previous results
            resultsDiv.innerHTML = '';
            resultsDiv.style.color = 'black';
            
            // SECURE - Create elements safely
            const title = document.createElement('h6');
            title.textContent = "Search Results for: " + searchTerm;
            
            const message = document.createElement('p');
            message.textContent = "No results found (this is a secure demo).";
            
            const securityNote = document.createElement('small');
            securityNote.textContent = "🛡️ Your search term was safely processed and displayed.";
            securityNote.style.color = 'green';
            
            // SECURE - Using appendChild
            resultsDiv.appendChild(title);
            resultsDiv.appendChild(message);
            resultsDiv.appendChild(securityNote);
        }

        // Initialize safe welcome message on page load
        document.addEventListener('DOMContentLoaded', function() {
            safeUpdateWelcome();
            
            // Listen for hash changes (safe handling)
            window.addEventListener('hashchange', safeUpdateWelcome);
            
            // Add input validation to form fields
            const userInput = document.getElementById('userInput');
            const searchInput = document.getElementById('searchInput');
            
            // Real-time input validation feedback
            userInput.addEventListener('input', function() {
                if (this.value.length > 500) {
                    this.setCustomValidity('Input too long (max 500 characters)');
                    this.style.borderColor = 'red';
                } else {
                    this.setCustomValidity('');
                    this.style.borderColor = '';
                }
            });
            
            searchInput.addEventListener('input', function() {
                if (this.value.length > 100) {
                    this.setCustomValidity('Search term too long (max 100 characters)');
                    this.style.borderColor = 'red';
                } else {
                    this.setCustomValidity('');
                    this.style.borderColor = '';
                }
            });
        });

        // Demonstrate safe URL parameter handling
        function getSafeUrlParameter(name) {
            const urlParams = new URLSearchParams(window.location.search);
            const value = urlParams.get(name);
            
            // Validate the parameter value
            if (value && validateInput(value, 100)) {
                return value;
            }
            return null;
        }

        // Safe handling of URL parameters on page load
        const nameParam = getSafeUrlParameter('name');
        if (nameParam) {
            document.addEventListener('DOMContentLoaded', function() {
                const welcomeDiv = document.getElementById('welcome-message');
                const currentText = welcomeDiv.textContent;
                // SECURE - Using textContent
                welcomeDiv.textContent = currentText + " | URL Parameter: " + nameParam + " (safely handled)";
            });
        }
        
        // Security demonstration function
        function showSecurityInfo() {
            const info = `
🛡️ DOM XSS Prevention Active:

✅ Safe Methods Used:
• textContent instead of innerHTML
• createElement + appendChild
• Input validation with whitelists
• HTML encoding for display

❌ Dangerous Methods Avoided:
• innerHTML with user data
• document.write()
• eval()
• Direct URL parameter usage

🔒 Additional Security:
• Content Security Policy headers
• Input length validation
• XSS Protection headers
• Safe error handling
            `.trim();
            
            alert(info);
        }
        
        // Add security info button functionality (if needed)
        // Can be called from a button click
        window.showSecurityInfo = showSecurityInfo;
    </script>
</body>
</html>