<?php
session_start();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DOM XSS - Vulnerable Lab</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .vulnerability-badge { background-color: #dc3545; }
        .code-example { background-color: #f8f9fa; padding: 15px; border-left: 4px solid #dc3545; }
        .output-box { min-height: 100px; border: 1px solid #ddd; padding: 15px; background-color: #f8f9fa; }
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
                <a class="nav-link active" href="dom.php">DOM XSS</a>
                <a class="nav-link" href="contexts.php">XSS Contexts</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h1>🌐 DOM-based XSS Vulnerability</h1>
        <div class="alert alert-danger">
            <strong>Kerentanan:</strong> JavaScript yang menggunakan data dari URL atau user input secara langsung untuk memodifikasi DOM tanpa sanitasi.
        </div>

        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h5>🎯 DOM XSS Example 1: URL Fragment</h5>
                    </div>
                    <div class="card-body">
                        <p>Halaman ini akan menampilkan pesan selamat datang berdasarkan fragment URL (#).</p>
                        <p><strong>Coba URL ini:</strong> <code>dom.php#&lt;script&gt;alert('DOM XSS!')&lt;/script&gt;</code></p>
                        
                        <div id="welcome-message" class="output-box">
                            <em>Loading welcome message...</em>
                        </div>

                        <button onclick="updateWelcome()" class="btn btn-primary mt-2">Refresh Message</button>
                    </div>
                </div>

                <div class="card mt-4">
                    <div class="card-header">
                        <h5>🎯 DOM XSS Example 2: URL Parameters</h5>
                    </div>
                    <div class="card-body">
                        <p>Input akan diambil dari URL parameter dan ditampilkan menggunakan innerHTML.</p>
                        <form id="urlParamForm">
                            <div class="mb-3">
                                <label for="userInput" class="form-label">User Input:</label>
                                <input type="text" class="form-control" id="userInput" 
                                       placeholder="Coba: <img src=x onerror=alert('DOM XSS')>">
                            </div>
                            <button type="button" onclick="displayUserInput()" class="btn btn-success">Display Input</button>
                        </form>

                        <div id="user-output" class="output-box mt-3">
                            <em>Output akan ditampilkan di sini...</em>
                        </div>
                    </div>
                </div>

                <div class="card mt-4">
                    <div class="card-header">
                        <h5>🎯 DOM XSS Example 3: Dynamic Content Loading</h5>
                    </div>
                    <div class="card-body">
                        <p>Konten dimuat secara dinamis berdasarkan parameter page.</p>
                        <div class="btn-group" role="group">
                            <button onclick="loadPage('home')" class="btn btn-outline-primary">Home</button>
                            <button onclick="loadPage('about')" class="btn btn-outline-primary">About</button>
                            <button onclick="loadPage('contact')" class="btn btn-outline-primary">Contact</button>
                        </div>
                        
                        <div class="mt-3">
                            <strong>Manual Page Load:</strong>
                            <input type="text" id="manualPage" placeholder="Coba: <script>alert('Manual DOM XSS')</script>" class="form-control d-inline-block" style="width: 300px;">
                            <button onclick="loadPage(document.getElementById('manualPage').value)" class="btn btn-warning">Load</button>
                        </div>

                        <div id="page-content" class="output-box mt-3">
                            <em>Select a page to load content...</em>
                        </div>
                    </div>
                </div>

                <div class="card mt-4">
                    <div class="card-header">
                        <h5>🎯 DOM XSS Example 4: Search with document.write</h5>
                    </div>
                    <div class="card-body">
                        <input type="text" id="searchInput" placeholder="Search term" class="form-control">
                        <button onclick="performSearch()" class="btn btn-info mt-2">Search</button>
                        
                        <div id="search-results" class="mt-3">
                            <!-- Results will be written here using document.write -->
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h5>💡 DOM XSS Payloads</h5>
                    </div>
                    <div class="card-body">
                        <h6>Fragment-based:</h6>
                        <div class="code-example">
                            <code>#&lt;script&gt;alert('DOM XSS')&lt;/script&gt;</code>
                        </div>

                        <h6 class="mt-3">Image with onerror:</h6>
                        <div class="code-example">
                            <code>&lt;img src=x onerror=alert('DOM XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">SVG with onload:</h6>
                        <div class="code-example">
                            <code>&lt;svg onload=alert('DOM XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">Iframe JavaScript:</h6>
                        <div class="code-example">
                            <code>&lt;iframe src=javascript:alert('DOM XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">Body onload:</h6>
                        <div class="code-example">
                            <code>&lt;body onload=alert('DOM XSS')&gt;</code>
                        </div>

                        <h6 class="mt-3">Input focus:</h6>
                        <div class="code-example">
                            <code>&lt;input autofocus onfocus=alert('DOM XSS')&gt;</code>
                        </div>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header">
                        <h5>🔍 Vulnerable JavaScript</h5>
                    </div>
                    <div class="card-body">
                        <small>
                            <pre><code>// VULNERABLE JS CODE:
// Using innerHTML directly
element.innerHTML = userInput;

// Using document.write
document.write(userInput);

// Using eval
eval(userInput);

// Direct DOM manipulation
document.location.hash</code></pre>
                        </small>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header">
                        <h5>🛡️ How to Fix</h5>
                    </div>
                    <div class="card-body">
                        <small>
                            <pre><code>// SECURE JS CODE:
// Use textContent instead of innerHTML
element.textContent = userInput;

// Encode HTML entities
function escapeHtml(text) {
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Use DOM methods safely
element.appendChild(textNode);</code></pre>
                        </small>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-header">
                        <h5>⚠️ Dangerous Functions</h5>
                    </div>
                    <div class="card-body">
                        <ul class="small">
                            <li><code>innerHTML</code></li>
                            <li><code>outerHTML</code></li>
                            <li><code>document.write()</code></li>
                            <li><code>document.writeln()</code></li>
                            <li><code>eval()</code></li>
                            <li><code>setTimeout()</code> with string</li>
                            <li><code>setInterval()</code> with string</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="alert alert-warning mt-4">
            <h5>📝 Learning Notes:</h5>
            <ul>
                <li><strong>DOM XSS</strong> terjadi sepenuhnya di client-side, tidak melibatkan server</li>
                <li>JavaScript menggunakan data dari URL, form input, atau storage secara langsung</li>
                <li>Payload dieksekusi melalui manipulasi DOM, bukan melalui HTTP response</li>
                <li>Sulit dideteksi oleh WAF karena tidak melalui server</li>
                <li>Pencegahan: Hindari innerHTML, gunakan textContent, validate input di JavaScript</li>
            </ul>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // DOM XSS Example 1: URL Fragment
        function updateWelcome() {
            var fragment = window.location.hash.substring(1);
            var welcomeDiv = document.getElementById('welcome-message');
            
            if (fragment) {
                // VULNERABLE CODE - Direct innerHTML assignment
                welcomeDiv.innerHTML = "Welcome, " + decodeURIComponent(fragment) + "!";
            } else {
                welcomeDiv.innerHTML = "Welcome! Add your name to the URL fragment (e.g., #JohnDoe)";
            }
        }

        // DOM XSS Example 2: URL Parameters  
        function displayUserInput() {
            var input = document.getElementById('userInput').value;
            var outputDiv = document.getElementById('user-output');
            
            // VULNERABLE CODE - Direct innerHTML assignment
            outputDiv.innerHTML = "You entered: " + input;
        }

        // DOM XSS Example 3: Dynamic Content Loading
        function loadPage(page) {
            var contentDiv = document.getElementById('page-content');
            
            // VULNERABLE CODE - Direct innerHTML assignment with user input
            switch(page) {
                case 'home':
                    contentDiv.innerHTML = "<h4>Home Page</h4><p>Welcome to our home page!</p>";
                    break;
                case 'about':
                    contentDiv.innerHTML = "<h4>About Page</h4><p>Learn more about us.</p>";
                    break;
                case 'contact':
                    contentDiv.innerHTML = "<h4>Contact Page</h4><p>Get in touch with us.</p>";
                    break;
                default:
                    // VULNERABLE - User input directly used in innerHTML
                    contentDiv.innerHTML = "<h4>Page: " + page + "</h4><p>Custom page content.</p>";
            }
        }

        // DOM XSS Example 4: Search with document.write
        function performSearch() {
            var searchTerm = document.getElementById('searchInput').value;
            var resultsDiv = document.getElementById('search-results');
            
            // VULNERABLE CODE - Using document.write (if in a new window) or innerHTML
            resultsDiv.innerHTML = "<h6>Search Results for: " + searchTerm + "</h6><p>No results found.</p>";
        }

        // Initialize welcome message on page load
        window.onload = function() {
            updateWelcome();
            
            // Listen for hash changes
            window.addEventListener('hashchange', updateWelcome);
        };

        // Additional DOM XSS examples with different sources
        
        // Example: Reading from URL parameters
        function getUrlParameter(name) {
            name = name.replace(/[\[]/, '\\[').replace(/[\]]/, '\\]');
            var regex = new RegExp('[\\?&]' + name + '=([^&#]*)');
            var results = regex.exec(location.search);
            return results === null ? '' : decodeURIComponent(results[1].replace(/\+/g, ' '));
        }

        // Check for URL parameters on load
        var nameParam = getUrlParameter('name');
        if (nameParam) {
            // VULNERABLE - Direct innerHTML with URL parameter
            document.addEventListener('DOMContentLoaded', function() {
                var existingContent = document.getElementById('welcome-message').innerHTML;
                document.getElementById('welcome-message').innerHTML = existingContent + "<br>URL Parameter Name: " + nameParam;
            });
        }
    </script>
</body>
</html>