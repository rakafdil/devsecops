<?php
require_once 'config.php';
include 'header.php';
?>

<h2>Welcome to Broken Access Control Learning Lab</h2>

<div class="alert alert-warning">
    <strong>⚠️ Educational Warning:</strong> This application contains intentional security vulnerabilities 
    for learning purposes. Never deploy this in a production environment!
</div>

<div class="vulnerability-info">
    <h3>🎯 Learning Objectives</h3>
    <p>This hands-on lab demonstrates common Broken Access Control vulnerabilities including:</p>
    <ul>
        <li><strong>Insecure Direct Object References (IDOR)</strong> - Access other users' data by changing IDs</li>
        <li><strong>Missing Function Level Access Control</strong> - Access admin functions without proper authorization</li>
        <li><strong>Horizontal Privilege Escalation</strong> - Access data belonging to other users at the same privilege level</li>
        <li><strong>Vertical Privilege Escalation</strong> - Gain higher privileges than intended</li>
        <li><strong>Missing Authorization</strong> - Functions that don't check user permissions</li>
    </ul>
</div>

<?php if (isLoggedIn()): ?>
    <h3>Quick Actions</h3>
    <div style="display: flex; gap: 15px; flex-wrap: wrap;">
        <a href="profile.php" style="text-decoration: none;">
            <button>View My Profile</button>
        </a>
        <a href="documents.php" style="text-decoration: none;">
            <button>Browse Documents</button>
        </a>
        <?php if (isAdmin()): ?>
            <a href="admin.php" style="text-decoration: none;">
                <button>Admin Panel</button>
            </a>
        <?php endif; ?>
    </div>

    <h3>🔍 Try These Exploits</h3>
    <div class="code-example">
        <h4>IDOR Examples:</h4>
        <p>1. Try changing user IDs in URLs:</p>
        <ul>
            <li><code>profile.php?user_id=1</code> (Admin profile)</li>
            <li><code>profile.php?user_id=2</code> (John Doe's profile)</li>
            <li><code>profile.php?user_id=3</code> (Jane Smith's profile)</li>
        </ul>
        
        <p>2. Try accessing admin functions:</p>
        <ul>
            <li><code>admin.php</code> (Even if you're not admin)</li>
            <li><code>admin.php?action=delete&user_id=2</code></li>
        </ul>
        
        <p>3. Document access bypass:</p>
        <ul>
            <li><code>documents.php?doc_id=1</code></li>
            <li><code>documents.php?doc_id=2</code> (Private HR document)</li>
            <li><code>documents.php?doc_id=3</code> (Admin security guidelines)</li>
        </ul>
    </div>

<?php else: ?>
    <h3>Get Started</h3>
    <p>Please <a href="login.php">login</a> or <a href="register.php">register</a> to start exploring the vulnerabilities.</p>
    
    <h4>Test Accounts:</h4>
    <div class="code-example">
        <strong>Admin Account:</strong><br>
        Username: admin<br>
        Password: password<br><br>
        
        <strong>Regular User Account:</strong><br>
        Username: john_doe<br>
        Password: password<br><br>
        
        <strong>Moderator Account:</strong><br>
        Username: jane_smith<br>
        Password: password
    </div>
<?php endif; ?>

<h3>📚 Learning Resources</h3>
<ul>
    <li><a href="vulnerabilities.php">Vulnerability Guide</a> - Detailed explanations of each vulnerability</li>
    <li><a href="https://owasp.org/www-project-top-ten/" target="_blank">OWASP Top 10</a></li>
    <li><a href="https://portswigger.net/web-security/access-control" target="_blank">PortSwigger Web Security Academy</a></li>
</ul>

<?php include 'footer.php'; ?>