<?php
require_once 'config.php';
include 'header.php';
?>

<h2>Vulnerability Learning Guide</h2>

<div class="alert alert-warning">
    <strong>Educational Purpose:</strong> This guide explains the vulnerabilities implemented in this application 
    for learning purposes. Understanding these issues helps developers build more secure applications.
</div>

<div style="margin-top: 30px;">
    <h3>🎯 1. Insecure Direct Object References (IDOR)</h3>
    <div class="vulnerability-info">
        <h4>What is IDOR?</h4>
        <p>IDOR occurs when an application provides direct access to objects based on user-supplied input. 
        An attacker can bypass authorization and access resources belonging to other users by modifying 
        the parameter values.</p>
        
        <h4>Examples in this app:</h4>
        <div class="code-example">
            <strong>Profile Access:</strong><br>
            • <code>profile.php?user_id=1</code> - Access admin profile<br>
            • <code>profile.php?user_id=2</code> - Access John's profile<br>
            • Change the user_id to access any user's sensitive data<br><br>
            
            <strong>Document Access:</strong><br>
            • <code>documents.php?doc_id=2</code> - Access private HR documents<br>
            • <code>documents.php?doc_id=3</code> - Access admin security guidelines<br>
            • Sequential IDs make it easy to enumerate all documents
        </div>
        
        <h4>Impact:</h4>
        <ul>
            <li>Unauthorized access to personal information</li>
            <li>Exposure of sensitive financial data (salaries)</li>
            <li>Access to confidential documents</li>
            <li>Privacy violations and data breaches</li>
        </ul>
        
        <h4>How to fix:</h4>
        <ul>
            <li>Implement proper authorization checks</li>
            <li>Use indirect references (UUIDs instead of sequential IDs)</li>
            <li>Validate user permissions before serving content</li>
            <li>Implement access control lists (ACLs)</li>
        </ul>
    </div>
</div>

<div style="margin-top: 30px;">
    <h3>🔒 2. Missing Function Level Access Control</h3>
    <div class="vulnerability-info">
        <h4>What is Missing Function Level Access Control?</h4>
        <p>This vulnerability occurs when an application fails to properly validate user permissions 
        before executing sensitive functions or displaying administrative interfaces.</p>
        
        <h4>Examples in this app:</h4>
        <div class="code-example">
            <strong>Admin Panel Access:</strong><br>
            • Any logged-in user can access <code>admin.php</code><br>
            • No server-side validation of admin privileges<br>
            • Users can perform admin actions like deleting accounts<br><br>
            
            <strong>Privilege Escalation:</strong><br>
            • Regular users can promote themselves to admin<br>
            • No verification of current user's role before processing actions
        </div>
        
        <h4>Impact:</h4>
        <ul>
            <li>Unauthorized access to administrative functions</li>
            <li>Privilege escalation attacks</li>
            <li>Data manipulation and deletion</li>
            <li>Complete system compromise</li>
        </ul>
        
        <h4>How to fix:</h4>
        <ul>
            <li>Implement role-based access control (RBAC)</li>
            <li>Validate user permissions on every request</li>
            <li>Use server-side authorization checks</li>
            <li>Implement principle of least privilege</li>
        </ul>
    </div>
</div>

<div style="margin-top: 30px;">
    <h3>↔️ 3. Horizontal Privilege Escalation</h3>
    <div class="vulnerability-info">
        <h4>What is Horizontal Privilege Escalation?</h4>
        <p>This allows a user to access resources belonging to other users at the same privilege level. 
        Users can view or modify data that should be restricted to its owner.</p>
        
        <h4>Examples in this app:</h4>
        <div class="code-example">
            <strong>Profile Enumeration:</strong><br>
            • User 'john_doe' can view 'jane_smith's profile<br>
            • Access to salary information of other employees<br>
            • View personal contact details of colleagues<br><br>
            
            <strong>Document Access:</strong><br>
            • Users can read private documents created by others<br>
            • Access to confidential departmental information
        </div>
        
        <h4>Impact:</h4>
        <ul>
            <li>Privacy violations</li>
            <li>Exposure of personal data</li>
            <li>Corporate espionage opportunities</li>
            <li>Compliance violations (GDPR, HIPAA, etc.)</li>
        </ul>
    </div>
</div>

<div style="margin-top: 30px;">
    <h3>⬆️ 4. Vertical Privilege Escalation</h3>
    <div class="vulnerability-info">
        <h4>What is Vertical Privilege Escalation?</h4>
        <p>This allows a user to gain access to functionality or data that requires higher privileges. 
        Regular users can perform administrative actions.</p>
        
        <h4>Examples in this app:</h4>
        <div class="code-example">
            <strong>Admin Function Access:</strong><br>
            • Regular users can delete other user accounts<br>
            • Users can promote themselves to admin role<br>
            • Access to admin logs and sensitive system information
        </div>
        
        <h4>Impact:</h4>
        <ul>
            <li>Complete system compromise</li>
            <li>Data destruction capabilities</li>
            <li>User account manipulation</li>
            <li>Administrative control takeover</li>
        </ul>
    </div>
</div>

<div style="margin-top: 30px;">
    <h3>🛡️ General Security Best Practices</h3>
    <div class="vulnerability-info">
        <h4>Prevention Strategies:</h4>
        <ul>
            <li><strong>Implement Defense in Depth:</strong> Multiple layers of security controls</li>
            <li><strong>Use Secure Session Management:</strong> Proper session handling and validation</li>
            <li><strong>Apply Principle of Least Privilege:</strong> Users get minimum necessary permissions</li>
            <li><strong>Input Validation:</strong> Validate and sanitize all user inputs</li>
            <li><strong>Regular Security Audits:</strong> Code reviews and penetration testing</li>
            <li><strong>Logging and Monitoring:</strong> Track access patterns and suspicious activities</li>
        </ul>
        
        <h4>Testing Methodology:</h4>
        <ol>
            <li>Identify all endpoints and parameters</li>
            <li>Test with different user roles and permissions</li>
            <li>Attempt to access restricted resources</li>
            <li>Try parameter manipulation and enumeration</li>
            <li>Test for privilege escalation possibilities</li>
            <li>Verify proper error handling</li>
        </ol>
    </div>
</div>

<div style="margin-top: 30px;">
    <h3>🔍 Hands-On Exercises</h3>
    <div class="vulnerability-info">
        <h4>Exercise 1: Profile Enumeration</h4>
        <ol>
            <li>Login as 'john_doe' (password: 'password')</li>
            <li>Visit your profile and note the URL structure</li>
            <li>Try changing the user_id parameter to access other profiles</li>
            <li>Document what sensitive information you can access</li>
        </ol>
        
        <h4>Exercise 2: Admin Panel Bypass</h4>
        <ol>
            <li>Login as a regular user</li>
            <li>Try to access the admin panel directly</li>
            <li>Attempt to delete other users or promote yourself</li>
            <li>Observe what actions are actually processed</li>
        </ol>
        
        <h4>Exercise 3: Document Access</h4>
        <ol>
            <li>Identify private documents in the document listing</li>
            <li>Try to access them directly using doc_id parameters</li>
            <li>Test for document enumeration possibilities</li>
            <li>Assess the sensitivity of exposed information</li>
        </ol>
    </div>
</div>

<div style="margin-top: 30px;">
    <h3>📚 Additional Resources</h3>
    <ul>
        <li><a href="https://owasp.org/www-project-top-ten/" target="_blank">OWASP Top 10</a></li>
        <li><a href="https://portswigger.net/web-security/access-control" target="_blank">PortSwigger Web Security Academy - Access Control</a></li>
        <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" target="_blank">OWASP Authorization Cheat Sheet</a></li>
        <li><a href="https://cwe.mitre.org/data/definitions/284.html" target="_blank">CWE-284: Improper Access Control</a></li>
    </ul>
</div>

<?php include 'footer.php'; ?>