<?php
require_once 'config.php';
include 'header.php';
?>

<h2>🛡️ Secure Code Examples</h2>

<div class="alert alert-success">
    <strong>✅ Security Fixed:</strong> This page demonstrates how the vulnerabilities have been properly fixed 
    with secure coding practices.
</div>

<div style="margin-top: 30px;">
    <h3>🔒 1. Fixed IDOR Vulnerability</h3>
    <div class="vulnerability-info">
        <h4>Before (Vulnerable Code):</h4>
        <div class="code-example">
// VULNERABILITY: No authorization check<br>
$user_id = $_GET['user_id'];<br>
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");<br>
$stmt->execute([$user_id]);
        </div>
        
        <h4>After (Secure Code):</h4>
        <div class="code-example" style="background-color: #d4edda; border-left: 4px solid #28a745;">
// FIXED: Proper authorization check<br>
$user_id = $_GET['user_id'] ?? $_SESSION['user_id'];<br>
<br>
// Check if current user can access this profile<br>
if ($user_id != $_SESSION['user_id'] && !isAdmin()) {<br>
&nbsp;&nbsp;&nbsp;&nbsp;header('HTTP/1.1 403 Forbidden');<br>
&nbsp;&nbsp;&nbsp;&nbsp;die("Access denied");<br>
}<br>
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");<br>
$stmt->execute([$user_id]);
        </div>
        
        <h4>Security Improvements:</h4>
        <ul>
            <li>✅ Authorization check before data access</li>
            <li>✅ Users can only access their own profiles</li>
            <li>✅ Admin users have elevated privileges</li>
            <li>✅ Proper HTTP 403 Forbidden response</li>
        </ul>
    </div>
</div>

<div style="margin-top: 30px;">
    <h3>🚪 2. Fixed Missing Function Level Access Control</h3>
    <div class="vulnerability-info">
        <h4>Before (Vulnerable Code):</h4>
        <div class="code-example">
// VULNERABILITY: Weak warning, page continues to load<br>
if (!isAdmin()) {<br>
&nbsp;&nbsp;&nbsp;&nbsp;echo "Warning: You don't have admin privileges";<br>
&nbsp;&nbsp;&nbsp;&nbsp;// Page continues to load anyway!<br>
}
        </div>
        
        <h4>After (Secure Code):</h4>
        <div class="code-example" style="background-color: #d4edda; border-left: 4px solid #28a745;">
// FIXED: Proper access control with termination<br>
if (!isAdmin()) {<br>
&nbsp;&nbsp;&nbsp;&nbsp;header('HTTP/1.1 403 Forbidden');<br>
&nbsp;&nbsp;&nbsp;&nbsp;die("Access denied");<br>
}
        </div>
        
        <h4>Security Improvements:</h4>
        <ul>
            <li>✅ Immediate termination for unauthorized users</li>
            <li>✅ Proper HTTP status code (403 Forbidden)</li>
            <li>✅ No sensitive functionality exposure</li>
            <li>✅ Clear error messaging</li>
        </ul>
    </div>
</div>

<div style="margin-top: 30px;">
    <h3>📄 3. Fixed Document Access Control</h3>
    <div class="vulnerability-info">
        <h4>Before (Vulnerable Code):</h4>
        <div class="code-example">
// VULNERABILITY: No permission check for private documents<br>
$stmt = $pdo->prepare("SELECT * FROM documents WHERE id = ?");<br>
$stmt->execute([$doc_id]);<br>
$document = $stmt->fetch();<br>
// Document displayed regardless of privacy settings
        </div>
        
        <h4>After (Secure Code):</h4>
        <div class="code-example" style="background-color: #d4edda; border-left: 4px solid #28a745;">
// FIXED: Check document permissions before access<br>
$stmt = $pdo->prepare("SELECT * FROM documents WHERE id = ?");<br>
$stmt->execute([$doc_id]);<br>
$document = $stmt->fetch();<br>
<br>
if ($document['is_private'] && <br>
&nbsp;&nbsp;&nbsp;&nbsp;$document['owner_id'] != $_SESSION['user_id'] && <br>
&nbsp;&nbsp;&nbsp;&nbsp;!isAdmin()) {<br>
&nbsp;&nbsp;&nbsp;&nbsp;header('HTTP/1.1 403 Forbidden');<br>
&nbsp;&nbsp;&nbsp;&nbsp;die("Access denied");<br>
}
        </div>
        
        <h4>Security Improvements:</h4>
        <ul>
            <li>✅ Privacy settings respected</li>
            <li>✅ Owner-based access control</li>
            <li>✅ Admin override capability</li>
            <li>✅ Document listing filtered by permissions</li>
        </ul>
    </div>
</div>

<div style="margin-top: 30px;">
    <h3>🔧 Current Application Status</h3>
    <div class="alert alert-success">
        <h4>✅ Security Fixes Applied:</h4>
        <ul>
            <li><strong>profile.php</strong> - IDOR vulnerability fixed</li>
            <li><strong>admin.php</strong> - Function level access control implemented</li>
            <li><strong>documents.php</strong> - Document access permissions enforced</li>
        </ul>
        
        <h4>🧪 Testing the Fixes:</h4>
        <p>Try the following tests to see the security improvements:</p>
        <ol>
            <li>Login as regular user and try to access <code>admin.php</code> - Should get 403 Forbidden</li>
            <li>Try accessing other user profiles: <code>profile.php?user_id=1</code> - Should be denied</li>
            <li>Try accessing private documents: <code>documents.php?doc_id=2</code> - Should be denied</li>
            <li>Notice that private documents no longer appear in the document listing</li>
        </ol>
    </div>
</div>

<div style="margin-top: 30px;">
    <h3>📚 Additional Security Best Practices</h3>
    <div class="vulnerability-info">
        <h4>Implemented Security Controls:</h4>
        <ul>
            <li><strong>Input Validation:</strong> All user inputs are validated and sanitized</li>
            <li><strong>Session Management:</strong> Secure session handling with proper checks</li>
            <li><strong>Error Handling:</strong> Consistent error responses without information leakage</li>
            <li><strong>Authorization Matrix:</strong> Clear role-based permissions</li>
            <li><strong>Principle of Least Privilege:</strong> Users only get minimum necessary access</li>
        </ul>
        
        <h4>Security Headers and Responses:</h4>
        <ul>
            <li><strong>HTTP 403 Forbidden:</strong> Proper status codes for unauthorized access</li>
            <li><strong>Consistent Messaging:</strong> Clear but not information-revealing error messages</li>
            <li><strong>Early Termination:</strong> Stop processing immediately on authorization failure</li>
        </ul>
    </div>
</div>

<?php include 'footer.php'; ?>