<?php
require_once 'config.php';
requireLogin();

// FIXED: Proper authorization check for document access
$doc_id = $_GET['doc_id'] ?? null;
$pdo = getConnection();

if ($doc_id) {
    // Get document first to check permissions
    $stmt = $pdo->prepare("SELECT d.*, u.username as owner_name FROM documents d LEFT JOIN users u ON d.owner_id = u.id WHERE d.id = ?");
    $stmt->execute([$doc_id]);
    $document = $stmt->fetch();
    
    if (!$document) {
        $error = "Document not found.";
    } elseif ($document['is_private'] && $document['owner_id'] != $_SESSION['user_id'] && !isAdmin()) {
        // Check if user can access this private document
        header('HTTP/1.1 403 Forbidden');
        die("<div class='alert alert-danger'>Access denied. You don't have permission to view this private document.</div>");
    }
} else {
    // Get documents that user is allowed to see
    if (isAdmin()) {
        // Admin can see all documents
        $stmt = $pdo->query("SELECT d.*, u.username as owner_name FROM documents d LEFT JOIN users u ON d.owner_id = u.id ORDER BY d.created_at DESC");
    } else {
        // Regular users can only see public documents and their own private documents
        $stmt = $pdo->prepare("SELECT d.*, u.username as owner_name FROM documents d LEFT JOIN users u ON d.owner_id = u.id WHERE d.is_private = 0 OR d.owner_id = ? ORDER BY d.created_at DESC");
        $stmt->execute([$_SESSION['user_id']]);
    }
    $documents = $stmt->fetchAll();
}

$current_user = getCurrentUser();

include 'header.php';
?>

<h2>Documents</h2>

<?php if (isset($document)): ?>
    <!-- Single document view -->
    <?php if (isset($error)): ?>
        <div class="alert alert-danger"><?php echo sanitizeInput($error); ?></div>
    <?php else: ?>
        
        <?php if ($document['is_private'] && $document['owner_id'] != $current_user['id']): ?>
            <div class="alert alert-danger">
                <strong>🚨 UNAUTHORIZED ACCESS:</strong> You are viewing a private document that doesn't belong to you! 
                This is a critical security violation.
            </div>
        <?php endif; ?>

        <div style="background: white; border: 1px solid #ddd; padding: 20px; border-radius: 5px;">
            <h3><?php echo sanitizeInput($document['title']); ?></h3>
            <div style="margin: 15px 0; padding: 10px; background: #f8f9fa; border-left: 4px solid #007bff;">
                <strong>Owner:</strong> <?php echo sanitizeInput($document['owner_name']); ?><br>
                <strong>Created:</strong> <?php echo date('F j, Y g:i A', strtotime($document['created_at'])); ?><br>
                <strong>Status:</strong> 
                <span style="color: <?php echo $document['is_private'] ? 'red' : 'green'; ?>;">
                    <?php echo $document['is_private'] ? 'PRIVATE' : 'PUBLIC'; ?>
                </span>
            </div>
            
            <div style="border-top: 1px solid #eee; padding-top: 15px; line-height: 1.6;">
                <?php echo nl2br(sanitizeInput($document['content'])); ?>
            </div>
        </div>

        <div style="margin-top: 20px;">
            <a href="documents.php"><button>← Back to Documents</button></a>
        </div>

        <div class="vulnerability-info" style="margin-top: 30px;">
            <h3>🔍 Document Access Vulnerability</h3>
            <p>This demonstrates unauthorized document access:</p>
            <ul>
                <li>No authorization check to verify document access permissions</li>
                <li>Private documents are accessible by changing the doc_id parameter</li>
                <li>Sensitive information is exposed to unauthorized users</li>
            </ul>
        </div>
    <?php endif; ?>

<?php else: ?>
    <!-- Document listing -->
    <?php if (isset($documents)): ?>
        <p>Browse available documents. Click on any document to view its contents.</p>
        
        <div class="alert alert-warning">
            <strong>🔍 Testing Tip:</strong> Try accessing documents by changing the doc_id parameter in the URL. 
            Even private documents may be accessible!
        </div>

        <div style="display: grid; gap: 15px; margin-top: 20px;">
            <?php foreach ($documents as $doc): ?>
                <div style="border: 1px solid #ddd; padding: 15px; border-radius: 5px; background: white;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
                        <h4 style="margin: 0;">
                            <a href="documents.php?doc_id=<?php echo $doc['id']; ?>" style="text-decoration: none; color: #007bff;">
                                <?php echo sanitizeInput($doc['title']); ?>
                            </a>
                        </h4>
                        <span style="padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; color: white; background-color: <?php echo $doc['is_private'] ? '#dc3545' : '#28a745'; ?>;">
                            <?php echo $doc['is_private'] ? 'PRIVATE' : 'PUBLIC'; ?>
                        </span>
                    </div>
                    
                    <div style="font-size: 14px; color: #666; margin-bottom: 10px;">
                        <strong>Owner:</strong> <?php echo sanitizeInput($doc['owner_name']); ?> | 
                        <strong>Created:</strong> <?php echo date('M j, Y', strtotime($doc['created_at'])); ?>
                    </div>
                    
                    <div style="color: #333;">
                        <?php 
                        $preview = substr($doc['content'], 0, 150);
                        echo sanitizeInput($preview) . (strlen($doc['content']) > 150 ? '...' : '');
                        ?>
                    </div>
                    
                    <?php if ($doc['is_private'] && $doc['owner_id'] != $current_user['id']): ?>
                        <div style="margin-top: 10px; padding: 8px; background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 3px; font-size: 13px;">
                            ⚠️ This is a private document you shouldn't be able to see!
                        </div>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>

        <div class="vulnerability-info" style="margin-top: 30px;">
            <h3>🔍 Document Access Control Issues</h3>
            <p>Notice the security issues with document access:</p>
            <ul>
                <li>Private documents are visible in the listing</li>
                <li>Document IDs are predictable and sequential</li>
                <li>No access control validation before displaying documents</li>
            </ul>
            
            <h4>Test these direct document access URLs:</h4>
            <div class="code-example">
                <a href="documents.php?doc_id=1">documents.php?doc_id=1</a> (Public policy)<br>
                <a href="documents.php?doc_id=2">documents.php?doc_id=2</a> (Private HR document) ⚠️<br>
                <a href="documents.php?doc_id=3">documents.php?doc_id=3</a> (Admin security guidelines) ⚠️<br>
                <a href="documents.php?doc_id=4">documents.php?doc_id=4</a> (Marketing strategy)<br>
                <a href="documents.php?doc_id=5">documents.php?doc_id=5</a> (Financial reports) ⚠️
            </div>
        </div>
    <?php endif; ?>
<?php endif; ?>

<?php include 'footer.php'; ?>