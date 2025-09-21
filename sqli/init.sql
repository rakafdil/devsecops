-- Create database if not exists
CREATE DATABASE IF NOT EXISTS vulnerable_app;
USE vulnerable_app;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL,
    role ENUM('admin', 'user', 'moderator') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO users (username, password, email, role) VALUES
('admin', 'admin123', 'admin@vulnerable-app.com', 'admin'),
('john_doe', 'password123', 'john@example.com', 'user'),
('jane_smith', 'qwerty456', 'jane@example.com', 'user'),
('moderator', 'mod_pass', 'mod@vulnerable-app.com', 'moderator'),
('test_user', 'test123', 'test@example.com', 'user'),
('alice', 'alice_secret', 'alice@example.com', 'user'),
('bob', 'bob_password', 'bob@example.com', 'user'),
('charlie', 'charlie123', 'charlie@example.com', 'moderator');

-- Create additional table for demonstration
CREATE TABLE IF NOT EXISTS sensitive_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    secret_info VARCHAR(255),
    credit_card VARCHAR(20),
    ssn VARCHAR(15),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Insert sensitive data (for demonstration of data exfiltration)
INSERT INTO sensitive_data (user_id, secret_info, credit_card, ssn) VALUES
(1, 'Admin secret key: ADM-2023-SECRET', '4532-1234-5678-9012', '123-45-6789'),
(2, 'User personal note: My birthday is 1990-05-15', '4111-1111-1111-1111', '987-65-4321'),
(3, 'Private message: Meeting at 3 PM', '5555-5555-5555-4444', '456-78-9012'),
(4, 'Moderator access token: MOD-TOKEN-789', '4000-0000-0000-0002', '789-01-2345');

-- Create logs table
CREATE TABLE IF NOT EXISTS access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Show tables and structure for demonstration
SHOW TABLES;
DESCRIBE users;
DESCRIBE sensitive_data;
