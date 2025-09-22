-- Create database
CREATE DATABASE IF NOT EXISTS broken_auth_app;
USE broken_auth_app;

-- Users table with weak password storage
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL, -- Stored in plain text or weak hash
    role ENUM('admin', 'user', 'moderator') DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    password_reset_token VARCHAR(255) NULL,
    password_reset_expires TIMESTAMP NULL
);

-- Sessions table for custom session management
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    user_id INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Login attempts table for monitoring
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN DEFAULT FALSE,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Password reset tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(6), -- Predictable 6-digit token
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Insert sample users with weak passwords
INSERT INTO users (username, email, password, role) VALUES
('admin', 'admin@company.com', 'admin', 'admin'),
('john', 'john@company.com', 'password', 'user'),
('jane', 'jane@company.com', '123456', 'user'),
('bob', 'bob@company.com', 'qwerty', 'user'),
('alice', 'alice@company.com', 'alice123', 'user'),
('charlie', 'charlie@company.com', 'password123', 'moderator'),
('david', 'david@company.com', 'david', 'user'),
('sarah', 'sarah@company.com', '111111', 'user'),
('mike', 'mike@company.com', 'mike2023', 'user'),
('lisa', 'lisa@company.com', 'welcome', 'user');

-- Insert some login attempts for testing
INSERT INTO login_attempts (username, ip_address, success) VALUES
('admin', '192.168.1.100', true),
('john', '192.168.1.101', false),
('jane', '192.168.1.102', true),
('unknown_user', '192.168.1.103', false);

-- Create a view for user statistics
CREATE VIEW user_login_stats AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.failed_login_attempts,
    u.last_login,
    COUNT(la.id) as total_login_attempts,
    SUM(CASE WHEN la.success = 1 THEN 1 ELSE 0 END) as successful_logins,
    SUM(CASE WHEN la.success = 0 THEN 1 ELSE 0 END) as failed_logins
FROM users u
LEFT JOIN login_attempts la ON u.username = la.username
GROUP BY u.id, u.username, u.email, u.failed_login_attempts, u.last_login;

-- Show tables
SHOW TABLES;
