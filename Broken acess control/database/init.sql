-- Create database schema for Broken Access Control learning
CREATE DATABASE IF NOT EXISTS vulnerable_app;
USE vulnerable_app;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role ENUM('user', 'admin', 'moderator') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Documents table (for demonstrating unauthorized access)
CREATE TABLE documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT,
    owner_id INT,
    is_private BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- User profiles table
CREATE TABLE profiles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNIQUE,
    full_name VARCHAR(100),
    phone VARCHAR(20),
    address TEXT,
    salary DECIMAL(10,2),
    department VARCHAR(50),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Admin logs table
CREATE TABLE admin_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_id INT,
    action VARCHAR(255),
    target_user_id INT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Insert sample data
INSERT INTO users (username, password, email, role) VALUES
('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin@company.com', 'admin'), -- password: password
('john_doe', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'john@company.com', 'user'),
('jane_smith', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'jane@company.com', 'moderator'),
('bob_wilson', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'bob@company.com', 'user'),
('alice_brown', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'alice@company.com', 'user');

INSERT INTO profiles (user_id, full_name, phone, address, salary, department) VALUES
(1, 'Administrator', '+1-555-0001', '123 Admin St', 80000.00, 'IT'),
(2, 'John Doe', '+1-555-0002', '456 User Ave', 50000.00, 'Sales'),
(3, 'Jane Smith', '+1-555-0003', '789 Mod Blvd', 60000.00, 'HR'),
(4, 'Bob Wilson', '+1-555-0004', '321 Regular Rd', 45000.00, 'Marketing'),
(5, 'Alice Brown', '+1-555-0005', '654 Normal Ln', 55000.00, 'Finance');

INSERT INTO documents (title, content, owner_id, is_private) VALUES
('Public Company Policy', 'This is a public document accessible to all employees.', 1, FALSE),
('Confidential HR Document', 'This contains sensitive HR information and salary data.', 3, TRUE),
('Admin Security Guidelines', 'Internal security protocols - CONFIDENTIAL', 1, TRUE),
('Marketing Strategy 2024', 'Our marketing plans for next year.', 4, FALSE),
('Financial Reports Q3', 'Quarterly financial data - RESTRICTED ACCESS', 5, TRUE);