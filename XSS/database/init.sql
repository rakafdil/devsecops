-- Create databases
CREATE DATABASE IF NOT EXISTS xss_lab;
CREATE DATABASE IF NOT EXISTS xss_lab_secure;

-- Use xss_lab database
USE xss_lab;

-- Create comments table for stored XSS demo
CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    comment TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create users table for login demo
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create posts table for blog demo
CREATE TABLE IF NOT EXISTS posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    author VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO comments (name, email, comment) VALUES 
('John Doe', 'john@example.com', 'Great tutorial on XSS!'),
('Jane Smith', 'jane@example.com', 'Very informative content.');

INSERT INTO users (username, password, email) VALUES 
('admin', 'admin123', 'admin@example.com'),
('user1', 'password', 'user1@example.com');

INSERT INTO posts (title, content, author) VALUES 
('Understanding XSS', 'Cross-site scripting (XSS) is a type of security vulnerability...', 'Admin'),
('Web Security Best Practices', 'Here are some important security practices for web development...', 'Security Expert');

-- Setup for secure database
USE xss_lab_secure;

-- Create the same tables for secure app
CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    comment TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    author VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data for secure app
INSERT INTO comments (name, email, comment) VALUES 
('John Doe', 'john@example.com', 'Great secure tutorial!'),
('Jane Smith', 'jane@example.com', 'Well protected application.');

INSERT INTO users (username, password, email) VALUES 
('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin@example.com'),
('user1', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user1@example.com');

INSERT INTO posts (title, content, author) VALUES 
('Secure XSS Prevention', 'This application demonstrates proper XSS prevention techniques...', 'Security Admin'),
('Input Validation Guide', 'Proper input validation and output encoding examples...', 'Developer');