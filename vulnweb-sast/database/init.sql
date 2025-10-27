-- Database initialization script for VulnWeb
CREATE DATABASE IF NOT EXISTS vulnwebdb;
USE vulnwebdb;

-- Users table (Vulnerable to SQL Injection and Broken Authentication)
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role ENUM('user', 'admin', 'moderator') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Products table
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2),
    category VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Comments table (Vulnerable to XSS)
CREATE TABLE comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    product_id INT,
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Sessions table (Vulnerable sessions)
CREATE TABLE user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    session_token VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Orders table (For broken access control demo)
CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    product_id INT,
    quantity INT DEFAULT 1,
    total_price DECIMAL(10,2),
    status ENUM('pending', 'paid', 'shipped', 'delivered') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Insert sample data
INSERT INTO users (username, password, email, role) VALUES
('admin', 'admin123', 'admin@vulnweb.com', 'admin'),
('user1', 'password123', 'user1@example.com', 'user'),
('user2', 'mypassword', 'user2@example.com', 'user'),
('moderator', 'mod123', 'mod@vulnweb.com', 'moderator'),
('testuser', '123456', 'test@example.com', 'user');

INSERT INTO products (name, description, price, category) VALUES
('Laptop Gaming', 'High-performance gaming laptop', 15000000.00, 'Electronics'),
('Smartphone Android', 'Latest Android smartphone', 8000000.00, 'Electronics'),
('Coffee Maker', 'Automatic coffee brewing machine', 2500000.00, 'Home'),
('Wireless Headphones', 'Noise-canceling wireless headphones', 3500000.00, 'Electronics'),
('Smart Watch', 'Fitness tracking smartwatch', 4500000.00, 'Electronics');

INSERT INTO comments (user_id, product_id, comment) VALUES
(2, 1, 'Great laptop! Very fast for gaming.'),
(3, 1, 'Expensive but worth it.'),
(2, 2, 'Good phone, battery life is excellent.'),
(3, 3, 'Perfect for my morning coffee routine.'),
(2, 4, 'Sound quality is amazing!');

INSERT INTO orders (user_id, product_id, quantity, total_price, status) VALUES
(2, 1, 1, 15000000.00, 'delivered'),
(3, 2, 1, 8000000.00, 'shipped'),
(2, 4, 2, 7000000.00, 'pending'),
(3, 3, 1, 2500000.00, 'paid');