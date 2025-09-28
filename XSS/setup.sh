#!/bin/bash

# XSS Lab Setup Script
# This script sets up the complete XSS hands-on lab environment

echo "🚀 Setting up XSS Hands-On Lab..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Stop and remove existing containers
echo "🛑 Stopping existing containers..."
docker-compose down -v 2>/dev/null || true

# Build and start containers
echo "🏗️ Building and starting containers..."
docker-compose up --build -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Check if services are running
echo "🔍 Checking service status..."

# Check MySQL
if docker-compose exec -T mysql mysqladmin ping -h localhost -u root -prootpassword &>/dev/null; then
    echo "✅ MySQL is running"
else
    echo "❌ MySQL is not running"
fi

# Check Vulnerable App
if curl -s http://localhost:8080 &>/dev/null; then
    echo "✅ Vulnerable App is running on http://localhost:8080"
else
    echo "❌ Vulnerable App is not accessible"
fi

# Check Secure App
if curl -s http://localhost:8081 &>/dev/null; then
    echo "✅ Secure App is running on http://localhost:8081"
else
    echo "❌ Secure App is not accessible"
fi

# Check phpMyAdmin
if curl -s http://localhost:8082 &>/dev/null; then
    echo "✅ phpMyAdmin is running on http://localhost:8082"
else
    echo "❌ phpMyAdmin is not accessible"
fi

echo ""
echo "🎉 XSS Lab Setup Complete!"
echo ""
echo "📋 Access Information:"
echo "🔓 Vulnerable Application: http://localhost:8080"
echo "🔒 Secure Application:     http://localhost:8081"  
echo "🗄️  phpMyAdmin:            http://localhost:8082"
echo ""
echo "🔑 Database Credentials:"
echo "   Host: localhost:3306"
echo "   Username: xsslab"
echo "   Password: password123"
echo "   Root Password: rootpassword"
echo ""
echo "📚 Documentation:"
echo "   - README.md: General information"
echo "   - PAYLOADS.md: XSS testing payloads"
echo "   - PREVENTION.md: Security best practices"
echo ""
echo "🎯 Lab Objectives:"
echo "   1. Test XSS vulnerabilities in the vulnerable app"
echo "   2. Try the same payloads in the secure app"
echo "   3. Compare the different implementations"
echo "   4. Learn XSS prevention techniques"
echo ""
echo "⚠️  WARNING: Use this lab for educational purposes only!"
echo ""

# Optional: Open browsers (uncomment if desired)
# echo "🌐 Opening browsers..."
# open http://localhost:8080 2>/dev/null || xdg-open http://localhost:8080 2>/dev/null || true
# open http://localhost:8081 2>/dev/null || xdg-open http://localhost:8081 2>/dev/null || true