#!/bin/bash

echo "🎯 VulnWeb - Starting Vulnerable Web Application"
echo "================================================"

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

echo "✅ Docker and Docker Compose are available"

# Start the application
echo "🚀 Starting VulnWeb application..."
docker-compose up -d

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Check if services are running
if docker-compose ps | grep -q "Up"; then
    echo "✅ VulnWeb is now running!"
    echo ""
    echo "📋 Access Information:"
    echo "   🌐 Web Application: http://localhost:8080"
    echo "   🗄️  MySQL Database: localhost:3306"
    echo ""
    echo "👤 Test Accounts:"
    echo "   Admin:     admin / admin123"
    echo "   User:      user1 / password123"
    echo "   Moderator: moderator / mod123"
    echo ""
    echo "🎯 Vulnerability Testing:"
    echo "   Debug Mode: http://localhost:8080?debug=1"
    echo "   Guide:      http://localhost:8080/vulnerabilities.php"
    echo ""
    echo "⚠️  WARNING: This application is intentionally vulnerable!"
    echo "   Only use in controlled environments for educational purposes."
    echo ""
    echo "🛑 To stop the application: docker-compose down"
else
    echo "❌ Failed to start VulnWeb. Check Docker logs:"
    docker-compose logs
fi