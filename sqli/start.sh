#!/bin/bash

# Quick Start Script untuk SQL Injection Demo
echo "🚀 Starting SQL Injection Demo Environment..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose not found. Please install docker-compose."
    exit 1
fi

echo "📦 Building and starting containers..."
docker-compose up -d

echo "⏳ Waiting for services to be ready..."
sleep 30

# Check if web service is responding
echo "🔍 Checking web service..."
if curl -s http://localhost:8080 > /dev/null; then
    echo "✅ Web service is ready!"
else
    echo "⚠️  Web service might still be starting..."
fi

# Check if database is ready
echo "🔍 Checking database..."
if docker-compose exec -T db mysql -u root -ppassword123 -e "SELECT 1;" > /dev/null 2>&1; then
    echo "✅ Database is ready!"
else
    echo "⚠️  Database might still be starting..."
fi

echo ""
echo "🎯 Environment Ready!"
echo "========================"
echo "🌐 Web Application: http://localhost:8080"
echo "🗄️  Database: localhost:3306 (root/password123)"
echo ""
echo "📚 Quick Start Guide:"
echo "1. Open http://localhost:8080 in your browser"
echo "2. Try login with: admin' OR '1'='1' --"
echo "3. Check out /search.php for more vulnerabilities"
echo "4. Run ./test_sqli.sh for automated testing"
echo ""
echo "📖 Read README.md for complete documentation"
echo "🎯 Check payloads.md for more attack vectors"
echo ""
echo "⚠️  Remember: This is for EDUCATIONAL purposes only!"

# Optional: Run basic tests
read -p "🧪 Do you want to run basic SQL injection tests? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🧪 Running basic tests..."
    ./test_sqli.sh
fi

echo "🎓 Happy Learning!"
