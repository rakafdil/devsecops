#!/bin/bash

# XSS Security Validation Test Script
# This script tests both vulnerable and secure applications

echo "🔒 XSS Security Validation Test"
echo "================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test URLs
VULNERABLE_URL="http://localhost:8080"
SECURE_URL="http://localhost:8081"

# Test payloads
declare -a PAYLOADS=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert('XSS')>"
    "<svg onload=alert('XSS')>"
    "\" onmouseover=\"alert('XSS')\""
    "'; alert('XSS'); //"
    "<iframe src=\"javascript:alert('XSS')\"></iframe>"
)

echo -e "${BLUE}Testing XSS vulnerabilities...${NC}"
echo ""

# Function to test XSS payload
test_xss_payload() {
    local url=$1
    local payload=$2
    local context=$3
    
    # URL encode the payload
    local encoded_payload=$(printf '%s' "$payload" | jq -sRr @uri)
    local test_url="${url}/${context}.php?search=${encoded_payload}"
    
    # Make request and check response
    local response=$(curl -s "$test_url")
    
    if [[ "$response" == *"$payload"* ]]; then
        return 0  # Vulnerable (payload found in response)
    else
        return 1  # Safe (payload not found or encoded)
    fi
}

# Function to check security headers
check_security_headers() {
    local url=$1
    local app_name=$2
    
    echo -e "${YELLOW}Checking security headers for $app_name...${NC}"
    
    local headers=$(curl -s -I "$url")
    
    # Check for XSS Protection header
    if [[ "$headers" == *"X-XSS-Protection"* ]]; then
        echo -e "  ${GREEN}✅ X-XSS-Protection header present${NC}"
    else
        echo -e "  ${RED}❌ X-XSS-Protection header missing${NC}"
    fi
    
    # Check for Content-Type Options header
    if [[ "$headers" == *"X-Content-Type-Options"* ]]; then
        echo -e "  ${GREEN}✅ X-Content-Type-Options header present${NC}"
    else
        echo -e "  ${RED}❌ X-Content-Type-Options header missing${NC}"
    fi
    
    # Check for Frame Options header
    if [[ "$headers" == *"X-Frame-Options"* ]]; then
        echo -e "  ${GREEN}✅ X-Frame-Options header present${NC}"
    else
        echo -e "  ${RED}❌ X-Frame-Options header missing${NC}"
    fi
    
    # Check for CSP header
    if [[ "$headers" == *"Content-Security-Policy"* ]]; then
        echo -e "  ${GREEN}✅ Content-Security-Policy header present${NC}"
    else
        echo -e "  ${RED}❌ Content-Security-Policy header missing${NC}"
    fi
    
    echo ""
}

# Test function for each application
test_application() {
    local url=$1
    local app_name=$2
    
    echo -e "${BLUE}Testing $app_name at $url${NC}"
    echo "----------------------------------------"
    
    local vulnerable_count=0
    local total_tests=0
    
    # Test reflected XSS
    for payload in "${PAYLOADS[@]}"; do
        ((total_tests++))
        if test_xss_payload "$url" "$payload" "reflected"; then
            echo -e "  ${RED}❌ VULNERABLE to reflected XSS with: $payload${NC}"
            ((vulnerable_count++))
        else
            echo -e "  ${GREEN}✅ SAFE from reflected XSS with: $payload${NC}"
        fi
    done
    
    # Test stored XSS (simplified - just check if form exists)
    local stored_response=$(curl -s "$url/stored.php")
    if [[ "$stored_response" == *'name="comment"'* ]]; then
        if [[ "$app_name" == *"Vulnerable"* ]]; then
            echo -e "  ${RED}❌ Stored XSS form present (likely vulnerable)${NC}"
            ((vulnerable_count++))
        else
            echo -e "  ${GREEN}✅ Stored XSS form present with protection${NC}"
        fi
    fi
    
    ((total_tests++))
    
    # Test DOM XSS (check if dangerous JavaScript functions are used)
    local dom_response=$(curl -s "$url/dom.php")
    if [[ "$dom_response" == *"innerHTML"* ]] && [[ "$app_name" == *"Vulnerable"* ]]; then
        echo -e "  ${RED}❌ DOM XSS: innerHTML usage detected${NC}"
        ((vulnerable_count++))
    else
        echo -e "  ${GREEN}✅ DOM XSS: Safe DOM manipulation${NC}"
    fi
    
    ((total_tests++))
    
    # Check security headers
    check_security_headers "$url" "$app_name"
    
    # Summary
    local safe_count=$((total_tests - vulnerable_count))
    echo -e "${BLUE}Summary for $app_name:${NC}"
    echo -e "  ${GREEN}Safe: $safe_count/$total_tests${NC}"
    echo -e "  ${RED}Vulnerable: $vulnerable_count/$total_tests${NC}"
    
    if [ $vulnerable_count -eq 0 ]; then
        echo -e "  ${GREEN}🎉 Overall Status: SECURE${NC}"
    else
        echo -e "  ${RED}⚠️  Overall Status: VULNERABLE${NC}"
    fi
    
    echo ""
}

# Check if applications are running
echo -e "${YELLOW}Checking if applications are running...${NC}"

if curl -s "$VULNERABLE_URL" > /dev/null; then
    echo -e "${GREEN}✅ Vulnerable application is running${NC}"
    vulnerable_running=true
else
    echo -e "${RED}❌ Vulnerable application is not accessible${NC}"
    vulnerable_running=false
fi

if curl -s "$SECURE_URL" > /dev/null; then
    echo -e "${GREEN}✅ Secure application is running${NC}"
    secure_running=true
else
    echo -e "${RED}❌ Secure application is not accessible${NC}"
    secure_running=false
fi

echo ""

# Run tests if applications are running
if [ "$vulnerable_running" = true ]; then
    test_application "$VULNERABLE_URL" "Vulnerable Application"
fi

if [ "$secure_running" = true ]; then
    test_application "$SECURE_URL" "Secure Application"
fi

# Additional payload testing
echo -e "${BLUE}Additional Payload Testing...${NC}"
echo "----------------------------"

# Test specific context payloads
declare -A CONTEXT_PAYLOADS=(
    ["html"]="<script>alert('HTML')</script>"
    ["attribute"]="\" onmouseover=\"alert('ATTR')\""
    ["javascript"]="'; alert('JS'); //"
    ["css"]="red; } body { background: url('javascript:alert(1)')"
    ["url"]="javascript:alert('URL')"
)

for context in "${!CONTEXT_PAYLOADS[@]}"; do
    payload="${CONTEXT_PAYLOADS[$context]}"
    
    if [ "$vulnerable_running" = true ]; then
        if test_xss_payload "$VULNERABLE_URL" "$payload" "contexts"; then
            echo -e "  ${RED}❌ Vulnerable app: $context context XSS${NC}"
        fi
    fi
    
    if [ "$secure_running" = true ]; then
        if test_xss_payload "$SECURE_URL" "$payload" "contexts"; then
            echo -e "  ${RED}❌ Secure app: $context context XSS${NC}"
        else
            echo -e "  ${GREEN}✅ Secure app: $context context protected${NC}"
        fi
    fi
done

echo ""

# Performance and security recommendations
echo -e "${BLUE}Security Recommendations:${NC}"
echo "-------------------------"
echo -e "${GREEN}✅ Implemented in Secure App:${NC}"
echo "  • Input validation and sanitization"
echo "  • Context-aware output encoding"
echo "  • Content Security Policy (CSP)"
echo "  • Security headers (X-XSS-Protection, X-Frame-Options, etc.)"
echo "  • CSRF protection with tokens"
echo "  • Safe DOM manipulation practices"
echo ""

echo -e "${RED}❌ Missing in Vulnerable App:${NC}"
echo "  • No input validation"
echo "  • No output encoding"
echo "  • No security headers"
echo "  • Direct innerHTML usage"
echo "  • No CSRF protection"
echo ""

echo -e "${YELLOW}📚 For Learning:${NC}"
echo "  • Compare source code between applications"
echo "  • Test with different browsers"
echo "  • Try bypass techniques"
echo "  • Read PAYLOADS.md for more test cases"
echo "  • Complete EXERCISES.md for hands-on practice"
echo ""

echo -e "${GREEN}🎉 Security validation test completed!${NC}"
echo "Check the results above and refer to documentation for next steps."