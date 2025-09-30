#!/bin/bash

# XSS Lab Testing Script
# This script demonstrates the differences between vulnerable and secure implementations

echo "🧪 XSS Hands-On Lab - Security Testing"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test URLs
VULNERABLE_BASE="http://localhost:8080"
SECURE_BASE="http://localhost:8081"

# Test payload
XSS_PAYLOAD="<script>alert('XSS')</script>"
ENCODED_PAYLOAD=$(echo "$XSS_PAYLOAD" | sed 's/</%3C/g; s/>/%3E/g; s/ /%20/g; s/'\''/%27/g; s/"/%22/g')

echo -e "${BLUE}🎯 Testing Reflected XSS${NC}"
echo "==============================="

echo -e "${YELLOW}Testing Vulnerable App:${NC}"
echo "URL: $VULNERABLE_BASE/reflected.php?search=$ENCODED_PAYLOAD"
VULNERABLE_RESPONSE=$(curl -s "$VULNERABLE_BASE/reflected.php?search=$ENCODED_PAYLOAD")

if echo "$VULNERABLE_RESPONSE" | grep -q "<script>alert('XSS')</script>"; then
    echo -e "${RED}❌ VULNERABLE: XSS payload is reflected without encoding${NC}"
else
    echo -e "${GREEN}✅ Payload was filtered or encoded${NC}"
fi

echo ""
echo -e "${YELLOW}Testing Secure App:${NC}"
echo "URL: $SECURE_BASE/reflected.php?search=$ENCODED_PAYLOAD"
SECURE_RESPONSE=$(curl -s "$SECURE_BASE/reflected.php?search=$ENCODED_PAYLOAD")

if echo "$SECURE_RESPONSE" | grep -q "<script>alert('XSS')</script>"; then
    echo -e "${RED}❌ VULNERABLE: XSS payload is reflected without encoding${NC}"
else
    echo -e "${GREEN}✅ SECURE: XSS payload was properly encoded${NC}"
fi

echo ""
echo -e "${BLUE}🔍 Response Analysis${NC}"
echo "==================="

echo -e "${YELLOW}Vulnerable App Response (showing payload area):${NC}"
echo "$VULNERABLE_RESPONSE" | grep -A2 -B2 "You searched for:" | head -5

echo ""
echo -e "${YELLOW}Secure App Response (showing payload area):${NC}"
echo "$SECURE_RESPONSE" | grep -A2 -B2 "You searched for:" | head -5

echo ""
echo -e "${BLUE}📊 Security Headers Comparison${NC}"
echo "================================"

echo -e "${YELLOW}Vulnerable App Headers:${NC}"
curl -s -I "$VULNERABLE_BASE" | grep -E "(X-XSS-Protection|Content-Security-Policy|X-Content-Type-Options|X-Frame-Options)" || echo "No security headers found"

echo ""
echo -e "${YELLOW}Secure App Headers:${NC}"
curl -s -I "$SECURE_BASE" | grep -E "(X-XSS-Protection|Content-Security-Policy|X-Content-Type-Options|X-Frame-Options)"

echo ""
echo -e "${BLUE}🧪 Additional Test Payloads${NC}"
echo "============================="

# Array of test payloads
declare -a test_payloads=(
    "<img src=x onerror=alert('XSS')>"
    "<svg onload=alert('XSS')>"
    "\" onmouseover=\"alert('XSS')"
    "<iframe src=\"javascript:alert('XSS')\"></iframe>"
)

for payload in "${test_payloads[@]}"; do
    encoded=$(echo "$payload" | sed 's/</%3C/g; s/>/%3E/g; s/ /%20/g; s/'\''/%27/g; s/"/%22/g')
    
    echo -e "${YELLOW}Testing payload: ${NC}$payload"
    
    # Test vulnerable app
    vuln_resp=$(curl -s "$VULNERABLE_BASE/reflected.php?search=$encoded")
    if echo "$vuln_resp" | grep -q "$(echo "$payload" | sed 's/[]\/$*.^[]/\\&/g')"; then
        echo -e "  ${RED}❌ Vulnerable app: UNFILTERED${NC}"
    else
        echo -e "  ${GREEN}✅ Vulnerable app: Filtered${NC}"
    fi
    
    # Test secure app
    secure_resp=$(curl -s "$SECURE_BASE/reflected.php?search=$encoded")
    if echo "$secure_resp" | grep -q "$(echo "$payload" | sed 's/[]\/$*.^[]/\\&/g')"; then
        echo -e "  ${RED}❌ Secure app: UNFILTERED${NC}"
    else
        echo -e "  ${GREEN}✅ Secure app: Properly encoded${NC}"
    fi
    echo ""
done

echo -e "${BLUE}📋 Test Summary${NC}"
echo "==============="
echo -e "${YELLOW}Vulnerable Application:${NC} http://localhost:8080"
echo -e "${YELLOW}Secure Application:${NC} http://localhost:8081"
echo -e "${YELLOW}phpMyAdmin:${NC} http://localhost:8082"
echo ""
echo -e "${GREEN}✅ Testing completed!${NC}"
echo ""
echo -e "${BLUE}📖 Next Steps:${NC}"
echo "1. Open both applications in your browser"
echo "2. Try the test payloads manually"
echo "3. Compare the behavior and source code"
echo "4. Read the documentation files (README.md, EXERCISES.md)"
echo "5. Practice with the exercises provided"
echo ""
echo -e "${YELLOW}⚠️  Remember: Use this lab for educational purposes only!${NC}"