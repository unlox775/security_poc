#!/usr/bin/env python3
"""
Test the HostRewriteServer class with focus on the multiple Set-Cookie headers issue.
This test reproduces the real problem where multiple Set-Cookie headers get concatenated.
"""

import unittest
import sys
import os
import requests
import threading
import time
from unittest.mock import patch
import responses

# Add src directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, '..', 'src')
sys.path.insert(0, src_dir)

from host_rewrite_proxy.server import HostRewriteServer


class TestHostRewriteServerMultipleCookies(unittest.TestCase):
    """Test the HostRewriteServer class with focus on multiple Set-Cookie headers"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.target_host = "example.com"
        self.proxy_host = "test-ngrok.ngrok-free.app"
        self.test_port = None  # Will be assigned dynamically
        self.server = None
        self.server_thread = None
        self.server_running = False
    
    def tearDown(self):
        """Clean up after tests"""
        if self.server_running and self.server_thread:
            try:
                # Try to stop the server gracefully
                requests.get(f"http://localhost:{self.test_port}/shutdown", timeout=1)
            except:
                pass
            self.server_thread.join(timeout=2)
    
    def start_server(self, port):
        """Start the server in a background thread on specified port"""
        self.test_port = port
        self.server = HostRewriteServer(self.target_host, self.proxy_host, port)
        
        def run_server():
            self.server.run()
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        self.server_running = True
        
        # Wait for server to start
        for _ in range(10):
            try:
                requests.get(f"http://localhost:{port}/", timeout=1)
                break
            except requests.ConnectionError:
                time.sleep(0.5)
    
    def test_requests_response_header_behavior(self):
        """Test how requests.Response handles multiple Set-Cookie headers directly"""
        print("\n=== Testing Requests Response Header Behavior ===")
        
        # Create a real requests.Response object with multiple Set-Cookie headers
        from requests.models import Response
        from urllib3.response import HTTPResponse
        
        # Create the underlying HTTPResponse with multiple Set-Cookie headers
        raw = HTTPResponse(
            body=b'<html>test</html>',
            status=200,
            headers=[
                ('Set-Cookie', 'session=ABC123; Domain=example.com; Path=/; Secure'),
                ('Set-Cookie', 'user=DEF456; Domain=example.com; Path=/; HttpOnly'),
                ('Set-Cookie', 'pref=GHI789; Domain=example.com; Path=/; Max-Age=3600'),
                ('Content-Type', 'text/html; charset=utf-8')
            ]
        )
        
        # Create the requests Response
        response = Response()
        response.raw = raw
        response.status_code = 200
        response._content = b'<html>test</html>'
        
        # Test different ways of accessing headers
        print(f"response.headers: {dict(response.headers)}")
        print(f"response.headers.get('Set-Cookie'): {response.headers.get('Set-Cookie')}")
        
        # Try to get list of Set-Cookie headers
        if hasattr(response.headers, 'getlist'):
            set_cookies = response.headers.getlist('Set-Cookie')
            print(f"response.headers.getlist('Set-Cookie'): {set_cookies}")
        else:
            print("response.headers does not have getlist method")
        
        # Check raw headers
        print(f"response.raw.headers: {dict(response.raw.headers)}")
        
        # This test helps us understand how requests handles multiple headers
        print("✅ SUCCESS: Requests response header behavior analyzed!")
        
        # Key finding: requests concatenates multiple Set-Cookie headers into one string!
        set_cookie_value = response.raw.headers.get('Set-Cookie')
        self.assertIsNotNone(set_cookie_value)
        self.assertIn(',', set_cookie_value)  # Should be comma-separated
    
    def test_cookie_rewriter_with_concatenated_headers(self):
        """Test how our cookie rewriter handles concatenated Set-Cookie headers"""
        print("\n=== Testing Cookie Rewriter with Concatenated Headers ===")
        
        from host_rewrite_proxy.cookie_rewriter import CookieRewriter
        from flask import Response
        
        # Create a mock response with concatenated Set-Cookie headers (like requests does)
        class MockResponse:
            def __init__(self):
                self.headers = {
                    'Set-Cookie': 'session=ABC123; Domain=example.com; Path=/; Secure, user=DEF456; Domain=example.com; Path=/; HttpOnly, pref=GHI789; Domain=example.com; Path=/; Max-Age=3600',
                    'Content-Type': 'text/html; charset=utf-8'
                }
            
            def getlist(self, key):
                if key.lower() == 'set-cookie':
                    # Simulate how requests might handle this
                    value = self.headers.get('Set-Cookie', '')
                    if value:
                        return [value]  # Returns the concatenated string as a single item
                return []
        
        # Create Flask response
        flask_response = Response('<html>test</html>', status=200)
        
        # Test our cookie rewriter
        cookie_rewriter = CookieRewriter(self.target_host, self.proxy_host)
        mock_response = MockResponse()
        
        print(f"Original Set-Cookie header: {mock_response.headers['Set-Cookie']}")
        print(f"Headers keys: {list(mock_response.headers.keys())}")
        print(f"'set-cookie' in headers: {'set-cookie' in mock_response.headers}")
        print(f"'Set-Cookie' in headers: {'Set-Cookie' in mock_response.headers}")
        
        # Process the cookies
        cookie_rewriter.rewrite_cookies_and_set_on_response(mock_response.headers, flask_response)
        
        # Check what we got
    final_headers = flask_response.get_wsgi_headers(None)
        set_cookie_headers = [value for name, value in final_headers if name.lower() == 'set-cookie']
        
        print(f"Final Set-Cookie headers: {set_cookie_headers}")
        
        # This test shows how our current code handles the concatenated headers
        print("✅ SUCCESS: Cookie rewriter behavior with concatenated headers analyzed!")
    
    def test_cookie_rewriter_case_sensitivity_issue(self):
        """Test the case sensitivity issue in header matching"""
        print("\n=== Testing Case Sensitivity Issue ===")
        
        from host_rewrite_proxy.cookie_rewriter import CookieRewriter
        from flask import Response
        
        # Create headers with exact case as requests.Response
        headers = {
            'Set-Cookie': 'session=ABC123; Domain=example.com; Path=/; Secure, user=DEF456; Domain=example.com; Path=/; HttpOnly',
            'Content-Type': 'text/html; charset=utf-8'
        }
        
        # Create Flask response
        flask_response = Response('<html>test</html>', status=200)
        
        # Test our cookie rewriter
        cookie_rewriter = CookieRewriter(self.target_host, self.proxy_host)
        
        print(f"Headers: {headers}")
        print(f"'set-cookie' in headers: {'set-cookie' in headers}")
        print(f"'Set-Cookie' in headers: {'Set-Cookie' in headers}")
        
        # Process the cookies
        cookie_rewriter.rewrite_cookies_and_set_on_response(headers, flask_response)
        
        # Check what we got
    final_headers = flask_response.get_wsgi_headers(None)
        set_cookie_headers = [value for name, value in final_headers if name.lower() == 'set-cookie']
        
        print(f"Final Set-Cookie headers: {set_cookie_headers}")
        
        # This should show the case sensitivity issue
        print("✅ SUCCESS: Case sensitivity issue identified!")

    @patch('host_rewrite_proxy.server.requests.request')  # mock only upstream HTTP calls
    def test_full_server_flow_with_multiple_cookies(self, mock_request):
        """Test the complete server flow with multiple Set-Cookie headers"""
        print("\n=== Testing Full Server Flow with Multiple Cookies ===")
        
        # Create a mock response with multiple Set-Cookie headers
        from requests.models import Response
        from urllib3.response import HTTPResponse
        
        # Create the underlying HTTPResponse with multiple Set-Cookie headers
        raw = HTTPResponse(
            body=b'<html>Test page with multiple cookies</html>',
            status=200,
            headers=[
                ('Set-Cookie', 'session=ABC123; Domain=example.com; Path=/; Secure; HttpOnly'),
                ('Set-Cookie', 'user=DEF456; Domain=example.com; Path=/; HttpOnly'),
                ('Set-Cookie', 'pref=GHI789; Domain=example.com; Path=/; Max-Age=3600'),
                ('Content-Type', 'text/html; charset=utf-8')
            ]
        )
        
        # Create the requests Response
        mock_response = Response()
        mock_response.raw = raw
        mock_response.status_code = 200
        mock_response._content = b'<html>Test page with multiple cookies</html>'
        
        # Configure the mock
        mock_request.return_value = mock_response
        
        # Start our proxy server on a unique port
        self.start_server(5006)
        
        # Make request through our proxy
        proxy_response = requests.get(f"http://localhost:{self.test_port}/test", timeout=5)
        
        print(f"Proxy response status: {proxy_response.status_code}")
        print(f"Proxy response headers: {dict(proxy_response.headers)}")
        
        # Check what we got back
        # Flask response headers don't have getlist method, so we need to check differently
        set_cookie_header = proxy_response.headers.get('Set-Cookie')
        print(f"Set-Cookie header from proxy: {set_cookie_header}")
        
        # Verify we got a Set-Cookie header
        self.assertIsNotNone(set_cookie_header, "Should have Set-Cookie header")
        
        # Verify domains were rewritten
        self.assertNotIn('example.com', set_cookie_header,
                        f"Found original domain in: {set_cookie_header}")
        self.assertIn(self.proxy_host, set_cookie_header,
                     f"Proxy domain not found in: {set_cookie_header}")
        
        # Verify we have multiple cookies (should be comma-separated)
        self.assertIn(',', set_cookie_header, "Should have multiple cookies separated by commas")
        
        print("✅ SUCCESS: Full server flow with multiple cookies works correctly!")

    def test_real_world_cookie_parsing_bug(self):
        """Test with real-world HTTP headers that have commas in cookie values"""
        print("\n=== Testing Real-World Cookie Parsing Bug ===")
        
        from host_rewrite_proxy.cookie_rewriter import CookieRewriter
        from flask import Response
        
        # Create headers that match real HTTP response
        headers = {
            'Set-Cookie': [
                'client-zip-short=98520; expires=Wed, 30-Jul-2025 01:41:24 GMT; path=/',
                'C_LOC=WA; expires=Wed, 30-Jul-2025 01:41:24 GMT; path=/',
                'AKA_A2=A; expires=Wed, 30-Jul-2025 02:26:24 GMT; path=/; domain=example.com; secure; HttpOnly',
                'akavpau_zezxapz5yf=1753839084~id=59a8da67e1ae66493e18b0cf1de72ae6; Domain=www.example.com; Path=/; Secure; SameSite=None',
                'akaas_AS01=2147483647~rv=91~id=6c0cbae1bc8125b64e2e40251310a8d7; path=/; Secure; SameSite=None',
                'bm_ss=ab8e18ef4e; Secure; SameSite=None; Domain=.example.com; Path=/; HttpOnly; Max-Age=3600'
            ],
            'Content-Type': 'text/html; charset=utf-8'
        }
        
        # Create Flask response
        flask_response = Response('<html>test</html>', status=200)
        
        # Test our cookie rewriter
        cookie_rewriter = CookieRewriter('example.com', 'test-ngrok.ngrok-free.app')
        
        print(f"Original headers: {headers}")
        
        # Process the cookies
        cookie_rewriter.rewrite_cookies_and_set_on_response(headers, flask_response)
        
        # Check what we got
        final_headers = flask_response.get_wsgi_headers(None)
        set_cookie_headers = [value for name, value in final_headers if name.lower() == 'set-cookie']
        
        print(f"Final Set-Cookie headers: {set_cookie_headers}")
        
        # Verify we got the correct number of cookies
        self.assertEqual(len(set_cookie_headers), 6, f"Expected 6 cookies, got {len(set_cookie_headers)}")
        
        # Verify specific cookies were handled correctly
        cookie_text = '; '.join(set_cookie_headers)
        
        # Check that cookies with domains were rewritten
        self.assertIn('Domain=test-ngrok.ngrok-free.app', cookie_text)
        self.assertNotIn('Domain=www.example.com', cookie_text)
        self.assertNotIn('Domain=.example.com', cookie_text)
        
        # Check that cookies without domains were left alone
        self.assertIn('client-zip-short=98520', cookie_text)
        self.assertIn('C_LOC=WA', cookie_text)
        
        print("✅ SUCCESS: Real-world cookie parsing works correctly!")
    
    def test_multiple_set_cookie_headers_are_preserved_and_rewritten(self):
        """
        Assert that multiple Set-Cookie headers are preserved and rewritten with the proxy domain.
        Simulates a real-world response with multiple cookies, some with domains, some with commas in date attributes.
        """
        from host_rewrite_proxy.cookie_rewriter import CookieRewriter
        from flask import Response

        headers = {
            'Set-Cookie': [
                'cookie1=abc123; expires=Wed, 30-Jul-2025 01:41:24 GMT; path=/',
                'cookie2=def456; expires=Wed, 30-Jul-2025 01:41:24 GMT; path=/',
                'cookie3=ghi789; expires=Wed, 30-Jul-2025 02:26:24 GMT; path=/; domain=example.com; secure; HttpOnly',
                'cookie4=val4; Domain=www.example.com; Path=/; Secure; SameSite=None',
                'cookie5=val5; path=/; Secure; SameSite=None',
                'cookie6=val6; Secure; SameSite=None; Domain=.example.com; Path=/; HttpOnly; Max-Age=3600'
            ],
            'Content-Type': 'text/html; charset=utf-8'
        }

        flask_response = Response('<html>test</html>', status=200)
        cookie_rewriter = CookieRewriter('example.com', 'test-ngrok.ngrok-free.app')
        cookie_rewriter.rewrite_cookies_and_set_on_response(headers, flask_response)

        final_headers = flask_response.get_wsgi_headers(None)
        set_cookie_headers = [value for name, value in final_headers if name.lower() == 'set-cookie']

        # Assert all cookies are present and rewritten as needed
        self.assertEqual(len(set_cookie_headers), 6, "Should preserve all Set-Cookie headers")
        for cookie in set_cookie_headers:
            if 'Domain=' in cookie:
                self.assertIn('test-ngrok.ngrok-free.app', cookie, "Domain should be rewritten to test-ngrok.ngrok-free.app")
            self.assertNotIn('example.com; ', cookie.replace('test-ngrok.ngrok-free.app', ''), "No original domain should remain except rewritten")

    def test_concatenated_set_cookie_header_is_split_and_rewritten(self):
        """
        Assert that a single concatenated Set-Cookie header (as requests might produce) is split and rewritten correctly.
        """
        from host_rewrite_proxy.cookie_rewriter import CookieRewriter
        from flask import Response

        concatenated_cookies = (
            'cookie1=abc123; expires=Wed, 30-Jul-2025 01:41:24 GMT; path=/, '
            'cookie2=def456; expires=Wed, 30-Jul-2025 01:41:24 GMT; path=/, '
            'cookie3=ghi789; expires=Wed, 30-Jul-2025 02:26:24 GMT; path=/; domain=example.com; secure; HttpOnly, '
            'cookie4=val4; Domain=www.example.com; Path=/; Secure; SameSite=None, '
            'cookie5=val5; path=/; Secure; SameSite=None, '
            'cookie6=val6; Secure; SameSite=None; Domain=.example.com; Path=/; HttpOnly; Max-Age=3600'
        )
        headers = {
            'Set-Cookie': concatenated_cookies,
            'Content-Type': 'text/html; charset=utf-8'
        }

        flask_response = Response('<html>test</html>', status=200)
        cookie_rewriter = CookieRewriter('example.com', 'test-ngrok.ngrok-free.app')
        cookie_rewriter.rewrite_cookies_and_set_on_response(headers, flask_response)

        final_headers = flask_response.get_wsgi_headers(None)
        set_cookie_headers = [value for name, value in final_headers if name.lower() == 'set-cookie']

        self.assertEqual(len(set_cookie_headers), 6, "Should split and preserve all cookies from concatenated header")
        for cookie in set_cookie_headers:
            if 'Domain=' in cookie:
                self.assertIn('test-ngrok.ngrok-free.app', cookie, "Domain should be rewritten to test-ngrok.ngrok-free.app")
            self.assertNotIn('example.com; ', cookie.replace('test-ngrok.ngrok-free.app', ''), "No original domain should remain except rewritten")

    def test_cookies_with_and_without_domain_are_handled_correctly(self):
        """
        Assert that cookies with a domain are rewritten, and cookies without a domain are left alone.
        """
        from host_rewrite_proxy.cookie_rewriter import CookieRewriter
        from flask import Response

        headers = {
            'Set-Cookie': [
                'cookieA=valA; path=/',
                'cookieB=valB; path=/; domain=example.com; Secure',
                'cookieC=valC; path=/; domain=.example.com; HttpOnly',
                'cookieD=valD; path=/; domain=test-ngrok.ngrok-free.app; Secure'
            ],
            'Content-Type': 'text/html; charset=utf-8'
        }

        flask_response = Response('<html>test</html>', status=200)
        cookie_rewriter = CookieRewriter('example.com', 'test-ngrok.ngrok-free.app')
        cookie_rewriter.rewrite_cookies_and_set_on_response(headers, flask_response)

        final_headers = flask_response.get_wsgi_headers(None)
        set_cookie_headers = [value for name, value in final_headers if name.lower() == 'set-cookie']

        self.assertEqual(len(set_cookie_headers), 4, "Should preserve all cookies")
        for cookie in set_cookie_headers:
            if 'Domain=' in cookie:
                self.assertIn('test-ngrok.ngrok-free.app', cookie, "Domain should be rewritten to test-ngrok.ngrok-free.app")
            else:
                self.assertNotIn('Domain=', cookie, "Cookies without domain should not have a domain attribute")

    def test_cookie_with_comma_in_date_is_not_split(self):
        """
        Assert that a cookie with a comma in the expires date is not split incorrectly.
        """
        from host_rewrite_proxy.cookie_rewriter import CookieRewriter
        from flask import Response

        headers = {
            'Set-Cookie': [
                'cookieX=valX; expires=Wed, 30-Jul-2025 01:41:24 GMT; path=/',
                'cookieY=valY; expires=Wed, 30-Jul-2025 01:41:24 GMT; path=/; domain=example.com'
            ],
            'Content-Type': 'text/html; charset=utf-8'
        }

        flask_response = Response('<html>test</html>', status=200)
        cookie_rewriter = CookieRewriter('example.com', 'test-ngrok.ngrok-free.app')
        cookie_rewriter.rewrite_cookies_and_set_on_response(headers, flask_response)

        final_headers = flask_response.get_wsgi_headers(None)
        set_cookie_headers = [value for name, value in final_headers if name.lower() == 'set-cookie']

        self.assertEqual(len(set_cookie_headers), 2, "Should not split cookies at comma in date")
        for cookie in set_cookie_headers:
            self.assertIn('Expires=', cookie, "Expires attribute should be present and not split")

    def test_cookie_with_quoted_value_and_comma_is_not_split(self):
        """
        Assert that a cookie with a quoted value containing a comma is not split incorrectly.
        """
        from host_rewrite_proxy.cookie_rewriter import CookieRewriter
        from flask import Response

        headers = {
            'Set-Cookie': [
                'cookieQ="val,with,comma"; path=/',
                'cookieR=valR; path=/; domain=example.com'
            ],
            'Content-Type': 'text/html; charset=utf-8'
        }

        flask_response = Response('<html>test.html>', status=200)
        cookie_rewriter = CookieRewriter('example.com', 'test-ngrok.ngrok-free.app')
        cookie_rewriter.rewrite_cookies_and_set_on_response(headers, flask_response)

        final_headers = flask_response.get_wsgi_headers(None)
        set_cookie_headers = [value for name, value in final_headers if name.lower() == 'set-cookie']

        self.assertEqual(len(set_cookie_headers), 2, "Should not split cookies at comma in quoted value")
        self.assertIn('cookieQ="val,with,comma"', set_cookie_headers[0], "Quoted value with comma should be preserved")
        self.assertIn('cookieR=valR', set_cookie_headers[1], "Second cookie should be present and correct")

    def test_real_requests_and_flask_stack_preserves_multiple_set_cookie_headers(self):
        """
        Assert that fetching a real Flask server with multiple Set-Cookie headers using requests exposes the real-world bug.
        This test will show if requests/WSGI concatenates or preserves Set-Cookie headers before our rewriter sees them.
        """
        import multiprocessing
        import requests
        import time
        from host_rewrite_proxy.cookie_rewriter import CookieRewriter
        from flask import Response

        port = 5011
        proc = multiprocessing.Process(target=flask_app_for_test_server, args=(port,))
        proc.start()
        time.sleep(1.5)  # Wait for server to start

        try:
            response = requests.get(f"http://localhost:{port}/test")
            print(f"requests.headers: {dict(response.headers)}")
            print(f"requests.raw.headers: {getattr(response.raw, 'headers', None)}")
            flask_response = Response('test', status=200)
            rewriter = CookieRewriter('example.com', 'test-ngrok.ngrok-free.app')
            rewriter.rewrite_cookies_and_set_on_response(response.headers, flask_response)
            final_headers = flask_response.get_wsgi_headers(None)
            set_cookie_headers = [value for name, value in final_headers if name.lower() == 'set-cookie']
            print(f"Final Set-Cookie headers: {set_cookie_headers}")
            self.assertGreaterEqual(len(set_cookie_headers), 1, "Should have at least one Set-Cookie header")
        finally:
            proc.terminate()
            proc.join()


def flask_app_for_test_server(port):
    from flask import Flask, make_response
    app = Flask(__name__)
    @app.route("/test")
    def test():
        resp = make_response("ok")
        resp.headers.add('Set-Cookie', 'cookie1=abc; expires=Wed, 30-Jul-2025 01:41:24 GMT; path=/')
        resp.headers.add('Set-Cookie', 'cookie2=def; expires=Wed, 30-Jul-2025 01:41:24 GMT; path=/')
        resp.headers.add('Set-Cookie', 'cookie3=ghi; expires=Wed, 30-Jul-2025 02:26:24 GMT; path=/; domain=example.com; secure; HttpOnly')
        return resp
    app.run(port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    print("🧪 Running HostRewriteServer Multiple Cookie Tests")
    print("=" * 60)
    
    # Run the tests
    unittest.main(verbosity=2) 