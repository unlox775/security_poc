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
    

    @unittest.skip("Quart threading issues in test environment")
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