#!/usr/bin/env python3
"""
Test the server's cookie handling flow with simple, readable examples.
"""

import unittest
from unittest.mock import Mock
from flask import Response
from src.host_rewrite_proxy.cookie_rewriter import CookieRewriter


class MockHeaders:
    """Mock headers that behave like requests.Response.headers"""
    
    def __init__(self, headers_dict):
        self._headers = headers_dict
    
    def getlist(self, key):
        """Return list of values for a header"""
        key_lower = key.lower()
        if key_lower in self._headers:
            value = self._headers[key_lower]
            if isinstance(value, list):
                return value
            return [value]
        return []
    
    def get(self, key, default=None):
        """Get a single header value"""
        key_lower = key.lower()
        return self._headers.get(key_lower, default)
    
    def __contains__(self, key):
        """Check if header exists"""
        return key.lower() in self._headers
    
    def __iter__(self):
        """Iterate over header keys"""
        return iter(self._headers.keys())
    
    def keys(self):
        """Get header keys"""
        return self._headers.keys()
    
    def items(self):
        """Get header items"""
        return self._headers.items()
    
    def __getitem__(self, key):
        """Get header by key"""
        return self._headers[key.lower()]
    
    def __setitem__(self, key, value):
        """Set header by key"""
        self._headers[key.lower()] = value


def create_mock_response(cookie_headers):
    """Create a mock requests.Response with the given cookie headers"""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.content = b"<html>Test content</html>"
    
    # Create headers with set-cookie
    headers_dict = {
        'content-type': 'text/html; charset=utf-8',
        'content-length': '25'
    }
    
    if cookie_headers:
        headers_dict['set-cookie'] = cookie_headers
    
    mock_response.headers = MockHeaders(headers_dict)
    return mock_response


def create_flask_response(mock_response):
    """Create a Flask response from the mock response"""
    flask_response = Response(
        mock_response.content,
        status=mock_response.status_code
    )
    
    # Add non-cookie headers
    for key, value in mock_response.headers.items():
        if key.lower() != 'set-cookie':
            flask_response.headers[key] = value
    
    return flask_response


def process_cookies(mock_response, flask_response, target_host, proxy_host):
    """Process cookies using the cookie rewriter"""
    cookie_rewriter = CookieRewriter(target_host, proxy_host)
    cookie_rewriter.rewrite_cookies_and_set_on_response(mock_response.headers, flask_response)
    return cookie_rewriter


def test_single_cookie_header():
    """Test handling a single Set-Cookie header with one cookie"""
    print("=== Testing Single Cookie Header ===")
    
    # Arrange
    target_host = "example.com"
    proxy_host = "test-ngrok.ngrok-free.app"
    cookie_headers = ["session=ABC123; Domain=example.com; Path=/; Secure"]
    
    # Act
    mock_response = create_mock_response(cookie_headers)
    flask_response = create_flask_response(mock_response)
    process_cookies(mock_response, flask_response, target_host, proxy_host)
    
    # Assert
    final_headers = flask_response.get_wsgi_headers(None)
    print(f"Final headers: {dict(final_headers)}")
    
    # Verify domain was rewritten
    for header_name, header_value in final_headers:
        if header_name.lower() == 'set-cookie':
            if 'example.com' in header_value:
                raise AssertionError(f"Found example.com domain in: {header_value}")
            if proxy_host not in header_value:
                raise AssertionError(f"Proxy domain not found in: {header_value}")
    
    print("✅ SUCCESS: Single cookie domain rewritten correctly!")


def test_multiple_cookies_in_one_header():
    """Test handling multiple cookies in a single Set-Cookie header"""
    print("=== Testing Multiple Cookies in One Header ===")
    
    # Arrange
    target_host = "example.com"
    proxy_host = "test-ngrok.ngrok-free.app"
    cookie_headers = ["session=ABC123; Domain=example.com; Path=/; Secure, user=DEF456; Domain=example.com; Path=/; HttpOnly"]
    
    # Act
    mock_response = create_mock_response(cookie_headers)
    flask_response = create_flask_response(mock_response)
    process_cookies(mock_response, flask_response, target_host, proxy_host)
    
    # Assert
    final_headers = flask_response.get_wsgi_headers(None)
    print(f"Final headers: {dict(final_headers)}")
    
    # Count Set-Cookie headers
    set_cookie_count = sum(1 for name, _ in final_headers if name.lower() == 'set-cookie')
    print(f"Found {set_cookie_count} Set-Cookie headers")
    
    # Verify all domains were rewritten
    for header_name, header_value in final_headers:
        if header_name.lower() == 'set-cookie':
            if 'example.com' in header_value:
                raise AssertionError(f"Found example.com domain in: {header_value}")
            if proxy_host not in header_value:
                raise AssertionError(f"Proxy domain not found in: {header_value}")
    
    print("✅ SUCCESS: Multiple cookies in one header rewritten correctly!")


def test_multiple_set_cookie_headers():
    """Test handling multiple Set-Cookie headers"""
    print("=== Testing Multiple Set-Cookie Headers ===")
    
    # Arrange
    target_host = "example.com"
    proxy_host = "test-ngrok.ngrok-free.app"
    cookie_headers = [
        "session=ABC123; Domain=example.com; Path=/; Secure",
        "user=DEF456; Domain=example.com; Path=/; HttpOnly",
        "pref=GHI789; Domain=example.com; Path=/; Max-Age=3600"
    ]
    
    # Act
    mock_response = create_mock_response(cookie_headers)
    flask_response = create_flask_response(mock_response)
    process_cookies(mock_response, flask_response, target_host, proxy_host)
    
    # Assert
    final_headers = flask_response.get_wsgi_headers(None)
    print(f"Final headers: {dict(final_headers)}")
    
    # Count Set-Cookie headers
    set_cookie_count = sum(1 for name, _ in final_headers if name.lower() == 'set-cookie')
    print(f"Found {set_cookie_count} Set-Cookie headers")
    
    # Verify all domains were rewritten
    for header_name, header_value in final_headers:
        if header_name.lower() == 'set-cookie':
            if 'example.com' in header_value:
                raise AssertionError(f"Found example.com domain in: {header_value}")
            if proxy_host not in header_value:
                raise AssertionError(f"Proxy domain not found in: {header_value}")
    
    print("✅ SUCCESS: Multiple Set-Cookie headers rewritten correctly!")


def test_cookies_without_domain():
    """Test handling cookies that don't have a Domain attribute"""
    print("=== Testing Cookies Without Domain ===")
    
    # Arrange
    target_host = "example.com"
    proxy_host = "test-ngrok.ngrok-free.app"
    cookie_headers = [
        "session=ABC123; Path=/; Secure",
        "user=DEF456; Path=/; HttpOnly"
    ]
    
    # Act
    mock_response = create_mock_response(cookie_headers)
    flask_response = create_flask_response(mock_response)
    process_cookies(mock_response, flask_response, target_host, proxy_host)
    
    # Assert
    final_headers = flask_response.get_wsgi_headers(None)
    print(f"Final headers: {dict(final_headers)}")
    
    # Count Set-Cookie headers
    set_cookie_count = sum(1 for name, _ in final_headers if name.lower() == 'set-cookie')
    print(f"Found {set_cookie_count} Set-Cookie headers")
    
    # Verify no example.com domains (shouldn't be any to rewrite)
    for header_name, header_value in final_headers:
        if header_name.lower() == 'set-cookie':
            if 'example.com' in header_value:
                raise AssertionError(f"Found example.com domain in: {header_value}")
    
    print("✅ SUCCESS: Cookies without domain handled correctly!")


def test_mixed_cookies():
    """Test handling a mix of cookies with and without domains"""
    print("=== Testing Mixed Cookies (with and without domains) ===")
    
    # Arrange
    target_host = "example.com"
    proxy_host = "test-ngrok.ngrok-free.app"
    cookie_headers = [
        "session=ABC123; Domain=example.com; Path=/; Secure",
        "user=DEF456; Path=/; HttpOnly",
        "pref=GHI789; Domain=example.com; Path=/; Max-Age=3600"
    ]
    
    # Act
    mock_response = create_mock_response(cookie_headers)
    flask_response = create_flask_response(mock_response)
    process_cookies(mock_response, flask_response, target_host, proxy_host)
    
    # Assert
    final_headers = flask_response.get_wsgi_headers(None)
    print(f"Final headers: {dict(final_headers)}")
    
    # Count Set-Cookie headers
    set_cookie_count = sum(1 for name, _ in final_headers if name.lower() == 'set-cookie')
    print(f"Found {set_cookie_count} Set-Cookie headers")
    
    # Verify no target domains exist and that cookies with domains have proxy domain
    for header_name, header_value in final_headers:
        if header_name.lower() == 'set-cookie':
            if target_host in header_value:
                raise AssertionError(f"Found {target_host} domain in: {header_value}")
            
            # Cookies with domains should have proxy domain, cookies without domains shouldn't have any domain
            if 'Domain=' in header_value:
                if proxy_host not in header_value:
                    raise AssertionError(f"Proxy domain not found in cookie with domain: {header_value}")
    
    print("✅ SUCCESS: Mixed cookies handled correctly!")


def test_cookies_with_subdomains():
    """Test handling cookies with subdomain domains"""
    print("=== Testing Cookies with Subdomains ===")
    
    # Arrange
    target_host = "example.com"
    proxy_host = "test-ngrok.ngrok-free.app"
    cookie_headers = [
        "session=ABC123; Domain=www.example.com; Path=/; Secure",
        "user=DEF456; Domain=.example.com; Path=/; HttpOnly"
    ]
    
    # Act
    mock_response = create_mock_response(cookie_headers)
    flask_response = create_flask_response(mock_response)
    process_cookies(mock_response, flask_response, target_host, proxy_host)
    
    # Assert
    final_headers = flask_response.get_wsgi_headers(None)
    print(f"Final headers: {dict(final_headers)}")
    
    # Count Set-Cookie headers
    set_cookie_count = sum(1 for name, _ in final_headers if name.lower() == 'set-cookie')
    print(f"Found {set_cookie_count} Set-Cookie headers")
    
    # Verify all domains were rewritten
    for header_name, header_value in final_headers:
        if header_name.lower() == 'set-cookie':
            if 'example.com' in header_value:
                raise AssertionError(f"Found example.com domain in: {header_value}")
            if proxy_host not in header_value:
                raise AssertionError(f"Proxy domain not found in: {header_value}")
    
    print("✅ SUCCESS: Cookies with subdomains rewritten correctly!")


if __name__ == "__main__":
    print("🧪 Running Server Flow Tests with Simple Examples")
    print("=" * 50)
    
    try:
        test_single_cookie_header()
        print()
        
        test_multiple_cookies_in_one_header()
        print()
        
        test_multiple_set_cookie_headers()
        print()
        
        test_cookies_without_domain()
        print()
        
        test_mixed_cookies()
        print()
        
        test_cookies_with_subdomains()
        print()
        
        print("🎉 All tests passed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        raise 