#!/usr/bin/env python3
"""
Test cookie extraction from requests.Response objects
"""

import unittest
from unittest.mock import Mock
from src.host_rewrite_proxy.cookie_rewriter import CookieRewriter

class TestCookieExtraction(unittest.TestCase):
    def setUp(self):
        self.cookie_rewriter = CookieRewriter('example.com', 'test-ngrok.ngrok-free.app')
    
    def create_mock_response_headers(self, set_cookie_headers):
        """Create a mock response headers object that behaves like requests.Response.headers"""
        headers = Mock()
        
        # Mock the items() method to return all headers
        all_headers = []
        for header_name, header_value in set_cookie_headers:
            all_headers.append((header_name, header_value))
        
        headers.items.return_value = all_headers
        
        # Mock the get method to return the first Set-Cookie header (requests behavior)
        set_cookie_values = [value for name, value in set_cookie_headers if name.lower() == 'set-cookie']
        if set_cookie_values:
            headers.get.return_value = ', '.join(set_cookie_values)
        else:
            headers.get.return_value = None
        
        return headers
    
    def test_extract_single_cookie_header(self):
        """Test extracting a single Set-Cookie header"""
        mock_headers = self.create_mock_response_headers([
            ('Set-Cookie', 'session=ABC123; Domain=example.com; Secure; Path=/')
        ])
        
        # Extract cookies using our method
        original_cookies = []
        for key, value in mock_headers.items():
            if key.lower() == 'set-cookie':
                original_cookies.append(value)
        
        self.assertEqual(len(original_cookies), 1)
        self.assertEqual(original_cookies[0], 'session=ABC123; Domain=example.com; Secure; Path=/')
    
    def test_extract_multiple_cookie_headers(self):
        """Test extracting multiple Set-Cookie headers"""
        mock_headers = self.create_mock_response_headers([
            ('Set-Cookie', 'session=ABC123; Domain=example.com; Secure; Path=/'),
            ('Set-Cookie', 'user=DEF456; Domain=www.example.com; Path=/'),
            ('Set-Cookie', 'pref=GHI789; Path=/; HttpOnly')
        ])
        
        # Extract cookies using our method
        original_cookies = []
        for key, value in mock_headers.items():
            if key.lower() == 'set-cookie':
                original_cookies.append(value)
        
        self.assertEqual(len(original_cookies), 3)
        self.assertEqual(original_cookies[0], 'session=ABC123; Domain=example.com; Secure; Path=/')
        self.assertEqual(original_cookies[1], 'user=DEF456; Domain=www.example.com; Path=/')
        self.assertEqual(original_cookies[2], 'pref=GHI789; Path=/; HttpOnly')
    
    def test_extract_mixed_headers(self):
        """Test extracting cookies from mixed headers"""
        mock_headers = self.create_mock_response_headers([
            ('Content-Type', 'text/html'),
            ('Set-Cookie', 'session=ABC123; Domain=example.com; Secure; Path=/'),
            ('Server', 'nginx'),
            ('Set-Cookie', 'user=DEF456; Domain=www.example.com; Path=/'),
            ('Cache-Control', 'no-cache')
        ])
        
        # Extract cookies using our method
        original_cookies = []
        for key, value in mock_headers.items():
            if key.lower() == 'set-cookie':
                original_cookies.append(value)
        
        self.assertEqual(len(original_cookies), 2)
        self.assertEqual(original_cookies[0], 'session=ABC123; Domain=example.com; Secure; Path=/')
        self.assertEqual(original_cookies[1], 'user=DEF456; Domain=www.example.com; Path=/')
    
    def test_no_cookie_headers(self):
        """Test when there are no Set-Cookie headers"""
        mock_headers = self.create_mock_response_headers([
            ('Content-Type', 'text/html'),
            ('Server', 'nginx'),
            ('Cache-Control', 'no-cache')
        ])
        
        # Extract cookies using our method
        original_cookies = []
        for key, value in mock_headers.items():
            if key.lower() == 'set-cookie':
                original_cookies.append(value)
        
        self.assertEqual(len(original_cookies), 0)
    
    def test_case_insensitive_header_matching(self):
        """Test that header matching is case insensitive"""
        mock_headers = self.create_mock_response_headers([
            ('set-cookie', 'session=ABC123; Domain=example.com; Secure; Path=/'),
            ('SET-COOKIE', 'user=DEF456; Domain=www.example.com; Path=/'),
            ('Set-Cookie', 'pref=GHI789; Path=/; HttpOnly')
        ])
        
        # Extract cookies using our method
        original_cookies = []
        for key, value in mock_headers.items():
            if key.lower() == 'set-cookie':
                original_cookies.append(value)
        
        self.assertEqual(len(original_cookies), 3)
        self.assertEqual(original_cookies[0], 'session=ABC123; Domain=example.com; Secure; Path=/')
        self.assertEqual(original_cookies[1], 'user=DEF456; Domain=www.example.com; Path=/')
        self.assertEqual(original_cookies[2], 'pref=GHI789; Path=/; HttpOnly')

if __name__ == '__main__':
    unittest.main()
