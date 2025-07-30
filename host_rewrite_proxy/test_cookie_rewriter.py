#!/usr/bin/env python3
"""
Unit tests for the CookieRewriter class with simple, readable examples.
"""

import unittest
from cookie_rewriter import CookieRewriter


class TestCookieRewriter(unittest.TestCase):
    
    def setUp(self):
        self.target_host = "example.com"
        self.proxy_host = "test-ngrok.ngrok-free.app"
        self.rewriter = CookieRewriter(self.target_host, self.proxy_host)
    
    def test_parse_simple_cookie(self):
        """Test parsing a simple cookie string"""
        # Arrange
        cookie_string = "session=ABC123; Domain=example.com; Path=/; Secure"
        
        # Act
        result = self.rewriter.parse_cookie_string(cookie_string)
        
        # Assert
        self.assertEqual(result['name'], 'session')
        self.assertEqual(result['value'], 'ABC123')
        self.assertEqual(result['attrs']['domain'], 'example.com')
        self.assertEqual(result['attrs']['path'], '/')
        self.assertTrue(result['attrs']['secure'])
    
    def test_parse_cookie_without_domain(self):
        """Test parsing a cookie without a domain attribute"""
        # Arrange
        cookie_string = "session=ABC123; Path=/; Secure"
        
        # Act
        result = self.rewriter.parse_cookie_string(cookie_string)
        
        # Assert
        self.assertEqual(result['name'], 'session')
        self.assertEqual(result['value'], 'ABC123')
        self.assertNotIn('domain', result['attrs'])
        self.assertEqual(result['attrs']['path'], '/')
        self.assertTrue(result['attrs']['secure'])
    
    def test_should_rewrite_domain(self):
        """Test domain rewriting logic"""
        # Arrange & Act & Assert
        # Should rewrite
        self.assertTrue(self.rewriter.should_rewrite_domain('example.com'))
        self.assertTrue(self.rewriter.should_rewrite_domain('.example.com'))
        self.assertTrue(self.rewriter.should_rewrite_domain('www.example.com'))
        
        # Should not rewrite
        self.assertFalse(self.rewriter.should_rewrite_domain('other.com'))
        self.assertFalse(self.rewriter.should_rewrite_domain('.other.com'))
        self.assertFalse(self.rewriter.should_rewrite_domain(None))
    
    def test_rewrite_cookie_domain(self):
        """Test rewriting a cookie's domain"""
        # Arrange
        cookie_data = {
            'name': 'session',
            'value': 'ABC123',
            'attrs': {
                'domain': 'example.com',
                'path': '/',
                'secure': True
            }
        }
        
        # Act
        result = self.rewriter.rewrite_cookie_domain(cookie_data)
        
        # Assert
        self.assertEqual(result['name'], 'session')
        self.assertEqual(result['value'], 'ABC123')
        self.assertEqual(result['attrs']['domain'], self.proxy_host)
        self.assertEqual(result['attrs']['path'], '/')
        self.assertTrue(result['attrs']['secure'])
    
    def test_rewrite_cookie_without_domain(self):
        """Test rewriting a cookie that has no domain attribute"""
        # Arrange
        cookie_data = {
            'name': 'session',
            'value': 'ABC123',
            'attrs': {
                'path': '/',
                'secure': True
            }
        }
        
        # Act
        result = self.rewriter.rewrite_cookie_domain(cookie_data)
        
        # Assert
        self.assertEqual(result['name'], 'session')
        self.assertEqual(result['value'], 'ABC123')
        self.assertNotIn('domain', result['attrs'])
        self.assertEqual(result['attrs']['path'], '/')
        self.assertTrue(result['attrs']['secure'])
    
    def test_cookie_to_string(self):
        """Test converting cookie data back to string"""
        # Arrange
        cookie_data = {
            'name': 'session',
            'value': 'ABC123',
            'attrs': {
                'domain': 'test-ngrok.ngrok-free.app',
                'path': '/',
                'secure': True,
                'httponly': True
            }
        }
        
        # Act
        result = self.rewriter.cookie_to_string(cookie_data)
        
        # Assert
        self.assertIn('session=ABC123', result)
        self.assertIn('Domain=test-ngrok.ngrok-free.app', result)
        self.assertIn('Path=/', result)
        self.assertIn('Secure', result)
        self.assertIn('HttpOnly', result)
    
    def test_rewrite_single_cookie(self):
        """Test rewriting a single cookie header"""
        # Arrange
        cookie_headers = ["session=ABC123; Domain=example.com; Path=/; Secure"]
        
        # Act
        result = self.rewriter.rewrite_cookies(cookie_headers)
        
        # Assert
        self.assertEqual(len(result), 1)
        self.assertIn('session=ABC123', result[0])
        self.assertIn(f'Domain={self.proxy_host}', result[0])
        self.assertNotIn('example.com', result[0])
    
    def test_rewrite_multiple_cookies_in_header(self):
        """Test rewriting multiple cookies in one header"""
        # Arrange
        cookie_headers = ["session=ABC123; Domain=example.com; Path=/; Secure, user=DEF456; Domain=example.com; Path=/; HttpOnly"]
        
        # Act
        result = self.rewriter.rewrite_cookies(cookie_headers)
        
        # Assert
        self.assertEqual(len(result), 2)
        self.assertIn('session=ABC123', result[0])
        self.assertIn(f'Domain={self.proxy_host}', result[0])
        self.assertIn('user=DEF456', result[1])
        self.assertIn(f'Domain={self.proxy_host}', result[1])
        
        # Verify no original domains remain
        for cookie in result:
            self.assertNotIn('example.com', cookie)
    
    def test_rewrite_multiple_headers(self):
        """Test rewriting multiple Set-Cookie headers"""
        # Arrange
        cookie_headers = [
            "session=ABC123; Domain=example.com; Path=/; Secure",
            "user=DEF456; Domain=example.com; Path=/; HttpOnly"
        ]
        
        # Act
        result = self.rewriter.rewrite_cookies(cookie_headers)
        
        # Assert
        self.assertEqual(len(result), 2)
        self.assertIn('session=ABC123', result[0])
        self.assertIn(f'Domain={self.proxy_host}', result[0])
        self.assertIn('user=DEF456', result[1])
        self.assertIn(f'Domain={self.proxy_host}', result[1])
        
        # Verify no original domains remain
        for cookie in result:
            self.assertNotIn('example.com', cookie)
    
    def test_rewrite_cookies_without_domains(self):
        """Test rewriting cookies without domain attributes"""
        # Arrange
        cookie_headers = [
            "session=ABC123; Path=/; Secure",
            "user=DEF456; Path=/; HttpOnly"
        ]
        
        # Act
        result = self.rewriter.rewrite_cookies(cookie_headers)
        
        # Assert
        self.assertEqual(len(result), 2)
        # Cookies without domains should not have any domain attribute
        for cookie in result:
            self.assertNotIn('Domain=', cookie)
            self.assertNotIn('example.com', cookie)
    
    def test_split_cookies(self):
        """Test splitting multiple cookies in one header"""
        # Arrange
        cookie_header = "session=ABC123; Domain=example.com; Path=/; Secure, user=DEF456; Domain=example.com; Path=/; HttpOnly"
        
        # Act
        result = self.rewriter._split_cookies(cookie_header)
        
        # Assert
        self.assertEqual(len(result), 2)
        self.assertIn('session=ABC123', result[0])
        self.assertIn('user=DEF456', result[1])
    
    def test_split_cookies_with_commas_in_dates(self):
        """Test splitting cookies when dates contain commas"""
        # Arrange
        cookie_header = "session=ABC123; Domain=example.com; Expires=Wed, 30-Jul-2025 00:07:41 GMT; Path=/; Secure, user=DEF456; Domain=example.com; Path=/; HttpOnly"
        
        # Act
        result = self.rewriter._split_cookies(cookie_header)
        
        # Assert
        self.assertEqual(len(result), 2)
        self.assertIn('session=ABC123', result[0])
        self.assertIn('user=DEF456', result[1])
        # Verify the date wasn't split
        self.assertIn('Wed, 30-Jul-2025 00:07:41 GMT', result[0])


if __name__ == '__main__':
    unittest.main() 