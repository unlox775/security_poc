#!/usr/bin/env python3

import re
from datetime import datetime
from typing import List, Dict, Any

from . import bug

class CookieRewriter:
    """Handles rewriting of cookie domains in proxy responses"""
    
    def __init__(self, target_host: str, proxy_host: str):
        self.target_host = target_host
        self.proxy_host = proxy_host
        
    def parse_cookie_string(self, cookie_string: str) -> Dict[str, Any]:
        """Parse a single cookie string into its components"""
        if '=' not in cookie_string:
            return {}
            
        parts = cookie_string.split(';')
        name_value = parts[0].strip()
        
        if '=' not in name_value:
            return {}
            
        name, value = name_value.split('=', 1)
        attrs = {}
        
        for part in parts[1:]:
            part = part.strip()
            if '=' in part:
                attr_name, attr_value = part.split('=', 1)
                attrs[attr_name.lower()] = attr_value.strip()
            else:
                attrs[part.lower()] = True
                
        return {
            'name': name.strip(),
            'value': value.strip(),
            'attrs': attrs
        }
    
    def should_rewrite_domain(self, domain: str) -> bool:
        """Check if a domain should be rewritten"""
        if not domain:
            return False
            
        domain = domain.lower()
        target_variations = [
            self.target_host.lower(),
            f'.{self.target_host.lower()}',
            f'www.{self.target_host.lower()}',
            f'.www.{self.target_host.lower()}'
        ]
        
        return domain in target_variations
    
    def rewrite_cookie_domain(self, cookie_data: Dict[str, Any]) -> Dict[str, Any]:
        """Rewrite the domain in a cookie if needed"""
        attrs = cookie_data.get('attrs', {})
        domain = attrs.get('domain')
        
        # If the cookie has a domain that should be rewritten, rewrite it
        if self.should_rewrite_domain(domain):
            attrs['domain'] = self.proxy_host
            cookie_data['attrs'] = attrs
        # Note: Cookies without a domain are left as-is (no domain attribute)
            
        return cookie_data
    
    def cookie_to_string(self, cookie_data: Dict[str, Any]) -> str:
        """Convert cookie data back to a string"""
        if not cookie_data:
            return ''
            
        name = cookie_data.get('name', '')
        value = cookie_data.get('value', '')
        attrs = cookie_data.get('attrs', {})
        
        result = f"{name}={value}"
        
        # Add attributes in a consistent order
        if 'path' in attrs:
            result += f"; Path={attrs['path']}"
        if 'domain' in attrs:
            result += f"; Domain={attrs['domain']}"
        if 'expires' in attrs:
            result += f"; Expires={attrs['expires']}"
        if 'max-age' in attrs:
            result += f"; Max-Age={attrs['max-age']}"
        if attrs.get('secure'):
            result += "; Secure"
        if attrs.get('httponly'):
            result += "; HttpOnly"
        if 'samesite' in attrs:
            result += f"; SameSite={attrs['samesite']}"
            
        return result
    
    def rewrite_cookies(self, cookie_headers: List[str]) -> List[str]:
        """Rewrite all cookies in a list of cookie headers"""
        rewritten_cookies = []
        
        for header in cookie_headers:
            # Split multiple cookies in one header
            # Use a more sophisticated approach to handle commas in dates
            individual_cookies = self._split_cookies(header)
            
            for cookie in individual_cookies:
                cookie_data = self.parse_cookie_string(cookie)
                if cookie_data:
                    rewritten_data = self.rewrite_cookie_domain(cookie_data)
                    rewritten_string = self.cookie_to_string(rewritten_data)
                    if rewritten_string:
                        rewritten_cookies.append(rewritten_string)
                        
        return rewritten_cookies
    
    #     def _split_cookies(self, cookie_header: str) -> List[str]:
    #         """Split a cookie header into individual cookies, handling commas in dates"""
    #         # Use regex to split on ", " followed by a cookie name pattern
    #         import re
    #         # Split on ", " that is followed by a pattern like "NAME=value"
    #         pattern = r', (?=[A-Za-z_][A-Za-z0-9_]*=)'
    #         cookies = re.split(pattern, cookie_header)
    #         return [cookie.strip() for cookie in cookies if cookie.strip()]
    
    def get_cookie_attrs_for_flask(self, cookie_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert cookie data to Flask set_cookie parameters"""
        attrs = cookie_data.get('attrs', {})
        
        # Handle max-age conversion
        max_age = attrs.get('max-age')
        if max_age and str(max_age).isdigit():
            max_age = int(max_age)
        else:
            max_age = None
            
        # Handle expires conversion
        expires = attrs.get('expires')
        if expires and not max_age:
            try:
                for fmt in ['%a, %d-%b-%Y %H:%M:%S GMT', '%a, %d %b %Y %H:%M:%S GMT']:
                    try:
                        expires_dt = datetime.strptime(expires, fmt)
                        max_age = int((expires_dt - datetime.now()).total_seconds())
                        break
                    except ValueError:
                        continue
            except:
                pass
                
        return {
            'domain': attrs.get('domain', self.proxy_host),
            'path': attrs.get('path', '/'),
            'secure': attrs.get('secure', False),
            'httponly': attrs.get('httponly', False),
            'samesite': attrs.get('samesite', None),
            'max_age': max_age
        } 

    def rewrite_cookies_and_set_on_response(self, response_headers, flask_response):
        """
        Rewrite all cookies from response headers and set them on the Flask response.
        
        Args:
            response_headers: Headers from the upstream response
            flask_response: Flask Response object to set cookies on
        """
        # Handle case-sensitive header matching
        set_cookie_key = None
        for key in response_headers.keys():
            if key.lower() == 'set-cookie':
                set_cookie_key = key
                break
        
        if not set_cookie_key:
            return
            
        # Get original cookies - prefer using get_all if available to preserve multiple headers
        original_cookies = []
        for key, value in response_headers.items():
            if key.lower() == 'set-cookie':
                if isinstance(value, list):
                    original_cookies.extend(value)
                else:
                    original_cookies.append(value)
        
        # Rewrite all cookies
        rewritten_cookies = self.rewrite_cookies(original_cookies)
        bug(original_cookies)
        bug(rewritten_cookies)
        
        # Set each rewritten cookie on the Flask response
        for cookie_string in rewritten_cookies:
            self._set_cookie_from_string(flask_response, cookie_string)
    
    def _set_cookie_from_string(self, flask_response, cookie_string):
        """Set the Set-Cookie header directly to preserve original formatting (including quoted values and commas)."""
        if '=' not in cookie_string:
            return
        flask_response.headers.add('Set-Cookie', cookie_string)
    
    def _split_cookies(self, cookie_header) -> List[str]:
        """Split a cookie header into individual cookies, handling commas in dates"""
        # Handle case where cookie_header is already a list
        if isinstance(cookie_header, list):
            return cookie_header
        
        # Handle case where cookie_header is a single string (possibly concatenated)
        if isinstance(cookie_header, str):
            # Use a proper Set-Cookie parser that handles commas in values
            return self._parse_set_cookie_header(cookie_header)
        
        return []
    
    def _parse_set_cookie_header(self, header_string: str) -> List[str]:
        """Parse a Set-Cookie header string that may contain multiple cookies"""
        cookies = []
        current_cookie = ""
        in_quotes = False
        i = 0
        
        while i < len(header_string):
            char = header_string[i]
            
            if char == '"':
                in_quotes = not in_quotes
                current_cookie += char
            elif char == ',' and not in_quotes:
                # Check if this comma is followed by a cookie name pattern
                # Look ahead to see if we have "NAME=value" pattern
                next_part = header_string[i+1:].strip()
                if self._looks_like_cookie_start(next_part):
                    # This is a cookie separator
                    if current_cookie.strip():
                        cookies.append(current_cookie.strip())
                    current_cookie = ""
                else:
                    # This comma is part of a value (like in a date)
                    current_cookie += char
            else:
                current_cookie += char
            
            i += 1
        
        # Add the last cookie
        if current_cookie.strip():
            cookies.append(current_cookie.strip())
        
        return cookies
    
    def _looks_like_cookie_start(self, text: str) -> bool:
        """Check if text looks like the start of a new cookie (NAME=value pattern)"""
        # Remove leading whitespace
        text = text.strip()
        
        # Look for pattern like "NAME=value" or "NAME="
        # Cookie names are typically alphanumeric with some special chars
        import re
        pattern = r'^[A-Za-z_][A-Za-z0-9_-]*='
        return bool(re.match(pattern, text))
