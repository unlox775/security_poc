import re
from datetime import datetime
from typing import Dict, Any, List

class CookieRewriter:
    def __init__(self, target_host: str, proxy_host: str):
        self.target_host = target_host
        self.proxy_host = proxy_host

    def parse_cookie_string(self, cookie_string: str) -> Dict[str, Any]:
        """Parse a cookie string into its components"""
        if '=' not in cookie_string:
            return None
            
        # Split on first '=' to separate name/value from attributes
        name_value, attrs_part = cookie_string.split('=', 1)
        name = name_value.strip()
        
        # Find the value (everything up to the first semicolon)
        if ';' in attrs_part:
            value, attrs_part = attrs_part.split(';', 1)
        else:
            value = attrs_part
            attrs_part = ''
            
        value = value.strip()
        
        # Parse attributes
        attrs = {}
        if attrs_part:
            # Split on semicolons, but be careful with dates that contain commas
            attr_parts = self._split_attrs(attrs_part)
            for part in attr_parts:
                part = part.strip()
                if '=' in part:
                    attr_name, attr_value = part.split('=', 1)
                    attrs[attr_name.strip().lower()] = attr_value.strip()
                else:
                    attrs[part.lower()] = True
                    
        return {
            'name': name,
            'value': value,
            'attrs': attrs
        }
    
    def _split_attrs(self, attrs_part: str) -> List[str]:
        """Split attributes, being careful with dates that contain commas"""
        parts = []
        current_part = ""
        paren_count = 0
        
        for char in attrs_part:
            if char == '(':
                paren_count += 1
            elif char == ')':
                paren_count -= 1
            elif char == ';' and paren_count == 0:
                if current_part.strip():
                    parts.append(current_part.strip())
                current_part = ""
                continue
            current_part += char
            
        if current_part.strip():
            parts.append(current_part.strip())
            
        return parts

    def should_rewrite_domain(self, domain: str) -> bool:
        """Check if a domain should be rewritten"""
        if not domain:
            return False
            
        # Remove leading dot for comparison
        clean_domain = domain.lstrip('.')
        clean_target = self.target_host.lstrip('.')
        
        # Check if domain matches target host or is a subdomain
        return (clean_domain == clean_target or 
                clean_domain.endswith('.' + clean_target))

    def rewrite_cookie_domain(self, cookie_data: Dict[str, Any]) -> Dict[str, Any]:
        """Rewrite the domain of a cookie if needed"""
        if not cookie_data:
            return cookie_data
            
        attrs = cookie_data.get('attrs', {})
        domain = attrs.get('domain')
        
        if domain and self.should_rewrite_domain(domain):
            attrs['domain'] = self.proxy_host
            
        return cookie_data

    def cookie_to_string(self, cookie_data: Dict[str, Any]) -> str:
        """Convert cookie data back to a string"""
        if not cookie_data:
            return ""
            
        name = cookie_data.get('name', '')
        value = cookie_data.get('value', '')
        attrs = cookie_data.get('attrs', {})
        
        result = f"{name}={value}"
        
        # Add attributes in a consistent order
        attr_order = ['domain', 'path', 'expires', 'max-age', 'secure', 'httponly', 'samesite']
        
        for attr_name in attr_order:
            if attr_name in attrs:
                attr_value = attrs[attr_name]
                if attr_value is True:
                    result += f"; {attr_name.title()}"
                else:
                    result += f"; {attr_name.title()}={attr_value}"
                    
        # Add any remaining attributes
        for attr_name, attr_value in attrs.items():
            if attr_name not in attr_order:
                if attr_value is True:
                    result += f"; {attr_name.title()}"
                else:
                    result += f"; {attr_name.title()}={attr_value}"
                    
        return result

    def rewrite_cookies(self, cookie_headers: List[str]) -> List[str]:
        """Rewrite a list of cookie header strings"""
        rewritten_cookies = []
        
        for header in cookie_headers:
            # Split multiple cookies in one header
            individual_cookies = self._split_cookies(header)
            
            for cookie in individual_cookies:
                # Parse the cookie
                cookie_data = self.parse_cookie_string(cookie)
                if not cookie_data:
                    continue
                    
                # Rewrite the domain
                rewritten_data = self.rewrite_cookie_domain(cookie_data)
                
                # Convert back to string
                rewritten_cookie = self.cookie_to_string(rewritten_data)
                rewritten_cookies.append(rewritten_cookie)
                
        return rewritten_cookies
    
    def _split_cookies(self, cookie_header: str) -> List[str]:
        """Split multiple cookies in one header string"""
        # This is a simple split for now - we'll need more sophisticated logic
        # for cookies that contain commas in their values
        return [cookie.strip() for cookie in cookie_header.split(',')]

    def get_cookie_attrs_for_flask(self, cookie_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert cookie attributes to Flask-compatible format"""
        if not cookie_data:
            return {}
            
        attrs = cookie_data.get('attrs', {})
        
        # Convert max-age to integer
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
        if 'set-cookie' not in response_headers:
            return
            
        # Get original cookies - extract all Set-Cookie headers properly
        original_cookies = []
        for key, value in response_headers.items():
            if key.lower() == 'set-cookie':
                original_cookies.append(value)
        
        # Rewrite all cookies
        rewritten_cookies = self.rewrite_cookies(original_cookies)
        print(f"Original cookies: {original_cookies}")
        print(f"Rewritten cookies: {rewritten_cookies}")
        
        # Set each rewritten cookie on the Flask response
        for cookie_string in rewritten_cookies:
            self._set_cookie_from_string(flask_response, cookie_string)
    
    def _set_cookie_from_string(self, flask_response, cookie_string):
        """Parse a cookie string and set it on the Flask response"""
        if '=' not in cookie_string:
            return
            
        # Parse the cookie string using our existing parser
        cookie_data = self.parse_cookie_string(cookie_string)
        if not cookie_data:
            return
            
        # Rewrite the domain if needed
        rewritten_data = self.rewrite_cookie_domain(cookie_data)
        
        # Extract name and value
        name = rewritten_data.get('name', '').strip()
        value = rewritten_data.get('value', '').strip()
        
        # Get attributes for Flask
        attrs = rewritten_data.get('attrs', {})
        
        # Convert max-age if present
        max_age = attrs.get('max-age')
        if max_age and str(max_age).isdigit():
            attrs['max_age'] = int(max_age)
            attrs.pop('max-age', None)
        else:
            attrs.pop('max-age', None)
            
        # Handle expires conversion if no max-age
        expires = attrs.get('expires')
        if expires and 'max_age' not in attrs:
            try:
                for fmt in ['%a, %d-%b-%Y %H:%M:%S GMT', '%a, %d %b %Y %H:%M:%S GMT']:
                    try:
                        expires_dt = datetime.strptime(expires, fmt)
                        attrs['max_age'] = int((expires_dt - datetime.now()).total_seconds())
                        break
                    except ValueError:
                        continue
            except:
                pass
            attrs.pop('expires', None)
        
        # Set the cookie
        flask_response.set_cookie(name, value, **attrs) 