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

        # At least go down, don't remove the top level domain, the .com or whatever is at the end. Don't remove that, but go to at least one step of that one, because a lot of times people will go up several domains for cookie domains, and do like dot  that domain.
        # E.g for foo.bar.baz.com, check foo.bar.baz.com, bar.baz.com, baz.com, but NOT .com
        # Then we will add a . to each variation, and even add a www to just the original one, and then check all of those.
        domains_needing_rewrite = [
            self.target_host,
            f'.{self.target_host}',
            f'www.{self.target_host}',
            f'.www.{self.target_host}'
        ]
        # Add parent domains (but not top-level domains like .com)
        # For example.com, also match example.com, but NOT .com
        chop_domain = self.target_host
        while chop_domain.count('.') > 1:  # Stop before we get to top-level domain
            chop_domain = chop_domain.split('.', 1)[1]
            domains_needing_rewrite.append(chop_domain)
            domains_needing_rewrite.append(f'.{chop_domain}')

        # Check exact matches first
        if domain in domains_needing_rewrite:
            return True
            
        # Check if it's a subdomain of the target host
        # For example.com, also match api.example.com, sub.example.com, etc.
        if domain.endswith(f'.{self.target_host}'):
            return True

        return False
    
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
        """Rewrite each Set-Cookie header value directly without splitting."""
        rewritten = []
        for header in cookie_headers:
            # bug(header)
            data = self.parse_cookie_string(header)
            if not data:
                continue
            data = self.rewrite_cookie_domain(data)
            cookie_str = self.cookie_to_string(data)
            if cookie_str:
                rewritten.append(cookie_str)
        return rewritten

