import requests
import re
import sys
from typing import Dict, Any
from .cookie_rewriter import CookieRewriter

class ReverseProxy:
    def __init__(self, target_host: str, proxy_host: str):
        self.target_host = target_host
        self.proxy_host = proxy_host
        self.cookie_rewriter = CookieRewriter(target_host, proxy_host)
    
    def rewrite_urls_in_content(self, content: bytes, original_host: str, proxy_host: str) -> bytes:
        """Rewrite URLs in HTML/CSS/JS content to use the proxy host"""
        if not content:
            return content
        
        # Convert to string if it's bytes
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        
        # Rewrite absolute URLs
        content = re.sub(
            rf'https?://{re.escape(original_host)}',
            f'https://{proxy_host}',
            content,
            flags=re.IGNORECASE
        )
        
        # Rewrite protocol-relative URLs
        content = re.sub(
            rf'//{re.escape(original_host)}',
            f'//{proxy_host}',
            content,
            flags=re.IGNORECASE
        )
        
        return content.encode('utf-8') if isinstance(content, str) else content
    
    def process_request(self, request_method: str, request_path: str, request_headers: Dict[str, str], 
                       request_data: bytes, query_string: str = None) -> tuple[bytes, int, Dict[str, str]]:
        """
        Process an incoming request and return the response.
        
        Returns:
            tuple: (content, status_code, headers)
        """
        # Construct the target URL
        target_url = f"https://{self.target_host}/{request_path}"
        if query_string:
            target_url += f"?{query_string}"
        
        # Prepare headers for the target request
        headers = dict(request_headers)
        
        # Rewrite the Host header to the target host
        headers['Host'] = self.target_host
        
        # Remove headers that shouldn't be forwarded
        headers.pop('Content-Length', None)
        headers.pop('Transfer-Encoding', None)
        
        try:
            # Make the request to the target
            response = requests.request(
                method=request_method,
                url=target_url,
                headers=headers,
                data=request_data,
                stream=True,
                verify=True,
                allow_redirects=False
            )
            
            # Get response content
            content = response.content
            
            # Rewrite URLs in the response content
            if response.headers.get('content-type', '').startswith(('text/html', 'text/css', 'application/javascript')):
                content = self.rewrite_urls_in_content(content, self.target_host, self.proxy_host)
            
            # Prepare headers for response (excluding set-cookie)
            response_headers = {}
            for key, value in response.headers.items():
                if key.lower() != 'set-cookie':
                    response_headers[key] = value
            
            print(f"{request_method} {request_path} -> {response.status_code} ({len(content)} bytes)")
            sys.stdout.flush()
            
            return content, response.status_code, response_headers, response.raw.headers
            
        except Exception as e:
            print(f"Error proxying request: {str(e)}")
            return f"Proxy error: {str(e)}".encode('utf-8'), 500, {}
    
    def process_cookies(self, response_headers, flask_response):
        """Process cookies from the response and set them on the Flask response"""
        self.cookie_rewriter.rewrite_cookies_and_set_on_response(response_headers, flask_response)
