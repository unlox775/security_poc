#!/usr/bin/env python3

import argparse
import requests
from flask import Flask, request, Response
import re
from urllib.parse import urljoin, urlparse
import json
import time
import sys
from datetime import datetime
from cookie_rewriter import CookieRewriter

def get_ngrok_url():
    """Get the ngrok public URL from the ngrok API"""
    ngrok_api = 'http://127.0.0.1:4040/api/tunnels'
    retries = 10
    wait_seconds = 2

    for _ in range(retries):
        try:
            response = requests.get(ngrok_api)
            tunnels = json.loads(response.text).get('tunnels', [])
            for tunnel in tunnels:
                if tunnel['proto'] == 'https':
                    return tunnel['public_url']
        except requests.ConnectionError:
            pass
        time.sleep(wait_seconds)

    print("Failed to retrieve ngrok URL.")
    print("Please start ngrok first: ngrok http 5002")
    sys.exit(1)

def rewrite_urls_in_content(content, original_host, proxy_host):
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
    
    return content



def main():
    parser = argparse.ArgumentParser(description='Host Rewrite Proxy')
    parser.add_argument('target_host', help='Target hostname to proxy to (e.g., example.com)')
    parser.add_argument('--port', type=int, default=5002, help='Port to run the proxy on (default: 5002)')
    args = parser.parse_args()

    target_host = args.target_host
    proxy_port = args.port
    
    # Get ngrok URL for the proxy
    proxy_host = get_ngrok_url().replace('https://', '')
    print(f"Ngrok URL: https://{proxy_host}")
    print(f"Proxying requests to: {target_host}")
    print(f"Proxy running on port: {proxy_port}")
    print(f"Add to /etc/hosts: 127.0.0.1 {proxy_host}")
    print("=" * 50)

    app = Flask(__name__)

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def proxy_request(path):
        # Construct the target URL
        target_url = f"https://{target_host}/{path}"
        if request.query_string:
            target_url += f"?{request.query_string.decode()}"
        
        # Prepare headers for the target request
        headers = dict(request.headers)
        
        # Rewrite the Host header to the target host
        headers['Host'] = target_host
        
        # Remove headers that shouldn't be forwarded
        headers.pop('Content-Length', None)
        headers.pop('Transfer-Encoding', None)
        
        # Get request data
        data = request.get_data()
        
        try:
            # Make the request to the target
            response = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=data,
                stream=True,
                verify=True,
                allow_redirects=False
            )
            
            # Get response content
            content = response.content
            
            # Rewrite URLs in the response content
            if response.headers.get('content-type', '').startswith(('text/html', 'text/css', 'application/javascript')):
                content = rewrite_urls_in_content(content, target_host, proxy_host)
            
            # Prepare headers for Flask response (excluding all set-cookie headers)
            flask_headers = {}
            for key, value in response.headers.items():
                if key.lower() != 'set-cookie':
                    flask_headers[key] = value
            print(f"Flask headers (without cookies): {flask_headers}")
            
            # Create Flask response with non-cookie headers
            flask_response = Response(
                content,
                status=response.status_code,
                headers=flask_headers
            )
            
            # Initialize cookie rewriter and handle all cookie logic
            cookie_rewriter = CookieRewriter(target_host, proxy_host)
            cookie_rewriter.rewrite_cookies_and_set_on_response(response.headers, flask_response)
            
            # Remove CORS headers that might interfere
            flask_response.headers.pop('Access-Control-Allow-Origin', None)
            flask_response.headers.pop('Access-Control-Allow-Methods', None)
            flask_response.headers.pop('Access-Control-Allow-Headers', None)
            
            print(f"{request.method} {request.path} -> {response.status_code} ({len(content)} bytes)")
            sys.stdout.flush()
            
            return flask_response
            
        except Exception as e:
            print(f"Error proxying request: {str(e)}")
            return f"Proxy error: {str(e)}", 500

    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=proxy_port, debug=False)

if __name__ == '__main__':
    main() 