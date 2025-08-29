#!/usr/bin/env python3
"""
Iframe Sandbox Security Tester

A Flask application to test different iframe sandbox configurations
and demonstrate their security implications.
"""

from flask import Flask, send_from_directory, render_template_string
import time
import os

app = Flask(__name__)

# Configuration
SECRET_COOKIE_VALUE = "super-secret-cookie-value-12345"

@app.route('/')
def parent_page():
    """Serve the parent page"""
    import time
    cache_buster = int(time.time())
    with open('parent.html', 'r') as f:
        content = f.read()
    # Replace the cache buster in the script tag
    content = content.replace('/parent.js?v=1', f'/parent.js?v={cache_buster}')
    from flask import Response
    response = Response(content, mimetype='text/html')
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/iframe-test')
def iframe_test():
    """Serve the iframe test page"""
    import time
    cache_buster = int(time.time())
    with open('iframe-test.html', 'r') as f:
        content = f.read()
    # Replace the cache buster in the script tag
    content = content.replace('/iframe-test.js?v=1', f'/iframe-test.js?v={cache_buster}')
    from flask import Response
    response = Response(content, mimetype='text/html')
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/parent.js')
def parent_js():
    """Serve the parent JavaScript file"""
    from flask import Response
    with open('parent.js', 'r') as f:
        content = f.read()
    response = Response(content, mimetype='application/javascript')
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/iframe-test.js')
def iframe_test_js():
    """Serve the iframe test JavaScript file"""
    from flask import Response
    with open('iframe-test.js', 'r') as f:
        content = f.read()
    response = Response(content, mimetype='application/javascript')
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Iframe Sandbox Security Tester')
    parser.add_argument('--port', type=int, default=8080, help='Port to run server on')
    
    args = parser.parse_args()
    
    print("=== Iframe Sandbox Security Tester ===")
    print(f"Parent site: http://parent-site.local:{args.port}")
    print(f"Child site: http://child-site.local:{args.port}")
    print("\nTo setup hosts file: make setup")
    print("To cleanup hosts file: make cleanup")
    print("\nStarting server...")
    
    app.run(host='0.0.0.0', port=args.port, debug=True)
