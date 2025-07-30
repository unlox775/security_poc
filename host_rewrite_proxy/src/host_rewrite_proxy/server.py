import requests
import json
import time
import sys
from flask import Flask, request, Response
from .reverse_proxy import ReverseProxy

class HostRewriteServer:
    def __init__(self, target_host: str, proxy_host: str, port: int = 5002):
        self.target_host = target_host
        self.proxy_host = proxy_host
        self.port = port
        self.reverse_proxy = ReverseProxy(target_host, proxy_host)
        self.app = Flask(__name__)
        self._setup_routes()
    
    def _setup_routes(self):
        @self.app.route('/', defaults={'path': ''})
        @self.app.route('/<path:path>')
        def proxy_request(path):
            # Get request data
            data = request.get_data()
            query_string = request.query_string.decode() if request.query_string else None
            
            # Process the request through the reverse proxy
            content, status_code, response_headers, original_headers = self.reverse_proxy.process_request(
                request.method, path, dict(request.headers), data, query_string
            )
            
            # Create Flask response with non-cookie headers
            flask_response = Response(
                content,
                status=status_code,
                headers=response_headers
            )
            
            # Process cookies from the original response
            self.reverse_proxy.process_cookies(original_headers, flask_response)
            
            # Remove CORS headers that might interfere
            flask_response.headers.pop('Access-Control-Allow-Origin', None)
            flask_response.headers.pop('Access-Control-Allow-Methods', None)
            flask_response.headers.pop('Access-Control-Allow-Headers', None)
            
            return flask_response
    
    def run(self):
        """Start the Flask server"""
        self.app.run(host='0.0.0.0', port=self.port, debug=False)

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
