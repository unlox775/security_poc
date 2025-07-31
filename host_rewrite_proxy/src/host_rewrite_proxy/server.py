import requests
import json
import time
import sys
from quart import Quart, request, Response
from .proxy_request import ProxyRequest
from .proxy_response import ProxyResponse
import asyncio

class HostRewriteServer:
    def __init__(self, target_host: str, proxy_host: str, port: int = 5002):
        self.target_host = target_host
        self.proxy_host = proxy_host
        self.port = port
        # Quart application for async request handling
        self.app = Quart(__name__)
        self._setup_routes()
    
    def _setup_routes(self):
        @self.app.route('/', defaults={'path': ''})
        @self.app.route('/<path:path>')
        async def proxy_request(path):
            print(f"DEBUG: proxy_request: {path}")  
            # Parse incoming request into ProxyRequest (async via Quart)
            proxy_req = await ProxyRequest.from_quart(request)
            proxy_req.translate(self.target_host)
            # Build target URL
            target_url = f"https://{self.target_host}/{path}"
            print(f"DEBUG: target_url: {target_url}")
            if proxy_req.query_string:
                target_url += f"?{proxy_req.query_string}"
            print(f"DEBUG: target_url: {target_url}")
            # Forward request to upstream server
            resp = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: requests.request(
                    method=proxy_req.method,
                    url=target_url,
                    headers=dict(proxy_req.headers),
                    data=proxy_req.body_stream,
                    stream=True,
                    verify=True,
                    allow_redirects=False
                )
            )
            print(f"DEBUG: resp: {resp}")

            # Wrap and translate response
            px_resp = ProxyResponse.from_requests(resp)
            print(f"DEBUG: px_resp: {px_resp}")
            px_resp.translate_headers(self.target_host, self.proxy_host)
            print(f"DEBUG: px_resp: {px_resp}")
            # Stream translated content back to client
            return Response(
                px_resp.translate_content(self.target_host, self.proxy_host),
                status=px_resp.status_code,
                headers=px_resp.headers
            )
    
    def run(self):
        """Serve the Quart app via built-in async run"""
        # Quart's run will start the ASGI server
        self.app.run(host='0.0.0.0', port=self.port, debug=True)

def get_ngrok_url():
    """Get the ngrok public URL from the ngrok API"""
    ngrok_api = 'http://127.0.0.1:4040/api/tunnels'
    retries = 10
    wait_seconds = 2

    print("Getting ngrok URL...")
    for _ in range(retries):
        try:
            response = requests.get(ngrok_api)
            tunnels = json.loads(response.text).get('tunnels', [])
            for tunnel in tunnels:
                if tunnel['proto'] == 'https':
                    return tunnel['public_url']
        except requests.ConnectionError:
            pass
        print(f"Retrying ngrok URL retrieval... {_ + 1}/{retries}")
        time.sleep(wait_seconds)

    print("Failed to retrieve ngrok URL.")
    print("Please start ngrok first: ngrok http 5002")
    sys.exit(1)
