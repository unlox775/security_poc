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
            
            # Remove Content-Encoding and Content-Length headers since we're modifying content
            px_resp.headers = [(name, value) for name, value in px_resp.headers 
                              if name.lower() not in ['content-encoding', 'content-length']]
            
            # Create async generator for streaming content
            async def stream_content():
                try:
                    loop = asyncio.get_event_loop()
                    import re
                    import gzip
                    import io
                    
                    # Check if content is gzipped
                    is_gzipped = any(
                        name.lower() == 'content-encoding' and 'gzip' in value.lower()
                        for name, value in px_resp.headers
                    )
                    
                    # Compile patterns for URL rewriting
                    abs_pattern = re.compile(rf'https?://{re.escape(self.target_host)}', flags=re.IGNORECASE)
                    rel_pattern = re.compile(rf'//{re.escape(self.target_host)}', flags=re.IGNORECASE)
                    
                    if is_gzipped:
                        # Read the entire response content at once
                        try:
                            all_data = await loop.run_in_executor(None, lambda: resp.content)
                            print(f"DEBUG: Read {len(all_data)} bytes of gzipped content")
                            
                            # Decompress and process
                            decompressed = gzip.decompress(all_data)
                            print(f"DEBUG: Decompressed to {len(decompressed)} bytes")
                            text = decompressed.decode('utf-8', errors='ignore')
                            text = abs_pattern.sub(f'https://{self.proxy_host}', text)
                            text = rel_pattern.sub(f'//{self.proxy_host}', text)
                            yield text.encode('utf-8')
                        except Exception as e:
                            print(f"Error processing gzipped content: {e}")
                            # Fallback: try to read chunks manually
                            all_data = b''
                            while True:
                                try:
                                    chunk = await loop.run_in_executor(None, lambda: next(px_resp.body_stream))
                                    all_data += chunk
                                    print(f"DEBUG: Read chunk of {len(chunk)} bytes, total: {len(all_data)}")
                                except StopIteration:
                                    break
                                except Exception as e:
                                    print(f"Error reading chunk: {e}")
                                    break
                            
                            if all_data:
                                try:
                                    decompressed = gzip.decompress(all_data)
                                    text = decompressed.decode('utf-8', errors='ignore')
                                    text = abs_pattern.sub(f'https://{self.proxy_host}', text)
                                    text = rel_pattern.sub(f'//{self.proxy_host}', text)
                                    yield text.encode('utf-8')
                                except Exception as e:
                                    print(f"Error decompressing fallback: {e}")
                                    yield all_data
                    else:
                        # Stream non-gzipped content
                        while True:
                            try:
                                chunk = await loop.run_in_executor(None, lambda: next(px_resp.body_stream))
                                
                                # Translate the chunk inline
                                try:
                                    text = chunk.decode('utf-8', errors='ignore')
                                    text = abs_pattern.sub(f'https://{self.proxy_host}', text)
                                    text = rel_pattern.sub(f'//{self.proxy_host}', text)
                                    translated_chunk = text.encode('utf-8')
                                except Exception:
                                    # Non-text or decode error; pass through raw bytes
                                    translated_chunk = chunk
                                
                                yield translated_chunk
                            except StopIteration:
                                break
                            except Exception as e:
                                print(f"Error reading chunk: {e}")
                                break
                except Exception as e:
                    print(f"Error in stream_content: {e}")
                    yield b''
            
            # Stream translated content back to client
            return Response(
                stream_content(),
                status=px_resp.status_code,
                headers=px_resp.headers
            )
    
    def run(self):
        """Serve the Quart app via built-in async run"""
        # Workaround for Quart's signal handling in threaded environments
        import signal
        import os
        
        # Disable signal handling if not in main thread
        if os.getpid() != os.getppid():  # Simple check for non-main thread
            try:
                # Monkey patch signal handling to no-op
                def noop_signal_handler(*args, **kwargs):
                    pass
                signal.signal = noop_signal_handler
            except:
                pass
        
        # Quart's run will start the ASGI server
        self.app.run(host='0.0.0.0', port=self.port, debug=False)

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
