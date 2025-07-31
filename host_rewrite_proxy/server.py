#!/usr/bin/env python3
import sys
print("DEBUG: Starting server.py", file=sys.stderr, flush=True)
import argparse
import os

# Add src directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, 'src')
sys.path.insert(0, src_dir)

from host_rewrite_proxy.server import HostRewriteServer, get_ngrok_url

def main():
    parser = argparse.ArgumentParser(description='Host Rewrite Proxy')
    parser.add_argument('target_host', help='Target hostname to proxy to (e.g., example.com)')
    parser.add_argument('--port', type=int, default=5002, help='Port to run the proxy on (default: 5002)')
    args = parser.parse_args()
    print(f"DEBUG: args: {args}")

    target_host = args.target_host
    proxy_port = args.port
    
    # Get ngrok URL for the proxy
    print("Getting ngrok URL...")
    proxy_host = get_ngrok_url().replace('https://', '')
    print(f"Ngrok URL: https://{proxy_host}", flush=True)
    print(f"Proxying requests to: {target_host}", flush=True)
    print(f"Proxy running on port: {proxy_port}", flush=True)
    print(f"Add to /etc/hosts: 127.0.0.1 {proxy_host}", flush=True)
    print("=" * 50, flush=True)

    # Create and run the server using the new HostRewriteServer class
    server = HostRewriteServer(target_host, proxy_host, proxy_port)
    server.run()

if __name__ == '__main__':
    main() 