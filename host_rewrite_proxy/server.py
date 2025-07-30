#!/usr/bin/env python3

import argparse
import sys
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

    target_host = args.target_host
    proxy_port = args.port
    
    # Get ngrok URL for the proxy
    proxy_host = get_ngrok_url().replace('https://', '')
    print(f"Ngrok URL: https://{proxy_host}")
    print(f"Proxying requests to: {target_host}")
    print(f"Proxy running on port: {proxy_port}")
    print(f"Add to /etc/hosts: 127.0.0.1 {proxy_host}")
    print("=" * 50)

    # Create and run the server using the new HostRewriteServer class
    server = HostRewriteServer(target_host, proxy_host, proxy_port)
    server.run()

if __name__ == '__main__':
    main() 