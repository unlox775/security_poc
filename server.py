#!/usr/bin/env python3
"""
Host Rewrite Proxy Server

A reverse proxy that rewrites cookie domains from the target host to the proxy host.
"""

import argparse
import sys
from src.host_rewrite_proxy.server import HostRewriteServer, get_ngrok_url

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

    # Create and run the server
    server = HostRewriteServer(target_host, proxy_host, proxy_port)
    server.run()

if __name__ == '__main__':
    main() 