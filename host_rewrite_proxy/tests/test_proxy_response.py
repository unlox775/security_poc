#!/usr/bin/env python3

import sys, os
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, '..', 'src')
sys.path.insert(0, src_dir)

import unittest
from requests.models import Response
from urllib3.response import HTTPResponse
from host_rewrite_proxy.proxy_response import ProxyResponse

import threading, time, math, requests
from http.server import HTTPServer, BaseHTTPRequestHandler

class HTTPDummyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Generate a body larger than default chunk_size (8192)
        body = b'x' * 15000
        self.send_response(200)
        self.send_header('Set-Cookie', 'c1=v1')
        self.send_header('Set-Cookie', 'c2=v2')
        self.send_header('X-Test', 'value')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

class TestProxyResponse(unittest.TestCase):
    def make_dummy_response(self, headers, body=b'hello world'):
        """Helper to create a Response with given raw headers and body."""
        from types import SimpleNamespace
        raw = HTTPResponse(body=body, status=200, headers=headers)
        resp = Response()
        resp.raw = raw
        # Attach an original_response stub to preserve insertion order, including duplicates
        resp.raw._original_response = SimpleNamespace(
            headers=SimpleNamespace(items=lambda: headers)
        )
        resp.status_code = raw.status
        resp.iter_content = lambda chunk_size, decode_content=True: iter([body])
        return resp, raw

    def test_from_requests_preserves_raw_headers_and_streaming(self):
        # Simulate upstream HTTP response with multiple Set-Cookie headers
        headers = [
            ('Set-Cookie', 'c1=v1'),
            ('X-Test', 'value'),
            ('Set-Cookie', 'c2=v2'),
        ]
        raw_response, raw = self.make_dummy_response(headers)
        px_response = ProxyResponse.from_requests(raw_response)
        # Status code preserved
        self.assertEqual(px_response.status_code, 200)
        # Explicitly check header order and values (preserve original interleaving)
        self.assertEqual(px_response.headers[0], ('Set-Cookie', 'c1=v1'))
        self.assertEqual(px_response.headers[1], ('X-Test', 'value'))
        self.assertEqual(px_response.headers[2], ('Set-Cookie', 'c2=v2'))
        # Streaming yields exactly one chunk equal to the body
        chunks = list(px_response.body_stream)
        self.assertEqual(chunks, [b'hello world'])
    
    def test_translate_headers_rewrites_cookies(self):
        # Rewrite domains in Set-Cookie headers
        headers = [
            ('Set-Cookie', 'sess=abc; domain=original.com; path=/'),
            ('Set-Cookie', 'user=1; path=/'),
            ('Content-Type', 'text/html'),
        ]
        resp, _ = self.make_dummy_response(headers)
        px_response = ProxyResponse.from_requests(resp)
        px_response.translate_headers('original.com', 'proxy.com')
        cookies = [v for k, v in px_response.headers if k.lower() == 'set-cookie']
        self.assertIn('sess=abc; Path=/; Domain=proxy.com', cookies[0])
        self.assertIn('user=1; Path=/', cookies[1])

    def test_translate_content_rewrites_urls(self):
        # Rewrite URLs in body fragments
        content = b'<a href="http://original.com/path">link</a>'
        headers = [('Content-Type', 'text/html')]
        resp, _ = self.make_dummy_response(headers, body=content)
        px_response = ProxyResponse.from_requests(resp)
        chunks = list(px_response.translate_content('original.com', 'proxy.com'))
        output = b''.join(chunks)
        self.assertIn(b'https://proxy.com/path', output)
        self.assertNotIn(b'http://original.com', output)

class TestProxyResponseIntegration(unittest.TestCase):
    def setUp(self):
        # Start simple HTTP server in background thread
        self.server = HTTPServer(('127.0.0.1', 0), HTTPDummyHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.1)

    def tearDown(self):
        # Cleanly shutdown HTTP server and close socket
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)

    def test_integration_multi_chunk(self):
        url = f'http://127.0.0.1:{self.port}/'
        resp = requests.get(url, stream=True)
        px_response = ProxyResponse.from_requests(resp)
        # Status code and headers
        self.assertEqual(px_response.status_code, 200)
        expected_headers = list(resp.raw.headers.items())
        self.assertEqual(px_response.headers, expected_headers)
        # Body should stream in default chunk_size 8192
        chunks = list(px_response.body_stream)
        self.assertEqual(len(chunks), math.ceil(15000 / 8192))
        self.assertEqual(b''.join(chunks), b'x' * 15000)
    
    def test_headers_pass_through_and_cookie_translate(self):
        # Define handler that emits mixed-case and duplicate headers
        class HeaderHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'data'
                self.send_response(200)
                self.send_header('X-A', 'val1')
                self.send_header('x-a', 'val2')
                self.send_header('Set-Cookie', 'c1=1; domain=example.com; path=/')
                self.send_header('Set-Cookie', 'c2=2; path=/')
                self.send_header('X-B', 'val3')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, fmt, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), HeaderHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.1)
        url = f'http://127.0.0.1:{port}/'
        resp = requests.get(url, stream=True)
        px_response = ProxyResponse.from_requests(resp)
        # Skip default Server and Date headers
        hdrs = px_response.headers
        # Find where our custom headers start (first X-A)
        start = next(i for i, (k, _) in enumerate(hdrs) if k == 'X-A')
        expected = [
            ('X-A', 'val1'),
            ('x-a', 'val2'),
            ('Set-Cookie', 'c1=1; domain=example.com; path=/'),
            ('Set-Cookie', 'c2=2; path=/'),
            ('X-B', 'val3'),
            ('Content-Length', '4'),
        ]
        self.assertEqual(hdrs[start:start+len(expected)], expected)
        # Now rewrite cookies domains
        px_response.translate_headers('example.com', 'proxy.com')
        # Extract rewritten Set-Cookie values
        cookies = [v for k, v in px_response.headers if k.lower() == 'set-cookie']
        # c1 should have domain rewritten, c2 should preserve path only
        self.assertIn('c1=1; Path=/; Domain=proxy.com', cookies[0])
        self.assertIn('c2=2; Path=/', cookies[1])
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

if __name__ == '__main__':
    unittest.main(verbosity=2) 