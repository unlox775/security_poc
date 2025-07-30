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
    def test_from_requests_preserves_raw_headers_and_streaming(self):
        # Simulate upstream HTTP response with multiple Set-Cookie headers
        raw = HTTPResponse(
            body=b'hello world',
            status=200,
            headers=[
                ('Set-Cookie', 'c1=v1'),
                ('Set-Cookie', 'c2=v2'),
                ('X-Test', 'value')
            ]
        )
        resp = Response()
        resp.raw = raw
        resp.status_code = 200
        resp._content = b'hello world'
        # Override iter_content to yield the buffered content, avoiding raw.stream issues
        resp.iter_content = lambda chunk_size=8192, decode_content=True: iter([resp._content])
        # Use from_requests to build ProxyResponse
        pr = ProxyResponse.from_requests(resp)
        # Status code preserved
        self.assertEqual(pr.status_code, 200)
        # Check that raw.headers.items() are preserved in order
        expected = list(raw.headers.items())
        self.assertEqual(pr.headers, expected)
        # Streaming body yields correct content in one chunk
        chunks = list(pr.body_stream)
        self.assertEqual(b''.join(chunks), b'hello world')
        # Default iter_content chunk size produces one complete chunk
        self.assertEqual(chunks, [b'hello world'])
    
    def test_translate_headers_rewrites_cookies(self):
        # Simulate HTTPResponse with multiple Set-Cookie headers and HTML body
        raw = HTTPResponse(
            body=b'<a href="http://original.com/path">link</a>',
            status=200,
            headers=[
                ('Set-Cookie', 'sess=abc; domain=original.com; path=/'),
                ('Set-Cookie', 'user=1; path=/'),
                ('Content-Type', 'text/html')
            ]
        )
        resp = Response()
        resp.raw = raw
        resp.status_code = 200
        content = b'<a href="http://original.com/path">link</a>'
        resp._content = content
        resp.iter_content = lambda chunk_size, decode_content=True: iter([content])
        pr = ProxyResponse.from_requests(resp)
        pr.translate_headers('original.com', 'proxy.com')
        cookies = [v for k, v in pr.headers if k.lower() == 'set-cookie']
        self.assertIn('sess=abc; Path=/; Domain=proxy.com', cookies[0])
        self.assertIn('user=1; Path=/', cookies[1])

    def test_translate_content_rewrites_urls(self):
        # Simulate HTTPResponse with body containing URLs
        raw = HTTPResponse(
            body=b'<a href="http://original.com/path">link</a>',
            status=200,
            headers=[('Content-Type', 'text/html')]
        )
        resp = Response()
        resp.raw = raw
        resp.status_code = 200
        content = b'<a href="http://original.com/path">link</a>'
        resp._content = content
        resp.iter_content = lambda chunk_size, decode_content=True: iter([content])
        pr = ProxyResponse.from_requests(resp)
        chunks = list(pr.translate_content('original.com', 'proxy.com'))
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
        self.server.shutdown()

    def test_integration_multi_chunk(self):
        url = f'http://127.0.0.1:{self.port}/'
        resp = requests.get(url, stream=True)
        pr = ProxyResponse.from_requests(resp)
        # Status code and headers
        self.assertEqual(pr.status_code, 200)
        expected_headers = list(resp.raw.headers.items())
        self.assertEqual(pr.headers, expected_headers)
        # Body should stream in default chunk_size 8192
        chunks = list(pr.body_stream)
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
        pr = ProxyResponse.from_requests(resp)
        # Raw headers should match exactly from requests
        expected_raw = list(resp.raw.headers.items())
        self.assertEqual(pr.headers, expected_raw)
        # Now rewrite cookies domains
        pr.translate_headers('example.com', 'proxy.com')
        # Extract rewritten Set-Cookie values
        cookies = [v for k, v in pr.headers if k.lower() == 'set-cookie']
        # c1 should have domain rewritten, c2 should preserve path only
        self.assertIn('c1=1; Path=/; Domain=proxy.com', cookies[0])
        self.assertIn('c2=2; Path=/', cookies[1])
        server.shutdown()

if __name__ == '__main__':
    unittest.main(verbosity=2) 