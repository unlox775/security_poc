#!/usr/bin/env python3

import sys, os
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, '..', 'src')
sys.path.insert(0, src_dir)

import unittest
import socket
import threading
import time
import requests
from flask import Flask, request, jsonify
from host_rewrite_proxy.proxy_request import ProxyRequest

class TestProxyRequestIntegration(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        @self.app.route('/extract', methods=['GET', 'POST'])
        def extract():
            pr = ProxyRequest.from_flask(request)
            return jsonify({
                'method': pr.method,
                'path': pr.path,
                'headers': pr.headers,
                'body': pr.body.decode('utf-8'),
                'query_string': pr.query_string
            })
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        self.port = port
        self.server_thread = threading.Thread(
            target=self.app.run,
            kwargs={'host': '127.0.0.1', 'port': port, 'debug': False, 'use_reloader': False},
            daemon=True
        )
        self.server_thread.start()
        print(f'Server started on port {self.port}')
        time.sleep(0.5)

    def tearDown(self):
        # Daemon thread exits automatically
        pass

    def test_integration_get(self):
        url = f'http://127.0.0.1:{self.port}/extract?x=1&y=2'
        headers = {'X-Test': 'value', 'Cookie': 'a=b; c=d'}
        print(f'Sending GET request to {url} with headers {headers}')
        resp = requests.get(url, headers=headers)
        data = resp.json()
        self.assertEqual(data['method'], 'GET')
        self.assertEqual(data['path'], '/extract')
        self.assertEqual(data['query_string'], 'x=1&y=2')
        self.assertIn(['X-Test', 'value'], data['headers'])
        self.assertIn(['Cookie', 'a=b; c=d'], data['headers'])
        self.assertEqual(data['body'], '')

    def test_integration_post(self):
        url = f'http://127.0.0.1:{self.port}/extract'
        headers = {'X-Post': 'yes'}
        print(f'Sending POST request to {url} with headers {headers}')
        resp = requests.post(url, headers=headers, data='hello')
        data = resp.json()
        self.assertEqual(data['method'], 'POST')
        self.assertEqual(data['path'], '/extract')
        self.assertIsNone(data['query_string'])
        self.assertIn(['X-Post', 'yes'], data['headers'])
        self.assertEqual(data['body'], 'hello')

class TestProxyRequestUnit(unittest.TestCase):
    def test_translate_rewrites_and_filters_headers(self):
        initial_headers = [
            ('Host', 'oldhost.com'),
            ('Content-Length', '123'),
            ('Transfer-Encoding', 'chunked'),
            ('Connection', 'keep-alive'),
            ('Authorization', 'Bearer token'),
            ('Cookie', 'a=b; c=d')
        ]
        pr = ProxyRequest(
            method='GET', path='/', headers=initial_headers, body=b'', query_string=None
        )
        pr.translate('newhost.com')
        self.assertIn(('Host', 'newhost.com'), pr.headers)
        self.assertNotIn(('Content-Length', '123'), pr.headers)
        self.assertNotIn(('Transfer-Encoding', 'chunked'), pr.headers)
        self.assertNotIn(('Connection', 'keep-alive'), pr.headers)
        self.assertIn(('Authorization', 'Bearer token'), pr.headers)
        self.assertIn(('Cookie', 'a=b; c=d'), pr.headers)

if __name__ == '__main__':
    unittest.main(verbosity=2) 