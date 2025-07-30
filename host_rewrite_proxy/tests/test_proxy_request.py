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
from quart import Quart, request, jsonify
from host_rewrite_proxy.proxy_request import ProxyRequest
from unittest import IsolatedAsyncioTestCase
import math
import hashlib
CHUNK_SIZE = 1024

class TestProxyRequestIntegration(IsolatedAsyncioTestCase):
    def setUp(self):
        self.app = Quart(__name__)
        @self.app.route('/extract', methods=['GET', 'POST'])
        async def extract():
            pr = await ProxyRequest.from_quart(request)
            # Compute streaming metrics: read in CHUNK_SIZE byte chunks
            chunks = 0
            hasher = hashlib.md5()
            while True:
                chunk = pr.body_stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
                chunks += 1
            streaming = pr.body_stream is not None
            body_md5 = hasher.hexdigest()
            return jsonify({
                'method': pr.method,
                'path': pr.path,
                'headers': pr.headers,
                'body_length': len(pr.body),
                'query_string': pr.query_string,
                'streaming': streaming,
                'chunks': chunks,
                'body_md5': body_md5
            })

    def tearDown(self):
        pass

    async def test_integration_get(self):
        async with self.app.test_client() as client:
            url = '/extract?x=1&y=2'
            headers = [('X-Test', 'value'), ('Cookie', 'a=b; c=d')]
            print(f"\nSending GET request: {url} with headers {headers}\n")
            resp = await client.get(url, headers=headers)
            data = await resp.get_json()
        self.assertEqual(data['method'], 'GET')
        self.assertEqual(data['path'], '/extract')
        self.assertEqual(data['query_string'], 'x=1&y=2')
        self.assertIn(['x-test', 'value'], data['headers'])
        self.assertIn(['cookie', 'a=b; c=d'], data['headers'])
        self.assertEqual(data['body_length'], 0)

    async def test_integration_post(self):
        # Generate 4k of "this is the song that never ends, etc"
        send_data = 'this is the song that never ends, it goes on and on my friends, some people started singing it not knowing what it was, and they\'ll continue singing it forever just because...' * 100
        async with self.app.test_client() as client:
            resp = await client.post('/extract', headers=[('X-Post', 'yes')], data=send_data)
            data = await resp.get_json()
        self.assertEqual(data['method'], 'POST')
        self.assertEqual(data['path'], '/extract')
        self.assertIsNone(data['query_string'])
        self.assertIn(['x-post', 'yes'], data['headers'])
        self.assertEqual(data['body_length'], len(send_data))
        # Streaming flags and metrics
        self.assertTrue(data.get('streaming'), 'Should indicate streaming enabled')
        # Dynamically compute expected chunks and MD5
        expected_chunks = math.ceil(len(send_data) / CHUNK_SIZE)
        expected_md5 = hashlib.md5(send_data.encode('utf-8')).hexdigest()
        self.assertEqual(data.get('chunks'), expected_chunks, 'Should read in CHUNK_SIZE chunks')
        self.assertEqual(data.get('body_md5'), expected_md5, 'MD5 should match streamed content')

    async def test_integration_duplicate_headers(self):
        async with self.app.test_client() as client:
            headers = [
                ('X-Multi', 'first'),
                ('X-Foo', 'bar'),
                ('X-Multi', 'second'),
                ('x-Multi', 'third'),
                ('cookie', 'a=b; c=d'),
                ('X-Multi', 'fourth'),
                ('X-Multi', 'fifth'),
                ('Cookie', 'e=f; g=h'),
                ]
            resp = await client.get('/extract?dup=1', headers=headers)
            data = await resp.get_json()
        # Raw headers list preserved
        values = [h[1] for h in data['headers'] if h[0] == 'x-multi']

        # Verify exact ordering and raw values (lowercased header names and list format)
        expected = [
            ['x-multi', 'first'],
            ['x-foo', 'bar'],
            ['x-multi', 'second'],
            ['x-multi', 'third'],
            ['cookie', 'a=b; c=d'],
            ['x-multi', 'fourth'],
            ['x-multi', 'fifth'],
            ['cookie', 'e=f; g=h'],
        ]
        # Only check the first N entries to avoid default headers (user-agent, host)
        self.assertEqual(data['headers'][:len(expected)], expected)

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