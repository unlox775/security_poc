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

class TestProxyRequestIntegration(IsolatedAsyncioTestCase):
    def setUp(self):
        self.app = Quart(__name__)
        @self.app.route('/extract', methods=['GET', 'POST'])
        async def extract():
            pr = await ProxyRequest.from_quart(request)
            return jsonify({
                'method': pr.method,
                'path': pr.path,
                'headers': pr.headers,
                'body': pr.body.decode('utf-8'),
                'query_string': pr.query_string
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
        self.assertEqual(data['body'], '')

    async def test_integration_post(self):
        async with self.app.test_client() as client:
            resp = await client.post('/extract', headers=[('X-Post', 'yes')], data=b'hello')
            data = await resp.get_json()
        self.assertEqual(data['method'], 'POST')
        self.assertEqual(data['path'], '/extract')
        self.assertIsNone(data['query_string'])
        self.assertIn(['x-post', 'yes'], data['headers'])
        self.assertEqual(data['body'], 'hello')

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