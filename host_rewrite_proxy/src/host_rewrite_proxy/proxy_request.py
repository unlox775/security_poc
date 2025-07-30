#!/usr/bin/env python3

from typing import List, Tuple, Optional, Iterator
from flask import Request as FlaskRequest
try:
    from quart import Request as QuartRequest
except ImportError:
    QuartRequest = None
from requests.models import Response as RequestsResponse

class ProxyRequest:
    """Represents an incoming HTTP request to the proxy in a first-class data structure."""
    def __init__(self,
                 method: str,
                 path: str,
                 headers: List[Tuple[str, str]],
                 body: bytes,
                 query_string: Optional[str]):
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body
        self.query_string = query_string

    @classmethod
    def from_flask(cls, flask_request: FlaskRequest) -> 'ProxyRequest':
        # Extract headers as list of (name, value) tuples
        headers = [(k, v) for k, v in flask_request.headers.items()]
        body = flask_request.get_data()
        query_string = flask_request.query_string.decode() if flask_request.query_string else None
        path = flask_request.path
        return cls(
            method=flask_request.method,
            path=path,
            headers=headers,
            body=body,
            query_string=query_string
        )

    @classmethod
    async def from_quart(cls, quart_request: QuartRequest) -> 'ProxyRequest':
        """Extract raw headers and body from a Quart request in arrival order."""
        if QuartRequest is None:
            raise RuntimeError("QuartRequest not available; install quart to use this method.")
        # Use ASGI scope to get raw headers in arrival order
        hdrs = getattr(quart_request, 'scope', {}).get('headers', [])
        raw = [(name.decode('latin-1'), value.decode('latin-1')) for name, value in hdrs]
        body = await quart_request.get_data()
        query_string = quart_request.query_string.decode() if quart_request.query_string else None
        path = quart_request.path
        return cls(
            method=quart_request.method,
            path=path,
            headers=raw,
            body=body,
            query_string=query_string
        )

    def translate(self, target_host: str) -> None:
        """Rewrite headers before sending upstream (e.g., Host header, remove hop-by-hop)."""
        new_headers: List[Tuple[str, str]] = []
        for key, value in self.headers:
            lower = key.lower()
            if lower == 'host':
                new_headers.append(('Host', target_host))
            elif lower in ('content-length', 'transfer-encoding', 'connection'):
                continue
            else:
                new_headers.append((key, value))
        self.headers = new_headers

class ProxyResponse:
    """Represents the response from the upstream server in a streamable form."""
    def __init__(self,
                 status_code: int,
                 headers: List[Tuple[str, str]],
                 body_stream: Iterator[bytes]):
        self.status_code = status_code
        self.headers = headers
        self.body_stream = body_stream

    @classmethod
    def from_requests(cls, response: RequestsResponse) -> 'ProxyResponse':
        # Extract raw headers preserving multiple Set-Cookie entries
        raw_headers = [(k, v) for k, v in response.raw.headers.items()]
        # Stream the content in chunks
        body_stream = response.iter_content(chunk_size=8192)
        return cls(
            status_code=response.status_code,
            headers=raw_headers,
            body_stream=body_stream
        )

    def translate(self, proxy_host: str) -> None:
        """Apply translation logic (cookie rewriting, URL rewriting) to headers."""
        # TODO: integrate CookieRewriter and URL rewriting here
        pass 