#!/usr/bin/env python3

from typing import List, Tuple, Iterator
from requests.models import Response as RequestsResponse

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

    def translate_headers(self, origin_host: str, proxy_host: str) -> None:
        """Rewrite Set-Cookie headers using CookieRewriter, replacing domains from origin_host to proxy_host."""
        from .cookie_rewriter import CookieRewriter
        # Extract existing Set-Cookie header values
        cookie_values = [v for (k, v) in self.headers if k.lower() == 'set-cookie']
        # Rewrite cookies
        rewriter = CookieRewriter(origin_host, proxy_host)
        rewritten = rewriter.rewrite_cookies(cookie_values)
        # Filter out old Set-Cookie entries
        new_headers = [(k, v) for (k, v) in self.headers if k.lower() != 'set-cookie']
        # Append rewritten Set-Cookie headers
        for cookie in rewritten:
            new_headers.append(('Set-Cookie', cookie))
        self.headers = new_headers

    def translate_content(self, origin_host: str, proxy_host: str, chunk_size: int = 8192) -> Iterator[bytes]:
        """Stream and rewrite body chunks, applying URL rewriting per chunk."""
        from .reverse_proxy import ReverseProxy
        proxy = ReverseProxy(origin_host, proxy_host)
        for chunk in self.body_stream:
            # Rewrite URLs in this chunk if needed
            try:
                rewritten = proxy.rewrite_urls_in_content(chunk, origin_host, proxy_host)
            except Exception:
                rewritten = chunk
            yield rewritten
        # After streaming, close any underlying stream if possible
        try:
            if hasattr(self.body_stream, 'close'):
                self.body_stream.close()
        except Exception:
            pass 