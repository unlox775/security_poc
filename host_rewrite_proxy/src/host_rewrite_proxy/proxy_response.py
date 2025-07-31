#!/usr/bin/env python3

from typing import List, Tuple, Iterator
from requests.models import Response as RequestsResponse
import re

from . import bug

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
        """
        Build ProxyResponse from a requests.Response, preserving all raw HTTP headers
        (including duplicates and original case) if available.
        """
        # Prefer low-level HTTPMessage headers to preserve duplicates and case
        orig_resp = getattr(response.raw, '_original_response', None)
        if orig_resp and hasattr(orig_resp, 'headers'):
            # HTTPMessage.headers is a list-like preserving duplicates
            header_items = orig_resp.headers.items()
        else:
            header_items = response.raw.headers.items()
        raw_headers = [(k, v) for k, v in header_items]
        # Stream the content in chunks
        body_stream = response.iter_content(chunk_size=8192)
        return cls(
            status_code=response.status_code,
            headers=raw_headers,
            body_stream=body_stream
        )

    def translate_headers(self, origin_host: str, proxy_host: str) -> None:
        """Rewrite Set-Cookie and Location headers, replacing domains from origin_host to proxy_host."""
        new_headers = []
        
        for name, value in self.headers:
            lower_name = name.lower()
            
            if lower_name == 'set-cookie':
                # Handle Set-Cookie headers
                cookie_headers = [value]
                from .cookie_rewriter import CookieRewriter
                rewriter = CookieRewriter(origin_host, proxy_host)
                rewritten_cookies = rewriter.rewrite_cookies(cookie_headers)
                
                # Add rewritten Set-Cookie headers
                for cookie in rewritten_cookies:
                    new_headers.append(('Set-Cookie', cookie))
                    
            elif lower_name == 'location':
                # Handle Location headers for redirects
                try:
                    from urllib.parse import urlparse, urlunparse
                    parsed = urlparse(value)
                    
                    # If it's a relative URL, keep it as is
                    if not parsed.netloc:
                        new_headers.append((name, value))
                    else:
                        # If it's an absolute URL pointing to the origin host, rewrite it
                        if parsed.netloc.lower() == origin_host.lower():
                            new_location = urlunparse((
                                parsed.scheme,
                                proxy_host,
                                parsed.path,
                                parsed.params,
                                parsed.query,
                                parsed.fragment
                            ))
                            new_headers.append(('Location', new_location))
                        else:
                            # Keep other absolute URLs as is
                            new_headers.append((name, value))
                except Exception as e:
                    # If URL parsing fails, keep the original
                    new_headers.append((name, value))
                    
            else:
                # Keep all other headers as is
                new_headers.append((name, value))
        
        self.headers = new_headers

    def translate_content(self, origin_host: str, proxy_host: str, chunk_size: int = 8192) -> Iterator[bytes]:
        """Stream and rewrite body chunks, applying URL rewriting per chunk."""
        # Stream and rewrite URLs in each chunk
        # Rewrite absolute and protocol-relative URLs per chunk
        abs_pattern = re.compile(rf'https?://{re.escape(origin_host)}', flags=re.IGNORECASE)
        rel_pattern = re.compile(rf'//{re.escape(origin_host)}', flags=re.IGNORECASE)
        for chunk in self.body_stream:
            try:
                text = chunk.decode('utf-8', errors='ignore')
                text = abs_pattern.sub(f'https://{proxy_host}', text)
                text = rel_pattern.sub(f'//{proxy_host}', text)
                yield text.encode('utf-8')
            except Exception:
                # Non-text or decode error; pass through raw bytes
                yield chunk
        # After streaming, close any underlying stream if possible
        try:
            if hasattr(self.body_stream, 'close'):
                self.body_stream.close()
        except Exception:
            pass

    def next_chunk(self, origin_host: str, proxy_host: str) -> (bytes, bool):
        """
        Read the next translated chunk from the response.
        Returns a tuple (chunk_bytes, done_flag) where done_flag is True when no more data.
        """
        # Initialize iterator on first call
        if not hasattr(self, '_translate_iter'):
            self._translate_iter = self.translate_content(origin_host, proxy_host)
        try:
            chunk = next(self._translate_iter)
            return chunk, False
        except StopIteration:
            return b'', True 