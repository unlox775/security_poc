# Host Rewrite Proxy

A real-time reverse proxy that dynamically rewrites hostnames, cookies, and URLs to create a seamless proxy experience. This is a **proof of concept demonstrating how easy it is to create phishing sites** by simply proxying legitimate websites.

...  And yes 😞 I did use AI to format my random rambling to make this README.md file.

## ⚠️ Security Warning

This tool demonstrates a critical security vulnerability: **anyone can create a convincing phishing site by simply proxying a legitimate website**. The proxy automatically:

- Rewrites all hostnames to appear legitimate
- Modifies cookies to work through the proxy
- Updates URLs in HTML/CSS/JS content
- Handles redirects transparently
- Supports all HTTP methods (GET, POST, PUT, etc.)

**This is why websites need additional security measures beyond simple domain validation.**

## Features

- **Real-time Hostname Rewriting**: Any domain can be proxied through any other domain
- **Cookie Domain Translation**: Automatically rewrites Set-Cookie headers to work through the proxy
- **URL Rewriting**: Updates all URLs in HTML/CSS/JS content to use the proxy domain
- **Redirect Handling**: Rewrites Location headers to maintain proxy chain
- **Full HTTP Method Support**: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
- **CORS Headers**: Automatically adds CORS headers for cross-origin requests
- **Ngrok Integration**: Automatically detects and uses ngrok for public access
- **Streaming Support**: Handles large responses and gzipped content efficiently

## Project Structure

```
host_rewrite_proxy/
├── src/
│   └── host_rewrite_proxy/
│       ├── __init__.py
│       ├── bug.py                    # Debug logging utility
│       ├── cookie_rewriter.py        # Cookie parsing and domain rewriting
│       ├── proxy_request.py          # Request processing and header translation
│       ├── proxy_response.py         # Response processing and content rewriting
│       └── server.py                 # Quart async server implementation
├── tests/
│   ├── test_cookie_rewriter.py       # Cookie rewriting tests
│   ├── test_proxy_request.py         # Request processing tests
│   ├── test_proxy_response.py        # Response processing tests
│   └── test_server.py                # Server integration tests
├── server.py                         # Main entry point
├── run_tests.py                      # Test runner
├── Makefile                          # Build and test automation
├── requirements.txt                  # Python dependencies
└── README.md                         # This file
```

## How It Works

### Request Flow
1. **Client Request**: Browser sends request to proxy (e.g., `https://fake-bank.ngrok.io/login`)
2. **Request Processing**: `ProxyRequest.from_quart()` extracts method, headers, and body
3. **Header Translation**: `translate()` method rewrites headers (Host, Origin, Referer, etc.)
4. **Upstream Request**: Forwards to target server (e.g., `https://real-bank.com/login`)
5. **Response Processing**: `ProxyResponse.from_requests()` wraps the response

### Response Flow
1. **Header Translation**: `translate_headers()` rewrites Set-Cookie and Location headers
2. **Content Rewriting**: `stream_content()` rewrites URLs in HTML/CSS/JS content
3. **CORS Headers**: Adds Access-Control-Allow-* headers
4. **Streaming**: Yields content in chunks for efficient delivery

### Key Components

- **`ProxyRequest`**: Handles incoming requests, extracts data, translates headers
- **`ProxyResponse`**: Processes responses, rewrites content, handles streaming
- **`CookieRewriter`**: Parses and rewrites cookie domains
- **`HostRewriteServer`**: Quart async server with route handling

## Installation

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install ngrok (required for public access)
# Download from https://ngrok.com/download
# Or install via package manager:
# brew install ngrok  # macOS
# snap install ngrok  # Ubuntu

# Install concurrently (for automatic ngrok + proxy startup)
npm install -g concurrently
```

## Usage

### Quick Start (Recommended)

```bash
# Start the proxy with automatic ngrok setup
make start TARGET=studio.code.org

# The proxy will:
# - Start ngrok automatically on port 5002
# - Start the proxy server
# - Display the ngrok URL for access
# - Rewrite all URLs to use the ngrok domain
# - Translate cookies to work through the proxy
# - Handle redirects transparently
# - Support all HTTP methods
```

### Advanced Usage

```bash
# Proxy any domain
make start TARGET=example.com
make start TARGET=bankofamerica.com
make start TARGET=github.com

# Stop the proxy
make stop
```

### Manual Setup (Alternative)

If you prefer to run ngrok and the proxy separately:

```bash
# Terminal 1: Start ngrok
ngrok http 5002

# Terminal 2: Start the proxy server
PYTHONPATH=src python3 server.py studio.code.org

# Access through the ngrok URL shown in Terminal 1
```

## Security Implications

### Phishing Attack Vector
This tool demonstrates how attackers can easily create convincing phishing sites:

1. **Domain Spoofing**: `https://bankofamerica.ngrok.io` looks legitimate
2. **Content Cloning**: All content, forms, and functionality work identically
3. **Cookie Theft**: Login forms capture credentials transparently
4. **Session Hijacking**: Cookies can be intercepted and reused

### Defensive Measures
Websites should implement:

- **JavaScript URL Validation**: Client-side checks for expected domain
- **Server-side Origin Validation**: Verify requests come from expected sources
- **Content Security Policy**: Restrict resource loading to trusted domains
- **Certificate Pinning**: Validate SSL certificates match expected values
- **Multi-factor Authentication**: Require additional verification beyond passwords

### Legitimate Use Cases

1. **Bypassing IP Blocks**: Access sites blocked by geographic restrictions
2. **Development Testing**: Test applications through different domains
3. **Security Research**: Study how proxies affect web applications
4. **Content Access**: Access content through alternative routes

## Testing

```bash
# Run all tests
make test

# Run specific test suites
python3 run_tests.py test_cookie_rewriter
python3 run_tests.py test_proxy_request
python3 run_tests.py test_proxy_response
python3 run_tests.py test_server
```

## Technical Details

### Header Translation
- **Host**: Rewritten to target domain
- **Origin**: Rewritten to target domain
- **Referer**: Rewritten to target domain
- **X-Forwarded-***: Removed (proxy-specific)

### Content Rewriting
- **Absolute URLs**: `https://target.com/path` → `https://proxy.com/path`
- **Protocol-relative URLs**: `//target.com/path` → `//proxy.com/path`
- **Cookies**: Domain rewritten from target to proxy
- **Redirects**: Location headers rewritten to maintain proxy chain

### Streaming Implementation
- **Gzipped Content**: Decompressed, processed, re-encoded
- **Chunked Delivery**: Content streamed in 8KB chunks
- **Error Handling**: Graceful fallbacks for malformed content

## Dependencies

- **Quart**: Async web framework
- **Requests**: HTTP client for proxying
- **urllib3**: HTTP library for requests
- **asyncio**: Async/await support

## License

This project is for educational and security research purposes. Use responsibly and only on systems you own or have explicit permission to test.