# Host Rewrite Server

A reverse proxy server that rewrites cookie domains from the target host to the proxy host. This is useful for testing web applications where you need to proxy requests while maintaining proper cookie functionality.

## Features

- **Cookie Domain Rewriting**: Automatically rewrites cookie domains from the target host to the proxy host
- **Multiple Cookie Support**: Handles multiple Set-Cookie headers and multiple cookies in a single header
- **Subdomain Support**: Correctly identifies and rewrites subdomains (e.g., `www.example.com`, `.example.com`)
- **URL Rewriting**: Rewrites URLs in HTML/CSS/JS content to use the proxy host
- **Ngrok Integration**: Automatically detects and uses ngrok for public access

## Project Structure

```
host_rewrite_server/
├── src/
│   └── host_rewrite_proxy/
│       ├── __init__.py
│       ├── cookie_rewriter.py      # Cookie parsing and rewriting logic
│       ├── reverse_proxy.py        # Reverse proxy functionality
│       └── server.py              # Flask server implementation
├── tests/
│   ├── __init__.py
│   ├── test_cookie_extraction.py  # Tests for cookie extraction from requests
│   ├── test_cookie_rewriter.py    # Unit tests for cookie rewriter
│   └── test_server_flow.py        # Integration tests for server flow
├── server.py                      # Main server entry point
├── run_tests.py                   # Test runner
├── Makefile                       # Build and test automation
├── requirements.txt               # Python dependencies
└── README.md                      # This file
```

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Starting the Server

```bash
# Start the proxy server (requires ngrok to be running)
make start TARGET=example.com

# Or run directly
python3 server.py example.com
```

### Running Tests

```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run server flow tests only
make test-server-flow
```

### Manual Testing

1. Start ngrok: `ngrok http 5002`
2. Start the proxy: `python3 server.py example.com`
3. Add the ngrok domain to `/etc/hosts`: `127.0.0.1 <ngrok-domain>`
4. Access the proxy through the ngrok URL

## How It Works

1. **Request Processing**: The server receives requests and forwards them to the target host
2. **Response Processing**: Responses are processed to rewrite URLs and extract cookies
3. **Cookie Rewriting**: Cookie domains are rewritten from the target host to the proxy host
4. **Response Delivery**: The modified response is sent back to the client

## Testing

The project includes comprehensive tests:

- **Unit Tests**: Test individual components like cookie parsing and rewriting
- **Integration Tests**: Test the complete server flow with mocked responses
- **Cookie Extraction Tests**: Test the extraction of cookies from requests.Response objects

## Development

### Adding New Tests

1. Create test files in the `tests/` directory
2. Use the `run_tests.py` script to run tests with proper Python path setup
3. Follow the existing test patterns for consistency

### Code Structure

- **CookieRewriter**: Handles cookie parsing, domain rewriting, and serialization
- **ReverseProxy**: Manages request/response proxying and URL rewriting
- **HostRewriteServer**: Flask server implementation with route handling

## Dependencies

- Flask: Web framework
- Requests: HTTP client for proxying
- concurrently: For running ngrok and server simultaneously (optional)

## License

This project is part of the security_poc repository and is for educational/demonstration purposes.