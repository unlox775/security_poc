# Host Rewrite Proxy

A reverse proxy tool that intercepts requests to a spoofed domain and forwards them to a target host while rewriting URLs, cookies, and headers to maintain the illusion that the user is interacting with the original domain.

## Purpose

This tool demonstrates how a reverse proxy can be used to:
- Intercept traffic to a spoofed domain (e.g., `spoof.com`)
- Forward requests to a legitimate target (e.g., `example.com`)
- Rewrite response content to maintain the spoofed domain in URLs
- Handle cookies and headers appropriately

This is useful for security testing, phishing simulations, and understanding how reverse proxies work in practice.

## How It Works

1. **Request Interception**: The proxy receives requests to the spoofed domain
2. **Host Header Rewriting**: Changes the `Host` header to the target domain
3. **Request Forwarding**: Sends the modified request to the target server
4. **Response Processing**: Rewrites URLs in HTML/CSS/JS responses back to the spoofed domain
5. **Cookie Handling**: Modifies cookie domains to work with the spoofed domain

## Usage

### Quick Start

```bash
# Start the proxy targeting example.com
make start TARGET=example.com
```

### Manual Start

```bash
# Kill any existing ngrok processes
pkill ngrok

# Start ngrok tunnel
ngrok http 5002

# In another terminal, start the proxy
python3 server.py example.com
```

### Command Line Options

```bash
python3 server.py <target_host> [--port <port>]

# Examples:
python3 server.py example.com
python3 server.py amazon.com --port 5003
```

## Setup Instructions

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Install ngrok** (if not already installed):
   ```bash
   # macOS
   brew install ngrok
   
   # Or download from https://ngrok.com/
   ```

3. **Install concurrently** (for the Makefile):
   ```bash
   npm install -g concurrently
   ```

4. **Start the Proxy**:
   ```bash
   make start TARGET=example.com
   ```

5. **Configure DNS/Hosts**:
   - The tool will output the ngrok URL
   - Add the ngrok hostname to your `/etc/hosts` file:
     ```
     127.0.0.1 <ngrok-hostname>
     ```

## Features

### URL Rewriting
- Rewrites absolute URLs in HTML responses
- Handles protocol-relative URLs (`//example.com`)
- Processes CSS and JavaScript files

### Cookie Management
- Rewrites `Set-Cookie` domain attributes
- Preserves cookie functionality across the proxy

### Header Handling
- Removes problematic headers (Content-Length, Transfer-Encoding)
- Strips CORS headers that might interfere
- Maintains other headers for compatibility

### Logging
- Logs all requests with method, path, status code, and response size
- Provides real-time feedback on proxy activity

## Security Considerations

⚠️ **Warning**: This tool is for educational and testing purposes only.

- **Legal Use**: Only use against domains you own or have explicit permission to test
- **Ethical Testing**: Respect robots.txt and rate limits
- **No Malicious Use**: Do not use for phishing or other malicious activities

## Technical Details

### Port Configuration
- Default proxy port: 5002
- ngrok tunnel: HTTP on port 5002
- Target: HTTPS requests to specified hostname

### Content Types Handled
- `text/html`
- `text/css` 
- `application/javascript`

### Error Handling
- Graceful handling of connection errors
- Detailed error logging
- Fallback responses for failed requests

## Troubleshooting

### Common Issues

1. **ngrok not found**:
   ```bash
   # Install ngrok
   brew install ngrok
   ```

2. **Port already in use**:
   ```bash
   # Use a different port
   python3 server.py example.com --port 5003
   ```

3. **SSL certificate errors**:
   - The proxy uses HTTPS for target requests
   - Ensure your system trusts the target's SSL certificate

4. **Hosts file not working**:
   ```bash
   # Flush DNS cache
   sudo dscacheutil -flushcache
   ```

## Example Output

```
Ngrok URL: https://abc123.ngrok.io
Proxying requests to: example.com
Proxy running on port: 5002
Add to /etc/hosts: 127.0.0.1 abc123.ngrok.io
==================================================
GET / -> 200 (15432 bytes)
GET /static/css/main.css -> 200 (2048 bytes)
POST /login -> 302 (0 bytes)
```

## License

This tool is provided for educational purposes only. Use responsibly and in accordance with applicable laws and regulations. 