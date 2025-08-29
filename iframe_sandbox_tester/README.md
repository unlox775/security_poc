# Iframe Sandbox Security Tester

A comprehensive testing environment for iframe sandbox security configurations. Tests different sandbox parameters and their effects on cross-origin communication and access.

## What This Tests

The tester creates 4 different iframes with varying sandbox configurations:

1. **No Sandbox** - Most restrictive, blocks all scripts
2. **Scripts Only** - Allows JavaScript execution but no parent access
3. **Scripts + Same Origin** - Allows scripts and same-origin access (like WebLab2)
4. **Scripts + Forms + Popups** - Allows scripts, forms, and popups

Each iframe tests:
- Parent window access (cookies, localStorage, location)
- PostMessage communication
- Inline content execution
- Same-origin effects (own cookies, localStorage, origin)

## Quick Start

### 1. Install Dependencies
```bash
make install
```

### 2. Setup Hosts File
```bash
make setup
```
This adds entries to `/etc/hosts`:
```
127.0.0.1    parent-site.local
127.0.0.1    child-site.local
```

### 3. Run the Tester
```bash
make run
```

### 4. Open in Browser
Visit: http://parent-site.local:8080

### 5. Cleanup (when done)
```bash
make cleanup
```

## What You'll See

The parent page displays:
- Secret cookie value and localStorage key
- 4 iframes with different sandbox configurations
- Real-time test results from each iframe

Each iframe contains tests for:
1. **Parent Access** - Accessing parent window properties
2. **Inline Content** - Executing inline scripts and event handlers
3. **Same-Origin Effects** - Accessing own cookies, localStorage, and origin
4. **Message Received** - Receiving messages from parent

## Expected Results

### Iframe 1 (No Sandbox):
- ❌ All JavaScript tests show "JavaScript n/a"
- ✅ Basic content (styles, images) allowed

### Iframe 2 (Scripts Only):
- ❌ Parent access blocked (SecurityError)
- ✅ PostMessage works
- ✅ Inline scripts and event handlers work
- ❌ Cannot access own cookies/localStorage (opaque origin)

### Iframe 3 (Scripts + Same Origin):
- ❌ Parent access still blocked (cross-origin)
- ✅ PostMessage works
- ✅ Inline scripts and event handlers work
- ✅ Can access own cookies/localStorage (real origin)

### Iframe 4 (Scripts + Forms + Popups):
- ❌ Parent access blocked
- ✅ PostMessage works
- ✅ Inline scripts and event handlers work
- ❌ Cannot access own cookies/localStorage (opaque origin)

## Key Insights

### `allow-same-origin` is NOT a Security Vulnerability
Contrary to initial assumptions, `allow-same-origin` does NOT allow cross-origin access to parent window properties. It only affects how the iframe's own origin is treated:

- **Without `allow-same-origin`**: Iframe has "opaque origin" (like `null`)
- **With `allow-same-origin`**: Iframe has its "real origin" (e.g., `http://child-site.local:8080`)

This means:
- ✅ Iframe can access its own cookies, localStorage, and origin
- ❌ Iframe still cannot access parent window properties across origins
- ✅ PostMessage communication works (which is safe by design)

### WebLab2's Configuration is Secure
WebLab2 uses `sandbox="allow-scripts allow-same-origin"` which:
- Allows JavaScript execution in the iframe
- Allows the iframe to access its own storage (needed for student projects)
- Allows PostMessage communication (which WebLab2 uses)
- **Blocks** access to parent window properties (which is what we want!)

## Browser Compatibility

Tested on:
- Chrome 120+
- Firefox 120+
- Safari 17+

Different browsers may have slightly different security policies.

## Troubleshooting

### "Connection refused" errors:
- Make sure the Python server is running
- Check that the ports aren't in use
- Try different ports with `--port` flag

### Hosts file issues:
- Run `make cleanup` then `make setup`
- Check `/etc/hosts` manually
- May need to flush DNS: `sudo dscacheutil -flushcache` (macOS)

### Iframe not loading:
- Check browser console for errors
- Ensure both domains resolve correctly
- Try accessing child site directly: http://child-site.local:8080/iframe-test

## Files

- `iframe_sandbox_test.py` - Flask server serving both parent and iframe content
- `parent.html` - Main parent page with iframe grid
- `parent.js` - Parent page JavaScript for message handling
- `iframe-test.html` - Content loaded inside each iframe
- `iframe-test.js` - Iframe JavaScript for running tests
- `Makefile` - Convenience commands for setup/run/cleanup
