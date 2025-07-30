.PHONY: start stop test test-unit test-server-flow clean

# Start the proxy server
start:
	@pkill ngrok || true
	@echo "Starting services with concurrently..."
	@concurrently --prefix none "ngrok http 5002" "python3 server.py $(TARGET)"

# Stop the proxy server
stop:
	@echo "Stopping proxy server..."
	@pkill -f "python3 server.py" || true

# Run all tests
test: test-unit test-server-flow
	@echo "✅ All tests completed!"

# Run unit tests
test-unit:
	@echo "🧪 Running unit tests..."
	@python3 -m unittest tests.test_cookie_rewriter -v
	@python3 -m unittest tests.test_cookie_extraction -v
	@echo "✅ Unit tests passed!"

# Run server flow tests
test-server-flow:
	@echo "🧪 Running server flow tests..."
	@python3 tests/test_server_flow.py
	@echo "✅ Server flow tests passed!"

# Clean up
clean:
	@echo "🧹 Cleaning up..."
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@echo "✅ Cleanup completed!" 