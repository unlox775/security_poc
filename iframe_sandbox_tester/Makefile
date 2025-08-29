# Iframe Sandbox Security Tester Makefile

.PHONY: setup run cleanup install help

help:
	@echo "Iframe Sandbox Security Tester"
	@echo ""
	@echo "Commands:"
	@echo "  setup    - Add entries to /etc/hosts file"
	@echo "  run      - Start the test server"
	@echo "  cleanup  - Remove entries from /etc/hosts file"
	@echo "  install  - Install Python dependencies"
	@echo "  test     - Run all tests (setup, run, cleanup)"

setup:
	@echo "Setting up /etc/hosts entries (requires sudo password)..."
	@if ! grep -q "parent-site.local" /etc/hosts; then \
		echo "127.0.0.1    parent-site.local" | sudo tee -a /etc/hosts; \
	fi
	@if ! grep -q "child-site.local" /etc/hosts; then \
		echo "127.0.0.1    child-site.local" | sudo tee -a /etc/hosts; \
	fi
	@echo "Setup complete!"

run:
	@echo "Starting iframe sandbox tester..."
	@echo "Parent site: http://parent-site.local:8080"
	@echo "Child site: http://child-site.local:8080"
	@echo ""
	@echo "Press Ctrl+C to stop"
	python3 iframe_sandbox_test.py

cleanup:
	@echo "Cleaning up /etc/hosts entries (requires sudo password)..."
	@sudo sed -i '' '/parent-site.local/d' /etc/hosts
	@sudo sed -i '' '/child-site.local/d' /etc/hosts
	@echo "Cleanup complete!"

install:
	@echo "Installing Python dependencies..."
	pip3 install flask
	@echo "Dependencies installed!"

test: setup run cleanup
	@echo "Test complete!"

# Alternative: Run on different ports for true cross-origin testing
run-cross-origin:
	@echo "Starting cross-origin test..."
	@echo "Parent site: http://parent-site.local:8080"
	@echo "Child site: http://child-site.local:8081"
	@echo ""
	@echo "In another terminal, run: python3 iframe_sandbox_test.py --port 8081"
	python3 iframe_sandbox_test.py --port 8080
