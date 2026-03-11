.PHONY: start start-ruby start-node start-shell

# Default: Ruby payload (for backward compatibility)
start: start-ruby

start-ruby:
	@pkill ngrok || true
	@echo "Starting services with concurrently (Ruby payload)..."
	@concurrently --prefix none "ngrok http 5001" "python3 server.py --lang ruby"

start-node:
	@pkill ngrok || true
	@echo "Starting services with concurrently (Node.js payload)..."
	@concurrently --prefix none "ngrok http 5001" "python3 server.py --lang node"

start-shell:
	@pkill ngrok || true
	@echo "Starting services with concurrently (shell payload)..."
	@concurrently --prefix none "ngrok http 5001" "python3 server.py --lang shell"

