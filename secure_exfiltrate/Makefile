.PHONY: start

start:
	@pkill ngrok || true
	@echo "Starting services with concurrently..."
	@concurrently --prefix none "ngrok http 5000" "server.py"

