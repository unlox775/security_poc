.PHONY: start

server:
	@pkill ngrok || true
	@echo "Starting services with concurrently..."
	@concurrently --prefix none "ngrok http 5001" "server.py --lang shell"

