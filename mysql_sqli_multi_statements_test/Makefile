.PHONY: setup test clean

setup:
	@echo "Installing gems..."
	bundle install

test: setup
	@echo "Running multi-statement SQL injection test..."
	@echo ""
	@echo "Make sure MySQL 8 is running locally!"
	@echo "Update database credentials in test_multi_statement.rb if needed"
	@echo ""
	ruby test_multi_statement.rb

clean:
	@echo "Cleaning up test database..."
	@echo "Note: This will drop the test_multi_statement database"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		mysql -u root -e "DROP DATABASE IF EXISTS test_multi_statement;" || true; \
		echo "Database dropped"; \
	fi

help:
	@echo "Available targets:"
	@echo "  make setup  - Install required gems"
	@echo "  make test   - Run the multi-statement injection test"
	@echo "  make clean  - Drop the test database"
	@echo "  make help   - Show this help message"

