.PHONY: analyze audit test test-unit clean help

# Default CSV file paths (can be overridden)
DEV_CSV ?= /Users/dave/Downloads/2025-09_anthony_fraud/dev_suspect_activity.csv
PROD_CSV ?= /Users/dave/Downloads/2025-09_anthony_fraud/prod_suspect_activity.csv

# Analyze CSV files for unclassified events and patterns
analyze:
	@echo "🔍 Analyzing AWS CloudTrail events..."
	@PYTHONPATH=src python3 src/analyze_data.py --dev-csv $(DEV_CSV) --prod-csv $(PROD_CSV)

# Audit classifier structure and consistency
audit:
	@echo "🔍 Auditing classifier structure..."
	@PYTHONPATH=src python3 src/audit_classifier.py

# Run all tests
test:
	@echo "🧪 Running all tests..."
	@PYTHONPATH=src python3 -m unittest discover -v tests
	@echo "✅ All tests completed!"

# Run unit tests only
test-unit:
	@echo "🧪 Running unit tests..."
	@PYTHONPATH=src python3 -m unittest tests.test_classifier_structure -v
	@echo "✅ Unit tests passed!"

# Run integration tests
test-integration:
	@echo "🧪 Running integration tests..."
	@PYTHONPATH=src python3 tests/test_integration.py
	@echo "✅ Integration tests passed!"

# Clean up temporary files
clean:
	@echo "🧹 Cleaning up..."
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@echo "✅ Cleanup completed!"

# Show help
help:
	@echo "AWS Report Classifier - Available commands:"
	@echo ""
	@echo "  make analyze DEV_CSV=path/to/dev.csv PROD_CSV=path/to/prod.csv"
	@echo "    Analyze CSV files for unclassified events and patterns"
	@echo ""
	@echo "  make audit"
	@echo "    Audit classifier structure and internal consistency"
	@echo ""
	@echo "  make test"
	@echo "    Run all unit and integration tests"
	@echo ""
	@echo "  make test-unit"
	@echo "    Run unit tests only"
	@echo ""
	@echo "  make test-integration"
	@echo "    Run integration tests only"
	@echo ""
	@echo "  make clean"
	@echo "    Clean up temporary files"
	@echo ""
	@echo "  make help"
	@echo "    Show this help message"
	@echo ""
	@echo "Default CSV paths:"
	@echo "  DEV_CSV=$(DEV_CSV)"
	@echo "  PROD_CSV=$(PROD_CSV)"
