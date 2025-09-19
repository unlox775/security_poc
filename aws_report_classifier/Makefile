.PHONY: analyze audit test test-unit clean help

# Default CSV file paths (can be overridden)
# For multiple environments, use ENV_Foo_CSV format:
# ENV_DEV_CSV=/path/to/dev.csv ENV_PROD_CSV=/path/to/prod.csv make analyze
# For single environment, use ENV_CSV:
# ENV_CSV=/path/to/file.csv make analyze


# Analyze CSV files for unclassified events and patterns
analyze:
	@echo "🔍 Analyzing AWS CloudTrail events..."
	@$(eval ENV_VARS := $(shell env | grep '^ENV_.*_CSV=' | sed 's/^ENV_\([^_]*\)_CSV=.*/\1/' | tr '[:upper:]' '[:lower:]' | tr '\n' ',' | sed 's/,$$//'))
	@$(eval ENV_CSV_VAR := $(shell env | grep '^ENV_CSV='))
	@if [ -n "$(ENV_CSV_VAR)" ]; then \
		echo "📁 Single CSV mode: $(ENV_CSV)"; \
		PYTHONPATH=src python3 src/analyze_data.py --csv $(ENV_CSV); \
	elif [ -n "$(ENV_VARS)" ]; then \
		echo "📁 Multi-environment mode: $(ENV_VARS)"; \
		PYTHONPATH=src python3 src/analyze_data.py --env-csvs $(ENV_VARS); \
	else \
		echo "❌ No CSV files specified. Please use ENV_CSV or ENV_Foo_CSV format"; \
		echo "Examples:"; \
		echo "  ENV_CSV=/path/to/file.csv make analyze"; \
		echo "  ENV_DEV_CSV=/path/to/dev.csv ENV_PROD_CSV=/path/to/prod.csv make analyze"; \
		exit 1; \
	fi

# Run session clustering analysis
sessions:
	@echo "🔍 Running session clustering analysis..."
	@$(eval ENV_VARS := $(shell env | grep '^ENV_.*_CSV=' | sed 's/^ENV_\([^_]*\)_CSV=.*/\1/' | tr '[:upper:]' '[:lower:]' | tr '\n' ',' | sed 's/,$$//'))
	@$(eval ENV_CSV_VAR := $(shell env | grep '^ENV_CSV='))
	@if [ -n "$(ENV_CSV_VAR)" ]; then \
		echo "📁 Single CSV mode: $(ENV_CSV)"; \
		PYTHONPATH=src python3 src/session_clustering_analysis.py --csv $(ENV_CSV) --output-dir .; \
	elif [ -n "$(ENV_VARS)" ]; then \
		echo "📁 Multi-environment mode: $(ENV_VARS)"; \
		PYTHONPATH=src python3 src/session_clustering_analysis.py --env-csvs $(ENV_VARS) --output-dir .; \
	else \
		echo "❌ No CSV files specified. Please use ENV_CSV or ENV_Foo_CSV format"; \
		echo "Examples:"; \
		echo "  ENV_CSV=/path/to/file.csv make sessions"; \
		echo "  ENV_DEV_CSV=/path/to/dev.csv ENV_PROD_CSV=/path/to/prod.csv make sessions"; \
		exit 1; \
	fi

# Check a single file for unclassified events
check-file:
	@if [ -z "$(FILE)" ]; then \
		echo "❌ Please specify FILE=path/to/file.csv"; \
		echo "Example: make check-file FILE=/path/to/data.csv"; \
		exit 1; \
	fi
	@echo "🔍 Checking file for unclassified events..."
	@PYTHONPATH=src python3 src/analyze_data.py --check-file $(FILE)

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

# Run session clustering tests
test-sessions:
	@echo "🧪 Running session clustering tests..."
	@PYTHONPATH=src python3 -m unittest tests.test_session_clustering -v
	@echo "✅ Session clustering tests passed!"

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
	@echo "  # Multi-environment analysis:"
	@echo "  ENV_DEV_CSV=path/to/dev.csv ENV_PROD_CSV=path/to/prod.csv make analyze"
	@echo "  ENV_DEV_CSV=path/to/dev.csv ENV_PROD_CSV=path/to/prod.csv make sessions"
	@echo ""
	@echo "  # Single environment analysis:"
	@echo "  ENV_CSV=path/to/file.csv make analyze"
	@echo "  ENV_CSV=path/to/file.csv make sessions"
	@echo ""
	@echo ""
	@echo "  make check-file FILE=path/to/file.csv"
	@echo "    Check a single CSV file for unclassified events"
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
	@echo "  make test-sessions"
	@echo "    Run session clustering tests only"
	@echo ""
	@echo "  make clean"
	@echo "    Clean up temporary files"
	@echo ""
	@echo "  make help"
	@echo "    Show this help message"
	@echo ""
