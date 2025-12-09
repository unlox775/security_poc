#!/bin/bash
# Test runner using standard command logging tool

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_DIR="$(cd "$SCRIPT_DIR/../../__investigation_tools" && pwd)"
LOG_DIR="findings_log"

# Set output directory for the tool
export COMMAND_LOG_DIR="$SCRIPT_DIR/$LOG_DIR"

cd "$SCRIPT_DIR"

echo "Running tests with logging..."
echo "Log directory: $LOG_DIR"
echo ""

# Test 0: Verify basic SQL injection still works (baseline test with ActiveRecord)
"$TOOL_DIR/capture_command_log.sh" "basic_sqli_verification" "bundle exec ruby test_basic_sqli_exists.rb" "$LOG_DIR"
sleep 1

# Test 1: Multi-statement injection test
"$TOOL_DIR/capture_command_log.sh" "multi_statement_test" "bundle exec ruby test_multi_statement.rb" "$LOG_DIR"
sleep 1

# Test 2: DELETE in WHERE clause test
"$TOOL_DIR/capture_command_log.sh" "delete_in_where_test" "bundle exec ruby test_delete_in_where_clause.rb" "$LOG_DIR"
sleep 1

# Test 3: Direct MySQL test - confirms multi-statements are blocked (expected behavior)
"$TOOL_DIR/capture_command_log.sh" "direct_mysql_multi_statement_blocked" "bundle exec ruby test_simple_mysql.rb" "$LOG_DIR"
sleep 1

# Check database state
"$TOOL_DIR/capture_command_log.sh" "check_database_state" "mysql -u root test_multi_statement -e 'SELECT \"test_users\" as table_name, COUNT(*) as row_count FROM test_users UNION ALL SELECT \"hacker_target\", COUNT(*) FROM hacker_target;'" "$LOG_DIR"
sleep 1

# Check hacker_target table
"$TOOL_DIR/capture_command_log.sh" "check_hacker_target" "mysql -u root test_multi_statement -e 'SELECT * FROM hacker_target;'" "$LOG_DIR"

echo ""
echo "=================================================================================="
echo "Test Run Summary"
echo "=================================================================================="
echo ""

# Check all output files for exit status
FAILED_TESTS=()
PASSED_TESTS=()

for output_file in "$LOG_DIR"/*_output.txt; do
    if [ -f "$output_file" ]; then
        # Extract exit status from end of file (macOS compatible)
        exit_line=$(tail -1 "$output_file")
        if echo "$exit_line" | grep -q "Exit status:"; then
            exit_status=$(echo "$exit_line" | sed 's/.*Exit status: \([0-9]*\).*/\1/')
            # Extract test name: YYYY-MM-DD-HH-MM-SS_testname_output.txt -> testname
            test_name=$(basename "$output_file" | sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}_(.*)_output\.txt$/\1/')
            if [ "$exit_status" = "0" ]; then
                PASSED_TESTS+=("$test_name")
            else
                FAILED_TESTS+=("$test_name (exit: $exit_status)")
            fi
        fi
    fi
done

# Report results
if [ ${#PASSED_TESTS[@]} -gt 0 ]; then
    echo "✅ PASSED (${#PASSED_TESTS[@]}):"
    for test in "${PASSED_TESTS[@]}"; do
        echo "   - $test"
    done
    echo ""
fi

if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo "❌ FAILED (${#FAILED_TESTS[@]}):"
    for test in "${FAILED_TESTS[@]}"; do
        echo "   - $test"
    done
    echo ""
    echo "⚠️  WARNING: Some tests failed! Check output files in $LOG_DIR/"
    exit 1
else
    echo "✅ All tests passed!"
fi

echo ""
echo "Done. Check $LOG_DIR/ for all command and output files."

