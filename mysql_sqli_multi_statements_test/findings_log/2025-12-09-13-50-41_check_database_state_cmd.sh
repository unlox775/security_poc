#!/bin/bash
# Command: check_database_state
# Timestamp: 2025-12-09-13-50-41

mysql -u root test_multi_statement -e 'SELECT "test_users" as table_name, COUNT(*) as row_count FROM test_users UNION ALL SELECT "hacker_target", COUNT(*) FROM hacker_target;'
