#!/bin/bash
# Command: check_database_state
# Timestamp: 2025-12-09-14-21-54

mysql -u root test_multi_statement -e 'SELECT "test_users" as table_name, COUNT(*) as row_count FROM test_users UNION ALL SELECT "hacker_target", COUNT(*) FROM hacker_target;'
