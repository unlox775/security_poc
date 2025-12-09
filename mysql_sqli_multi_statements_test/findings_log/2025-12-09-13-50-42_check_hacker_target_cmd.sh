#!/bin/bash
# Command: check_hacker_target
# Timestamp: 2025-12-09-13-50-42

mysql -u root test_multi_statement -e 'SELECT * FROM hacker_target;'
