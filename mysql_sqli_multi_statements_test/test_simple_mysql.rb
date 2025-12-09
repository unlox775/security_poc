#!/usr/bin/env ruby
# frozen_string_literal: true

# Direct MySQL Multi-Statement Test
# Tests multi-statement behavior with and without MULTI_STATEMENTS flag
# 
# Expected results:
# - WITH MULTI_STATEMENTS flag: Multi-statements work (expected - MySQL allows this)
# - WITHOUT flag: Multi-statements blocked (expected - default behavior)
# - ActiveRecord does NOT enable this flag by default (security protection)

require 'mysql2'

# Database configuration
HOST = 'localhost'
USER = 'root'
PASS = '' # No password for local MySQL
DB = 'test_multi_statement'

puts "=" * 80
puts "Direct MySQL Multi-Statement Test"
puts "=" * 80
puts ""
puts "Purpose: Test multi-statement behavior with MULTI_STATEMENTS flag enabled"
puts "Expected: Multi-statements SHOULD work when flag is enabled (MySQL allows this)"
puts "Security: ActiveRecord does NOT enable this flag by default (protection)"
puts ""

# Create database if needed
begin
  admin_client = Mysql2::Client.new(host: HOST, username: USER, password: PASS)
  admin_client.query("CREATE DATABASE IF NOT EXISTS #{DB}")
  admin_client.close
rescue => e
  puts "Note: #{e.message}"
end

# Connect with multi-statements enabled
client = Mysql2::Client.new(
  host: HOST,
  username: USER,
  password: PASS,
  database: DB,
  flags: Mysql2::Client::MULTI_STATEMENTS
)

# Setup test tables (use separate queries to avoid multi-statement issues)
puts "Setting up test tables..."
client.query("DROP TABLE IF EXISTS test_users")
client.query("CREATE TABLE test_users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  userid VARCHAR(50),
  email VARCHAR(100)
)")
client.query("INSERT INTO test_users (userid, email) VALUES ('admin', 'admin@test.com'), ('user1', 'user1@test.com')")

client.query("DROP TABLE IF EXISTS hacker_target")
client.query("CREATE TABLE hacker_target (
  id INT PRIMARY KEY AUTO_INCREMENT,
  message VARCHAR(255) DEFAULT 'original_value',
  modified_at DATETIME DEFAULT NULL
)")
client.query("INSERT INTO hacker_target (message) VALUES ('original_value')")

puts "✓ Tables created\n\n"

# Test 1: Check initial state
result = client.query("SELECT message FROM hacker_target WHERE id = 1").first
puts "Initial hacker_target.message: #{result['message']}\n\n"

# Test 2: Try multi-statement query (simulating the injection)
puts "=" * 80
puts "TEST: Multi-statement query with semicolon"
puts "=" * 80

multi_query = <<~SQL
  SELECT 1 AS one FROM test_users WHERE (1=1);
  UPDATE hacker_target SET message='hacker_was_here', modified_at=NOW() WHERE id=1;
SQL

puts "Executing:"
puts multi_query
puts "\n"

begin
  # Execute multi-statement query
  # With MULTI_STATEMENTS, we need to process results differently
  puts "Executing multi-statement query..."
  client.query(multi_query)
  
  # Process all result sets
  # CRITICAL: With MULTI_STATEMENTS, you MUST process ALL result sets before running another query
  # Otherwise you get "Commands out of sync" error
  puts "Processing all result sets..."
  result_count = 0
  loop do
    result = client.store_result
    break unless result
    
    result_count += 1
    puts "  Result set #{result_count}:"
    result.each do |row|
      puts "    Row: #{row.inspect}"
    end
    
    # Move to next result set if available
    break unless client.next_result
  end
  
  puts "  Processed #{result_count} result set(s)"
  puts ""
  puts "NOTE: 'Commands out of sync' error occurs if you try to run another query"
  puts "      before processing all result sets from a multi-statement query."
  puts "      This is a MySQL client library requirement, not a security feature."
  puts ""
  
  # Check if data was modified - use a FRESH connection to avoid "out of sync" error
  puts "Checking data status with fresh connection..."
  check_client = Mysql2::Client.new(
    host: HOST,
    username: USER,
    password: PASS,
    database: DB
  )
  result_after = check_client.query("SELECT message, modified_at FROM hacker_target WHERE id = 1").first
  check_client.close
  
  puts "After multi-statement query:"
  puts "  hacker_target.message: #{result_after['message']}"
  puts "  hacker_target.modified_at: #{result_after['modified_at']}"
  puts ""
  
  if result_after['message'] == 'hacker_was_here'
    puts "✓ EXPECTED: Multi-statement UPDATE executed successfully"
    puts "  MySQL executed both the SELECT and UPDATE statements"
    puts "  This is expected when MULTI_STATEMENTS flag is enabled"
  else
    puts "⚠️  UNEXPECTED: Data not modified - UPDATE did not execute"
    puts "  This would be unexpected when MULTI_STATEMENTS flag is enabled"
    puts "  Need to investigate why multi-statements didn't work"
  end
  
rescue => e
  puts "ERROR: #{e.class}: #{e.message}"
  puts ""
  puts "Error explanation:"
  if e.message.include?("Commands out of sync")
    puts "  'Commands out of sync' means:"
    puts "    - A multi-statement query was executed"
    puts "    - Not all result sets were processed before trying to run another query"
    puts "    - This is a MySQL client library requirement"
    puts "    - It does NOT mean multi-statements are blocked"
    puts "    - The UPDATE may have executed before the error occurred!"
  end
  puts ""
  
  # Check if data was modified despite error - use fresh connection
  puts "Checking data status with fresh connection (to avoid 'out of sync' error)..."
  begin
    check_client = Mysql2::Client.new(
      host: HOST,
      username: USER,
      password: PASS,
      database: DB
    )
    result_after = check_client.query("SELECT message, modified_at FROM hacker_target WHERE id = 1").first
    check_client.close
    
    puts "  Query: SELECT message, modified_at FROM hacker_target WHERE id = 1"
    puts "  Result: #{result_after.inspect}"
    puts ""
    
    if result_after['message'] == 'hacker_was_here'
      puts "✓ EXPECTED: Multi-statement UPDATE executed successfully"
      puts "  The UPDATE executed before the 'out of sync' error occurred"
      puts "  This is expected when MULTI_STATEMENTS flag is enabled"
    else
      puts "⚠️  UNEXPECTED: Data unchanged: #{result_after['message']}"
      puts "  UPDATE did not execute - this would be unexpected with flag enabled"
    end
  rescue => e2
    puts "  Could not check data status: #{e2.message}"
  end
end

puts "\n"

# Check if multi-statements worked BEFORE resetting
puts "=" * 80
puts "INTERIM CHECK: Did multi-statement UPDATE execute?"
puts "=" * 80
interim_check = Mysql2::Client.new(host: HOST, username: USER, password: PASS, database: DB)
interim_result = interim_check.query("SELECT message, modified_at FROM hacker_target WHERE id = 1").first
interim_check.close

puts "Current data status:"
puts "  message: #{interim_result['message']}"
puts "  modified_at: #{interim_result['modified_at']}"
puts ""

if interim_result['message'] == 'hacker_was_here'
  puts "✓ EXPECTED: Multi-statement UPDATE executed"
  puts "   This confirms multi-statements work when MULTI_STATEMENTS flag is enabled"
  puts "   This is expected MySQL behavior - the flag allows multiple statements"
  multi_statement_worked = true
else
  puts "⚠️  UNEXPECTED: Multi-statement UPDATE did not execute"
  puts "   This would be unexpected when MULTI_STATEMENTS flag is enabled"
  multi_statement_worked = false
end
puts ""

# Test 3: Try without MULTI_STATEMENTS flag
puts "=" * 80
puts "TEST: Same query WITHOUT MULTI_STATEMENTS flag"
puts "=" * 80

# Reset target (use a fresh connection since the previous one may be in a bad state)
begin
  reset_client = Mysql2::Client.new(host: HOST, username: USER, password: PASS, database: DB)
  reset_client.query("UPDATE hacker_target SET message='original_value', modified_at=NULL WHERE id=1")
  reset_client.close
rescue => e
  puts "Note: Could not reset target: #{e.message}"
end

# Create new connection without multi-statements
client_no_multi = Mysql2::Client.new(
  host: HOST,
  username: USER,
  password: PASS,
  database: DB
  # No MULTI_STATEMENTS flag
)

begin
  results = client_no_multi.query(multi_query)
  results.each { |row| puts "Result: #{row.inspect}" }
  
  result_after = client_no_multi.query("SELECT message FROM hacker_target WHERE id = 1").first
  if result_after['message'] == 'hacker_was_here'
    puts "⚠️  Multi-statement worked even without flag!"
    client_no_multi.close
    exit 1  # This would be bad - multi-statements shouldn't work
  else
    puts "✓ Multi-statement blocked (expected)"
  end
rescue => e
  puts "ERROR (expected): #{e.class}: #{e.message}"
  begin
    result_after = client_no_multi.query("SELECT message FROM hacker_target WHERE id = 1").first
    puts "Data status: #{result_after['message']}"
    if result_after['message'] == 'hacker_was_here'
      puts "⚠️  BUT: Data WAS modified before error!"
      client_no_multi.close
      exit 1  # This would be bad
    else
      puts "✓ Multi-statement blocked - data unchanged (expected)"
    end
  rescue => e2
    puts "  Could not check data status: #{e2.message}"
  end
end

client_no_multi.close
begin
  client.close
rescue
  # Client may already be closed
end

puts "\n" + "=" * 80
puts "Test Summary"
puts "=" * 80

if multi_statement_worked
  puts "✓ Test PASSED - Multi-statements work when MULTI_STATEMENTS flag is enabled (expected)"
  puts ""
  puts "Summary:"
  puts "  - MySQL allows multiple statements when MULTI_STATEMENTS flag is enabled"
  puts "  - This is expected MySQL behavior - the flag is a 'foot gun' option"
  puts "  - When enabled, UPDATE/DELETE/INSERT can execute in multi-statement queries"
  puts ""
  puts "Security Protection:"
  puts "  - ActiveRecord does NOT enable MULTI_STATEMENTS flag by default"
  puts "  - This is the security protection - default behavior blocks multi-statements"
  puts "  - If someone enabled this flag in database.yml, write access would be possible"
  puts ""
  puts "About 'Commands out of sync' error:"
  puts "  - This error occurs when you try to run another query before processing"
  puts "    all result sets from a multi-statement query"
  puts "  - It's a MySQL client library requirement, NOT a security feature"
  puts "  - The UPDATE executed BEFORE the error occurred"
  puts "  - This confirms multi-statements work when the flag is enabled"
  puts ""
  puts "Conclusion: Multi-statements work with flag (expected), blocked without flag (protection)"
else
  puts "⚠️  UNEXPECTED: Multi-statements did not work even with flag enabled"
  puts "  This would indicate a problem - need to investigate"
end
puts "=" * 80

exit 0

