# Multi-Statement SQL Injection Test

## Purpose

Tests whether the `exists?` SQL injection vulnerability allows **multi-statement execution** (UPDATE/INSERT/DELETE) through semicolon injection, as suggested by examples in security documentation.

## The Question

Can an attacker execute multiple SQL statements through the `exists?` vulnerability? For example:
```ruby
User.exists?(["1=1);UPDATE users SET password='hacked' WHERE id=1;--"])
```

If this works, the vulnerability would allow **write access**, not just read access.

## Test Results

### 1. Multi-Statement Injection Through ActiveRecord `exists?`

**Result:** ❌ **BLOCKED**

When attempting to inject semicolon-separated statements through `exists?`, MySQL throws syntax errors:
```
Mysql2::Error: You have an error in your SQL syntax... near 'UPDATE hacker_target SET message='hacker_was_here'...
```

**Why:** ActiveRecord does NOT enable the `MULTI_STATEMENTS` flag by default. MySQL treats the semicolon and subsequent statement as part of the WHERE clause syntax, not as a separate statement.

**Evidence:** See `findings_log/` - all attempts show syntax errors, no data modification.

### 2. DML Statements in WHERE Clauses (DELETE/UPDATE/INSERT)

**Result:** ❌ **BLOCKED** (Grammar-level protection)

Attempts to use DELETE/UPDATE/INSERT as expressions in WHERE clauses are rejected by MySQL's SQL parser:
```
Mysql2::Error: You have an error in your SQL syntax... near 'DELETE FROM hacker_target WHERE id=1) = true...
```

**Why:** DML statements are **statements**, not **expressions**. They cannot be used where expressions are expected (like in WHERE clause conditions). This is a fundamental SQL grammar limitation.

**Evidence:** See `findings_log/2025-12-09-13-50-38_delete_in_where_test_output.txt` - MySQL explicitly rejects DELETE/UPDATE/INSERT as expressions.

### 3. Direct MySQL with MULTI_STATEMENTS Flag Enabled

**Result:** ✅ **WORKS** (Expected behavior)

When connecting directly to MySQL with `MULTI_STATEMENTS` flag enabled, multi-statements DO execute:
- UPDATE statement executed successfully
- Data was modified: `hacker_target.message` changed to `'hacker_was_here'`

**Why:** MySQL allows multiple statements when the `MULTI_STATEMENTS` flag is enabled. This is expected MySQL behavior - the flag is a "foot gun" option.

**Security Protection:** ActiveRecord does NOT enable this flag by default. This is the protection - default behavior blocks multi-statements.

**Evidence:** See `findings_log/2025-12-09-13-50-40_direct_mysql_multi_statement_blocked_output.txt` - UPDATE executed, data modified.

**Note on "Commands out of sync" error:** This error occurs when you try to run another query before processing all result sets from a multi-statement query. It's a MySQL client library requirement, NOT a security feature. The UPDATE executed BEFORE the error occurred.

## Conclusion

**The vulnerability is limited to READ access only:**

- ✅ Data exfiltration (SELECT-based)
- ✅ Boolean-based blind injection
- ✅ Time-based blind injection (sleep())
- ❌ **NO write access** (UPDATE/INSERT/DELETE blocked)
- ❌ **NO multi-statement execution** through ActiveRecord

**Severity:** P1 (Critical) - but limited to read access, not write access.

**Protection:** ActiveRecord's default configuration blocks multi-statements. If someone enabled `MULTI_STATEMENTS` in `database.yml`, write access would be possible.

## Test Files

- `test_basic_sqli_exists.rb` - Verifies basic SQL injection works (baseline)
- `test_multi_statement.rb` - Tests multi-statement injection through ActiveRecord
- `test_delete_in_where_clause.rb` - Tests DML statements in WHERE clauses
- `test_simple_mysql.rb` - Tests direct MySQL with MULTI_STATEMENTS flag
- `run_tests.sh` - Runs all tests with logging

## Running Tests

```bash
./run_tests.sh
```

All command and output files are logged in `findings_log/` with timestamps:
- `YYYY-MM-DD-HH-MM-SS_testname_cmd.sh` - The command
- `YYYY-MM-DD-HH-MM-SS_testname_output.txt` - The output

## Test Outputs

All test outputs are in `findings_log/`:
- `basic_sqli_verification` - Confirms basic SQL injection works
- `multi_statement_test` - Tests multi-statement through ActiveRecord (blocked)
- `delete_in_where_test` - Tests DML in WHERE clauses (blocked)
- `direct_mysql_multi_statement_blocked` - Tests direct MySQL with flag (works)
- `check_database_state` - Database state verification
- `check_hacker_target` - Target table verification
