#!/bin/bash
# capture_command_log.sh - Reusable tool for logging command execution
#
# Usage:
#   capture_command_log.sh <slug> <command> [output_dir]
#
# Or with environment variable:
#   export COMMAND_LOG_DIR=/path/to/logs
#   capture_command_log.sh <slug> <command>
#
# Creates paired files (cmd.sh sorts before output.txt):
#   YYYY-MM-DD-HH-MM-SS_slug_cmd.sh - The command
#   YYYY-MM-DD-HH-MM-SS_slug_output.txt - The output

if [ $# -lt 2 ]; then
    echo "Usage: capture_command_log.sh <slug> <command> [output_dir]" >&2
    echo "   or: COMMAND_LOG_DIR=/path capture_command_log.sh <slug> <command>" >&2
    exit 1
fi

SLUG="$1"
COMMAND="$2"
OUTPUT_DIR="${COMMAND_LOG_DIR:-${3:-.}}"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Get timestamp
TIMESTAMP=$(date +"%Y-%m-%d-%H-%M-%S")

# Create file names (cmd.sh sorts before output.txt)
CMD_FILE="${OUTPUT_DIR}/${TIMESTAMP}_${SLUG}_cmd.sh"
OUT_FILE="${OUTPUT_DIR}/${TIMESTAMP}_${SLUG}_output.txt"

# Write command file
cat > "$CMD_FILE" <<EOF
#!/bin/bash
# Command: $SLUG
# Timestamp: $TIMESTAMP

$COMMAND
EOF

chmod +x "$CMD_FILE"

# Run command and capture output (both stdout and stderr)
# Use a temp file to ensure we capture everything
TEMP_OUT=$(mktemp)
eval "$COMMAND" > "$TEMP_OUT" 2>&1
EXIT_STATUS=$?

# Write captured output to file
cat "$TEMP_OUT" > "$OUT_FILE"

# Append exit status to output file
echo "" >> "$OUT_FILE"
echo "---" >> "$OUT_FILE"
echo "Exit status: $EXIT_STATUS" >> "$OUT_FILE"

# Clean up temp file
rm -f "$TEMP_OUT"

# Report status (with warning if non-zero)
if [ $EXIT_STATUS -eq 0 ]; then
    echo "Logged: ${TIMESTAMP}_${SLUG} (exit: $EXIT_STATUS)"
else
    echo "⚠️  WARNING: ${TIMESTAMP}_${SLUG} (exit: $EXIT_STATUS) - CHECK OUTPUT FILE" >&2
fi

