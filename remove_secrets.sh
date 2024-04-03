#!/bin/bash

# Path to the gitleaks report file
report_file="./gitleaks_report.json"

# Parse the report file and remove detected secrets
jq -c '.[]' "$report_file" | while IFS= read -r line; do
    # Extract file path, line number, and secret from the JSON
    file=$(echo "$line" | jq -r '.File')
    line_number=$(echo "$line" | jq -r '.StartLine')

    # Replace the detected secret line with an empty string
    sed -i "${line_number}s/.*/ /" "$file"

    # Optional: Print information about the removed secret
    echo "Removed secret from file '$file' at line $line_number"
done
