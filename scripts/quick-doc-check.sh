#!/bin/bash

# Quick XML Documentation Check
# Lightweight script for rapid feedback during development
# Only shows files with issues, no details

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${PROJECT_ROOT}/src"

# Count undocumented members
count=$(find "$SRC_DIR" -name "*.cs" -type f ! -path "*/obj/*" ! -path "*/bin/*" -exec awk '
    BEGIN { prev=""; prev2=""; prev3="" }
    /^[[:space:]]*public[[:space:]]+(class|interface|enum|struct|record|delegate)/ {
        if (prev !~ /\/\/\// && prev2 !~ /\/\/\// && prev3 !~ /\/\/\//) {
            if ($0 !~ /\bpublic[a-zA-Z]/ && $0 !~ /=[^=].*public/ && $0 !~ /\(.*public/) {
                print FILENAME; exit
            }
        }
    }
    { prev3=prev2; prev2=prev; prev=$0 }
' {} \; | sort -u | wc -l)

if [ "$count" -eq 0 ]; then
    echo "✅ All public APIs documented"
    exit 0
else
    echo "❌ Found $count files with undocumented members"
    echo "Run: ./scripts/check-xml-docs.sh for details"
    exit 1
fi
