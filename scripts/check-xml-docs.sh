#!/bin/bash
set -euo pipefail

# XML Documentation Checker for C# Projects
# Verifies that all public members have XML documentation (///)
# Works without dotnet SDK - uses regex pattern matching
#
# Usage:
#   ./check-xml-docs.sh [directory]
#   Exit code 0: All public members documented
#   Exit code 1: Missing documentation found

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${1:-$(dirname "$SCRIPT_DIR")}"
SRC_DIR="${PROJECT_ROOT}/src"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_FILES=0
TOTAL_UNDOCUMENTED=0
FILES_WITH_ISSUES=0

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}XML Documentation Checker${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Project root: ${PROJECT_ROOT}"
echo "Source directory: ${SRC_DIR}"
echo ""

# Create temporary file for results
TEMP_RESULTS=$(mktemp)
trap "rm -f $TEMP_RESULTS" EXIT

# Find all C# files
find "$SRC_DIR" -name "*.cs" -type f ! -path "*/obj/*" ! -path "*/bin/*" | sort | while read -r file; do
    TOTAL_FILES=$((TOTAL_FILES + 1))

    # Use awk to analyze the file
    awk -v filename="$file" '
    BEGIN {
        file_has_issues = 0
        undocumented_count = 0

        # Store previous lines to check for XML comments
        prev_lines[0] = ""
        prev_lines[1] = ""
        prev_lines[2] = ""
        prev_lines[3] = ""
        prev_lines[4] = ""
    }

    # Function to check if previous lines contain ///
    function has_xml_doc() {
        for (i = 0; i <= 4; i++) {
            if (prev_lines[i] ~ /^[[:space:]]*\/\/\//) {
                return 1
            }
        }
        return 0
    }

    # Function to check if this is a real declaration (not a call or parameter)
    function is_declaration(line) {
        # Skip lines that are clearly not declarations
        if (line ~ /^[[:space:]]*\/\//) return 0                    # Comments
        if (line ~ /^[[:space:]]*\*/) return 0                      # Multi-line comment
        if (line ~ /^[[:space:]]*\[/) return 0                      # Attributes (usually)
        if (line ~ /^[[:space:]]*#/) return 0                       # Preprocessor
        if (line ~ /^[[:space:]]*using /) return 0                  # Using statements
        if (line ~ /^[[:space:]]*namespace /) return 0              # Namespace
        if (line ~ /^[[:space:]]*\}/) return 0                      # Closing braces

        # Skip method calls and assignments that happen to have "public" in them
        if (line ~ /[a-z][a-zA-Z0-9]*\(.*public/) return 0         # Method calls with public
        if (line ~ /=[^=].*public/) return 0                        # Assignments
        if (line ~ /\bpublic[a-zA-Z]/) return 0                    # publicKey, publicField (no space)

        # Must start with public (optionally preceded by attributes on same line)
        if (line !~ /^[[:space:]]*((\[[^\]]*\][[:space:]]*)*public[[:space:]])/) return 0

        # Skip auto-property accessors
        if (line ~ /^[[:space:]]*public[[:space:]]+(get|set)[[:space:]]*[;{]/) return 0
        if (line ~ /\{[[:space:]]*(get|set)[[:space:]]*(;|\{)/) return 0

        return 1
    }

    # Main pattern matching for public declarations
    /^[[:space:]]*((\[[^\]]*\][[:space:]]*)*public[[:space:]])/ {
        if (!is_declaration($0)) {
            # Shift previous lines and continue
            for (i = 4; i > 0; i--) {
                prev_lines[i] = prev_lines[i-1]
            }
            prev_lines[0] = $0
            next
        }

        # Check for XML documentation
        if (!has_xml_doc()) {
            if (file_has_issues == 0) {
                print "\n" filename ":"
                file_has_issues = 1
            }
            print "  Line " NR ": " $0
            undocumented_count++
        }
    }

    # Shift previous lines
    {
        for (i = 4; i > 0; i--) {
            prev_lines[i] = prev_lines[i-1]
        }
        prev_lines[0] = $0
    }

    END {
        if (file_has_issues > 0) {
            print "UNDOCUMENTED:" undocumented_count
            print "FILENAME:" filename
        }
    }
    ' "$file" >> "$TEMP_RESULTS"
done

# Process results
echo -e "${BLUE}----------------------------------------${NC}"
echo -e "${BLUE}Results:${NC}"
echo -e "${BLUE}----------------------------------------${NC}"
echo ""

if [ -s "$TEMP_RESULTS" ]; then
    # Parse results
    current_file=""
    while IFS= read -r line; do
        if [[ $line =~ ^UNDOCUMENTED:([0-9]+)$ ]]; then
            count="${BASH_REMATCH[1]}"
            TOTAL_UNDOCUMENTED=$((TOTAL_UNDOCUMENTED + count))
            FILES_WITH_ISSUES=$((FILES_WITH_ISSUES + 1))
        elif [[ $line =~ ^FILENAME:(.+)$ ]]; then
            current_file="${BASH_REMATCH[1]}"
        elif [[ $line =~ ^\.\/ ]] || [[ $line =~ ^/ ]]; then
            # File header
            echo -e "${YELLOW}${line}${NC}"
        elif [[ $line =~ ^[[:space:]]+Line ]]; then
            # Undocumented member
            echo -e "${RED}${line}${NC}"
        else
            echo "$line"
        fi
    done < "$TEMP_RESULTS"

    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}FAILED: Missing XML Documentation${NC}"
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}Files with issues: ${FILES_WITH_ISSUES}${NC}"
    echo -e "${RED}Total undocumented members: ${TOTAL_UNDOCUMENTED}${NC}"
    echo ""
    echo "Please add XML documentation (///) to all public members."
    echo "Example:"
    echo "  /// <summary>"
    echo "  /// Description of the member"
    echo "  /// </summary>"
    echo "  public void MyMethod() { }"
    exit 1
else
    echo -e "${GREEN}✓ All public members are documented!${NC}"
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}SUCCESS: Zero documentation warnings${NC}"
    echo -e "${GREEN}========================================${NC}"
    exit 0
fi
