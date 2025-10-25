#!/bin/bash
# AES-CCM Test Runner Script
# Comprehensive testing suite for HeroCrypt AES-CCM implementation

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  HeroCrypt AES-CCM Test Suite${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Check for .NET SDK
if ! command -v dotnet &> /dev/null; then
    echo -e "${RED}ERROR: .NET SDK not found!${NC}"
    echo "Please install .NET SDK from: https://dotnet.microsoft.com/download"
    exit 1
fi

echo -e "${GREEN}✓${NC} .NET SDK found: $(dotnet --version)"
echo ""

# Navigate to project root
cd "$(dirname "$0")"

# Restore dependencies
echo -e "${YELLOW}[1/7]${NC} Restoring dependencies..."
dotnet restore --verbosity quiet
echo -e "${GREEN}✓${NC} Dependencies restored"
echo ""

# Build the project
echo -e "${YELLOW}[2/7]${NC} Building project..."
dotnet build --configuration Release --no-restore --verbosity quiet
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Build successful"
else
    echo -e "${RED}✗${NC} Build failed"
    exit 1
fi
echo ""

# Run all AES-CCM tests
echo -e "${YELLOW}[3/7]${NC} Running all AES-CCM tests..."
dotnet test \
    --configuration Release \
    --no-build \
    --filter "FullyQualifiedName~AesCcmTests" \
    --logger "console;verbosity=normal" \
    --collect:"XPlat Code Coverage" \
    --results-directory ./TestResults

TEST_EXIT_CODE=$?
echo ""

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓${NC} All AES-CCM tests passed!"
else
    echo -e "${RED}✗${NC} Some tests failed (exit code: $TEST_EXIT_CODE)"
    echo ""
    echo "Run with --verbosity=detailed for more information:"
    echo "  dotnet test --filter \"FullyQualifiedName~AesCcmTests\" --logger \"console;verbosity=detailed\""
    exit 1
fi
echo ""

# Run RFC 3610 compliance tests specifically
echo -e "${YELLOW}[4/7]${NC} Verifying RFC 3610 compliance..."
RFC_RESULT=$(dotnet test \
    --configuration Release \
    --no-build \
    --filter "Category=Compliance&FullyQualifiedName~AesCcmTests" \
    --logger "console;verbosity=minimal" 2>&1)

if echo "$RFC_RESULT" | grep -q "Passed!"; then
    echo -e "${GREEN}✓${NC} RFC 3610 test vectors passed"
    echo "$RFC_RESULT" | grep -E "(Rfc3610|Passed|Failed)" || true
else
    echo -e "${RED}✗${NC} RFC 3610 test vectors failed"
    echo "$RFC_RESULT"
    exit 1
fi
echo ""

# Run authentication tests
echo -e "${YELLOW}[5/7]${NC} Verifying authentication security..."
AUTH_RESULT=$(dotnet test \
    --configuration Release \
    --no-build \
    --filter "FullyQualifiedName~AesCcmTests.AesCcm_*Authentication*" \
    --logger "console;verbosity=minimal" 2>&1)

if echo "$AUTH_RESULT" | grep -q "Passed!"; then
    echo -e "${GREEN}✓${NC} Authentication tests passed"
else
    echo -e "${RED}✗${NC} Authentication tests failed"
    echo "$AUTH_RESULT"
    exit 1
fi
echo ""

# Generate coverage report (if reportgenerator is installed)
echo -e "${YELLOW}[6/7]${NC} Generating code coverage report..."
if command -v reportgenerator &> /dev/null; then
    reportgenerator \
        -reports:"./TestResults/**/coverage.cobertura.xml" \
        -targetdir:"./TestResults/CoverageReport" \
        -reporttypes:Html 2>&1 | tail -n 3

    echo -e "${GREEN}✓${NC} Coverage report generated"
    echo "   View at: ./TestResults/CoverageReport/index.html"
else
    echo -e "${YELLOW}⚠${NC}  ReportGenerator not installed (skipping coverage report)"
    echo "   Install with: dotnet tool install -g dotnet-reportgenerator-globaltool"
fi
echo ""

# Summary
echo -e "${YELLOW}[7/7]${NC} Test Summary"
echo -e "${BLUE}================================================${NC}"

# Count test results
TOTAL_TESTS=$(echo "$RFC_RESULT" | grep -oP 'Passed: \K\d+' || echo "0")
echo -e "Total Tests:        ${GREEN}${TOTAL_TESTS}${NC}"
echo -e "RFC Compliance:     ${GREEN}✓ PASS${NC}"
echo -e "Authentication:     ${GREEN}✓ PASS${NC}"
echo -e "Build Status:       ${GREEN}✓ SUCCESS${NC}"

# Check for coverage file
if [ -f "./TestResults/"*"/coverage.cobertura.xml" ]; then
    COVERAGE=$(grep -oP 'line-rate="\K[0-9.]+' ./TestResults/*/coverage.cobertura.xml | head -n 1)
    COVERAGE_PCT=$(echo "$COVERAGE * 100" | bc -l | xargs printf "%.1f")

    if (( $(echo "$COVERAGE_PCT >= 95" | bc -l) )); then
        echo -e "Code Coverage:      ${GREEN}${COVERAGE_PCT}%${NC}"
    elif (( $(echo "$COVERAGE_PCT >= 80" | bc -l) )); then
        echo -e "Code Coverage:      ${YELLOW}${COVERAGE_PCT}%${NC} (target: 95%)"
    else
        echo -e "Code Coverage:      ${RED}${COVERAGE_PCT}%${NC} (target: 95%)"
    fi
fi

echo -e "${BLUE}================================================${NC}"
echo ""
echo -e "${GREEN}✓ AES-CCM implementation validated successfully!${NC}"
echo ""
echo "Next steps:"
echo "  1. Review coverage report (if generated)"
echo "  2. Run performance benchmarks (optional)"
echo "  3. Create pull request"
echo "  4. Continue with Phase 3C (AES-SIV, Rabbit, etc.)"
echo ""

exit 0
