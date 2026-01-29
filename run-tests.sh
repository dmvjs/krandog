#!/bin/bash

# Test runner for krandog runtime
set -e

RUNTIME="./krandog"
TESTS_DIR="./tests"
PASSED=0
FAILED=0
TOTAL=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Running krandog runtime tests..."
echo ""

# Build the runtime first
echo "Building runtime..."
make clean > /dev/null 2>&1
make > /dev/null 2>&1
echo ""

# Run each test
for test_file in "$TESTS_DIR"/*.js; do
    TOTAL=$((TOTAL + 1))
    test_name=$(basename "$test_file" .js)
    expected_file="$TESTS_DIR/$test_name.expected"

    # Skip if no expected output file
    if [ ! -f "$expected_file" ]; then
        echo -e "${YELLOW}SKIP${NC} $test_name (no expected output)"
        continue
    fi

    # Run the test and capture output
    actual_output=$($RUNTIME "$test_file" 2>&1) || {
        echo -e "${RED}FAIL${NC} $test_name (runtime error)"
        echo "  Runtime crashed or returned non-zero exit code"
        FAILED=$((FAILED + 1))
        continue
    }

    # Compare output
    expected_output=$(cat "$expected_file")

    if [ "$actual_output" = "$expected_output" ]; then
        echo -e "${GREEN}PASS${NC} $test_name"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAIL${NC} $test_name"
        echo "  Expected:"
        echo "$expected_output" | sed 's/^/    /'
        echo "  Actual:"
        echo "$actual_output" | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Results: $PASSED passed, $FAILED failed, $TOTAL total"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi
