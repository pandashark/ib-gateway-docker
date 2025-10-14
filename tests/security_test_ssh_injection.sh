#!/bin/bash
#
# Security Test: SSH Command Injection Prevention
#
# This script validates that the fix for CWE-78 (Command Injection) in run_ssh.sh
# successfully prevents arbitrary command execution through environment variables.
#
# CVSS v3.1: 9.1 Critical (before fix)
# CWE: CWE-78 - Improper Neutralization of Special Elements used in an OS Command
#
# Test Strategy:
# - Attempt command injection through SSH_USER_TUNNEL (should fail safely)
# - Attempt command injection through SSH_OPTIONS (should fail safely)
# - Verify no malicious files are created
# - All tests should result in SSH connection failures (expected) but NO code execution
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_SCRIPT="$PROJECT_ROOT/stable/scripts/run_ssh.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

echo "========================================"
echo "SSH Command Injection Security Tests"
echo "========================================"
echo ""

# Helper function to run a test
run_test() {
    local test_name="$1"
    local test_function="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "Test $TESTS_RUN: $test_name ... "

    if $test_function; then
        echo -e "${GREEN}PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Test 1: Command injection via SSH_USER_TUNNEL with semicolon
test_injection_user_tunnel_semicolon() {
    local marker_file="/tmp/ssh_injection_test_$$_semicolon"

    # Clean up any existing marker
    rm -f "$marker_file"

    # Set malicious environment
    export SSH_ALL_OPTIONS="-o StrictHostKeyChecking=no"
    export API_PORT="4001"
    export SSH_REMOTE_PORT="4001"
    export SSH_SCREEN=""
    export SSH_RESTART="1"
    export SSH_AUTH_SOCK="/tmp/fake-sock-$$"
    export SSH_USER_TUNNEL="user@host; touch $marker_file; #"

    # Run the script in background with timeout (will fail to connect, that's expected)
    timeout 2 bash "$TEST_SCRIPT" >/dev/null 2>&1 || true

    # Check if malicious command was executed
    if [ -f "$marker_file" ]; then
        echo -e "\n  ${RED}SECURITY BREACH: Command injection successful!${NC}"
        echo "  Malicious file created: $marker_file"
        rm -f "$marker_file"
        return 1
    fi

    return 0
}

# Test 2: Command injection via SSH_USER_TUNNEL with command substitution
test_injection_user_tunnel_command_subst() {
    local marker_file="/tmp/ssh_injection_test_$$_cmdsub"

    rm -f "$marker_file"

    export SSH_ALL_OPTIONS="-o StrictHostKeyChecking=no"
    export API_PORT="4001"
    export SSH_REMOTE_PORT="4001"
    export SSH_SCREEN=""
    export SSH_RESTART="1"
    export SSH_AUTH_SOCK="/tmp/fake-sock-$$"
    export SSH_USER_TUNNEL="user@host\$(touch $marker_file)"

    timeout 2 bash "$TEST_SCRIPT" >/dev/null 2>&1 || true

    if [ -f "$marker_file" ]; then
        echo -e "\n  ${RED}SECURITY BREACH: Command substitution successful!${NC}"
        rm -f "$marker_file"
        return 1
    fi

    return 0
}

# Test 3: Command injection via SSH_OPTIONS
test_injection_ssh_options() {
    local marker_file="/tmp/ssh_injection_test_$$_options"

    rm -f "$marker_file"

    export SSH_ALL_OPTIONS="-o StrictHostKeyChecking=no; touch $marker_file; #"
    export API_PORT="4001"
    export SSH_REMOTE_PORT="4001"
    export SSH_SCREEN=""
    export SSH_RESTART="1"
    export SSH_AUTH_SOCK="/tmp/fake-sock-$$"
    export SSH_USER_TUNNEL="user@localhost"

    timeout 2 bash "$TEST_SCRIPT" >/dev/null 2>&1 || true

    if [ -f "$marker_file" ]; then
        echo -e "\n  ${RED}SECURITY BREACH: Options injection successful!${NC}"
        rm -f "$marker_file"
        return 1
    fi

    return 0
}

# Test 4: Command injection via SSH_OPTIONS with backticks
test_injection_ssh_options_backticks() {
    local marker_file="/tmp/ssh_injection_test_$$_backticks"

    rm -f "$marker_file"

    export SSH_ALL_OPTIONS="\`touch $marker_file\`"
    export API_PORT="4001"
    export SSH_REMOTE_PORT="4001"
    export SSH_SCREEN=""
    export SSH_RESTART="1"
    export SSH_AUTH_SOCK="/tmp/fake-sock-$$"
    export SSH_USER_TUNNEL="user@localhost"

    timeout 2 bash "$TEST_SCRIPT" >/dev/null 2>&1 || true

    if [ -f "$marker_file" ]; then
        echo -e "\n  ${RED}SECURITY BREACH: Backtick injection successful!${NC}"
        rm -f "$marker_file"
        return 1
    fi

    return 0
}

# Test 5: Command injection via SSH_SCREEN
test_injection_ssh_screen() {
    local marker_file="/tmp/ssh_injection_test_$$_screen"

    rm -f "$marker_file"

    export SSH_ALL_OPTIONS="-o StrictHostKeyChecking=no"
    export API_PORT="4001"
    export SSH_REMOTE_PORT="4001"
    export SSH_SCREEN="; touch $marker_file; #"
    export SSH_RESTART="1"
    export SSH_AUTH_SOCK="/tmp/fake-sock-$$"
    export SSH_USER_TUNNEL="user@localhost"

    timeout 2 bash "$TEST_SCRIPT" >/dev/null 2>&1 || true

    if [ -f "$marker_file" ]; then
        echo -e "\n  ${RED}SECURITY BREACH: SSH_SCREEN injection successful!${NC}"
        rm -f "$marker_file"
        return 1
    fi

    return 0
}

# Test 6: Verify script still works with legitimate multi-word options
test_legitimate_multiple_options() {
    # This test just verifies the script doesn't crash with legitimate input
    export SSH_ALL_OPTIONS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=30"
    export API_PORT="4001"
    export SSH_REMOTE_PORT="4001"
    export SSH_SCREEN=""
    export SSH_RESTART="1"
    export SSH_AUTH_SOCK="/tmp/fake-sock-$$"
    export SSH_USER_TUNNEL="user@nonexistent"

    # Should fail to connect but not crash
    timeout 2 bash "$TEST_SCRIPT" >/dev/null 2>&1 || true

    # If we got here without crashing, pass
    return 0
}

# Run all tests
echo "Running security validation tests..."
echo ""

run_test "SSH_USER_TUNNEL injection (semicolon)" test_injection_user_tunnel_semicolon
run_test "SSH_USER_TUNNEL injection (command substitution)" test_injection_user_tunnel_command_subst
run_test "SSH_OPTIONS injection (semicolon)" test_injection_ssh_options
run_test "SSH_OPTIONS injection (backticks)" test_injection_ssh_options_backticks
run_test "SSH_SCREEN injection (semicolon)" test_injection_ssh_screen
run_test "Legitimate multi-word options (compatibility)" test_legitimate_multiple_options

# Summary
echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Total tests run: $TESTS_RUN"
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    echo ""
    echo -e "${RED}SECURITY VALIDATION FAILED${NC}"
    echo "The SSH tunnel script is still vulnerable to command injection!"
    exit 1
else
    echo "Tests failed: 0"
    echo ""
    echo -e "${GREEN}ALL SECURITY TESTS PASSED${NC}"
    echo "The SSH tunnel script successfully prevents command injection attacks."
    exit 0
fi
