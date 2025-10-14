---
task: h-fix-missing-error-handling
branch: fix/missing-error-handling
status: completed
created: 2025-10-14
started: 2025-10-14
completed: 2025-10-14
modules: [image-files/scripts, stable/scripts, latest/scripts]
---

# Add Strict Error Handling to common.sh

## Problem/Goal
The `common.sh` script lacks bash strict mode (`set -euo pipefail`) while other scripts depend on it. This creates a critical gap where failures in configuration functions like `apply_settings()`, `setup_ssh()`, or `set_ports()` could silently fail, leading to misconfiguration and security issues.

**Location**: `stable/scripts/common.sh`, `latest/scripts/common.sh`, `image-files/scripts/common.sh`

**Issue**: All other scripts use `set -Eeo pipefail` (lines 5 in run.sh, run_ssh.sh, run_socat.sh) but common.sh doesn't.

## Success Criteria
- [x] Add `set -Eeo pipefail` to common.sh (after shebang and shellcheck directives)
- [x] Apply fix to all three copies: stable/, latest/, image-files/
- [x] Verify error handling works correctly (critical functions fail loudly)
- [x] Run shellcheck on modified files to verify no new issues
- [x] Update documentation (scripts-CLAUDE.md, SECURITY.md, .documentation-index.md)

## Context Files
- @stable/scripts/common.sh:1-10
- @latest/scripts/common.sh:1-10
- @image-files/scripts/common.sh:1-10
- @stable/scripts/run.sh:5  # Shows correct pattern
- @stable/scripts/run_ssh.sh:5  # Shows correct pattern

## User Notes
This is critical because silent failures in configuration can lead to security misconfigurations (wrong ports, missing credentials, etc.). The fix is simple but important.

## Context Manifest

### Container Startup and Configuration

This IB Gateway Docker container orchestrates the startup of Interactive Brokers Gateway or TWS in an automated fashion. The container configures trading credentials, network ports, Java VM settings, and SSH tunnels without user interaction.

**The Startup Flow:**

Entry point scripts (`stable/scripts/run.sh` or `stable/tws-scripts/run_tws.sh`) use strict error handling (`set -Eeo pipefail` on line 5). On line 12, they source common.sh: `source "${SCRIPT_PATH}/common.sh"`.

**The Problem:**
common.sh lacked `set -Eeo pipefail` at the top, creating a dangerous execution context gap where configuration failures could be silent.

**Critical Functions in common.sh:**

1. **`apply_settings()`** (lines 4-39): Writes credentials to config.ini, sets file permissions (chmod 600), creates directories
   - Failure risks: Exposed credentials, missing configuration
2. **`file_env()`** (lines 45-61): Loads Docker secrets from files
   - Failure risks: Credential loading failures
3. **`set_ports()`** (lines 73-113): Determines API_PORT and SOCAT_PORT based on trading mode
   - Failure risks: Wrong trading mode (paper vs live), connection failures
4. **`set_java_heap()`** (lines 115-125): Modifies JVM memory settings
   - Failure risks: Out of memory crashes
5. **`setup_ssh()`** (lines 150-196): Configures SSH tunnel, starts ssh-agent, loads keys
   - Failure risks: Silent SSH tunnel failures
6. **`start_ssh()`** (lines 198-232): Launches SSH tunnel
   - Failure risks: No secure remote access
7. **`start_socat()`** (lines 234-249): Launches port forwarding relay
   - Failure risks: API inaccessible
8. **`port_forwarding()`** (lines 127-148): Orchestrates SSH/socat startup
   - Failure risks: Network misconfiguration

**Why This Is Dangerous:**

Without `set -Eeo pipefail` in common.sh, failures in file operations (envsubst, chmod, mkdir, sed) could be silenced. The container would appear to start successfully while being misconfigured:

- **Credential exposure**: chmod 600 failure leaves config files world-readable
- **Wrong trading mode**: Port configuration failure connects to wrong account (paper vs live)
- **Disabled security**: SSH tunnel setup failure exposes raw TCP API
- **Silent failures**: envsubst/mkdir/sed failures lead to missing or corrupt configuration

This container manages real Interactive Brokers trading accounts with real money, making silent failures a critical security risk.

**The Established Pattern:**

All scripts in the codebase use error handling:
- Main entry points: `set -Eeo pipefail` (run.sh, run_tws.sh, start_session.sh)
- Background workers: `set -Eo pipefail` (run_ssh.sh, run_socat.sh)
- **common.sh is the ONLY script lacking error handling**

For common.sh, use `-Eeo pipefail` because:
1. It's a library of functions called during startup (not a background worker)
2. Any function failure should halt the startup process
3. It matches the pattern of scripts that source it (run.sh, run_tws.sh)

### The Fix

Add `set -Eeo pipefail` on line 4 (after shebang and shellcheck directives, before function definitions) to all three common.sh copies.

**Before:**
```bash
#!/bin/bash
# shellcheck disable=SC1091

apply_settings() {
```

**After:**
```bash
#!/bin/bash
# shellcheck disable=SC1091

set -Eeo pipefail

apply_settings() {
```

**Why `-Eeo pipefail`:**
- `-E`: Error traps inherited by functions
- `-e`: Exit immediately on error
- `-o pipefail`: Pipeline failures propagate (critical for envsubst/redirections)

**Safety:** All conditional logic in common.sh uses proper if statements (safe with `-e` flag). Explicit exits already exist at lines 51, 91, 107, 132, 238.

### Technical Reference

**Files Modified:**
- `/home/pandashark/projects/ib-gateway-docker/stable/scripts/common.sh`
- `/home/pandashark/projects/ib-gateway-docker/latest/scripts/common.sh`
- `/home/pandashark/projects/ib-gateway-docker/image-files/scripts/common.sh`

**Scripts That Source common.sh:**
- `stable/scripts/run.sh:12`, `stable/tws-scripts/run_tws.sh:11`, `stable/tws-scripts/start_session.sh:10`
- Same pattern in `latest/` and `image-files/` directories

**Verification:**
```bash
shellcheck -x stable/scripts/common.sh
shellcheck -x latest/scripts/common.sh
shellcheck -x image-files/scripts/common.sh
```
All three return exit code 0 (no errors, no warnings).

## Work Log

### 2025-10-14

#### Completed
- Added `set -Eeo pipefail` to common.sh (all three copies: stable/, latest/, image-files/) on line 4
- Verified shellcheck passes with 0 errors, 0 warnings on all modified files
- Confirmed all conditional logic is safe with `-e` flag (proper if statements)
- Validated bash syntax checks pass on all files
- Verified files remain byte-for-byte identical across directories

#### Decisions
- Chose `-Eeo pipefail` (not just `-e`) to match pattern in run.sh/run_tws.sh which source common.sh
- Positioned on line 4 (after shebang and shellcheck directives, before function definitions)
- Applied to all three directories simultaneously for consistency

#### Discovered
- common.sh was the ONLY script lacking error handling despite containing 7 critical functions
- All other scripts already use `set -Eeo pipefail` or `set -Eo pipefail` consistently
- Explicit exit statements already exist in functions (lines 51, 91, 107, 132, 238)
- No conditional logic conflicts with `-e` flag

#### Security Implications
Configuration failures now halt container startup immediately instead of failing silently, preventing:
- Credential files left world-readable (chmod failure)
- Wrong trading mode connection (port configuration failure)
- Disabled SSH tunnel security (setup failure)
- Missing IBC configuration (template substitution failure)

#### Validation
- Shellcheck: 0 errors, 0 warnings on all 3 files
- Bash syntax: All files pass
- Files modified: 3 (one line insertion per file)
- Functions protected: apply_settings(), set_ports(), setup_ssh(), set_java_heap(), port_forwarding(), start_ssh(), start_socat()

#### Documentation Updated
- scripts-CLAUDE.md: Added error handling section documenting strict mode
- SECURITY.md: Added strict error handling to Defense in Depth Measures
- .documentation-index.md: Updated modified files list and critical security rules
