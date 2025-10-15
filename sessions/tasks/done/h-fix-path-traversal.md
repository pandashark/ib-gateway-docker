---
task: h-fix-path-traversal
branch: fix/path-traversal
status: completed
created: 2025-10-14
started: 2025-10-14
completed: 2025-10-14
modules: [image-files/scripts, stable/scripts, latest/scripts]
---

# Add Path Traversal Validation for TWS_SETTINGS_PATH

## Problem/Goal
The `TWS_SETTINGS_PATH` environment variable is used to create directories without validation against path traversal attacks. If a user provides a path like `/home/user/../../etc/malicious`, it could create security risks by allowing directory creation outside the intended scope.

**Location**: `stable/scripts/common.sh:23`, `latest/scripts/common.sh:23`, `image-files/scripts/common.sh:23`

**Current code**:
```bash
mkdir "$TWS_SETTINGS_PATH"
```

## Success Criteria
- [x] Add validation to reject paths containing `..` (path traversal)
- [x] Add `-p` flag to mkdir for parent directory creation (defensive)
- [x] Apply fix to all three copies: stable/, latest/, image-files/
- [x] Test with valid paths (should work)
- [x] Test with malicious paths containing `..` (should fail with error)
- [x] Ensure error message is clear and helpful

## Context Files
- @stable/scripts/common.sh:20-30
- @latest/scripts/common.sh:20-30
- @image-files/scripts/common.sh:20-30
- @stable/scripts/common.sh:45-61  # file_env function shows good validation pattern

## User Notes
Path traversal is a common security vulnerability. This fix prevents users (malicious or misconfigured) from creating directories outside the container's intended filesystem areas.

Recommended fix pattern:
```bash
if [[ "$TWS_SETTINGS_PATH" =~ \.\. ]]; then
    echo ".> Error: TWS_SETTINGS_PATH contains invalid path traversal"
    exit 1
fi
mkdir -p "$TWS_SETTINGS_PATH"
```

## Context Manifest

### How the TWS_SETTINGS_PATH System Currently Works

The IB Gateway Docker project provides a way for users to preserve TWS (Trader Workstation) and IB Gateway settings across container restarts by mounting a volume at a custom path. This is controlled via the `TWS_SETTINGS_PATH` environment variable. Understanding this feature requires tracing the complete startup flow from container launch through settings application.

**Container Initialization and Script Architecture:**

When the Docker container starts, the entry point is `/home/ibgateway/scripts/run.sh` (defined in Dockerfile CMD at line 107). This is the orchestrator script that sets up the complete environment. The script sources `/home/ibgateway/scripts/common.sh` at line 12, which provides all shared functions used across the initialization process. The `common.sh` file is critical because it contains the vulnerable code we need to fix - specifically the `apply_settings()` function.

The container runs as user `ibgateway` (UID 1000 by default, configurable via USER_ID build arg) in a non-root security context. The home directory is `/home/ibgateway` and the default TWS installation path is `/home/ibgateway/Jts` (set as `TWS_PATH` environment variable in Dockerfile line 76).

**Settings Path Configuration Flow (apply_settings function in common.sh:6-41):**

The `apply_settings()` function is called early in the startup sequence (from run.sh line 103, within the `start_process()` function). This function's job is to:

1. Apply environment variables to IBC config files (IB Controller - the automation tool that logs into TWS/Gateway)
2. Determine where TWS should store its settings files
3. Create the settings directory if it doesn't exist (THIS IS WHERE THE VULNERABILITY LIVES)
4. Set up the jts.ini configuration file with timezone settings

Here's the detailed flow when a user provides `TWS_SETTINGS_PATH`:

**Step 1 - Environment Variable Handling (lines 8-16):**

The function first checks if `CUSTOM_CONFIG != yes`. If users are providing their own config files, this function exits early and doesn't touch anything. Assuming normal operation, it proceeds to handle the TWS password using the `file_env` pattern.

The `file_env` function (defined at common.sh:47-63) is a security pattern that supports Docker secrets. It checks for both `TWS_PASSWORD` and `TWS_PASSWORD_FILE`, loads the password from the appropriate source, exports it as an environment variable, then uses `envsubst` to replace placeholders in the IBC config template. After substitution, the password is immediately unset via `unset_env` to prevent credential leakage. The resulting config file is chmod 600 to ensure only the container user can read it.

**Step 2 - Settings Directory Determination (lines 18-30):**

This is the critical section containing the vulnerability. The logic flow is:

```bash
if [ -n "$TWS_SETTINGS_PATH" ]; then
    echo ".> Settings directory set to: $TWS_SETTINGS_PATH"
    _JTS_PATH=$TWS_SETTINGS_PATH
    if [ ! -d "$TWS_SETTINGS_PATH" ]; then
        # if TWS_SETTINGS_PATH does not exists, create it
        echo ".> Creating directory: $TWS_SETTINGS_PATH"
        mkdir "$TWS_SETTINGS_PATH"  # LINE 25 - VULNERABLE
    fi
else
    echo ".> Settings directory NOT set, defaulting to: $TWS_PATH"
    _JTS_PATH=$TWS_PATH
fi
```

When `TWS_SETTINGS_PATH` is provided by the user (via docker-compose.yml environment variables), the code:
- Sets an internal variable `_JTS_PATH` to this user-provided path
- Checks if the directory exists with `[ ! -d "$TWS_SETTINGS_PATH" ]`
- If it doesn't exist, calls `mkdir "$TWS_SETTINGS_PATH"` WITHOUT ANY VALIDATION

**THE VULNERABILITY - Path Traversal (CWE-22):**

The `mkdir` command at line 25 (and identical lines in latest/common.sh:25 and image-files/common.sh:25) accepts the user-provided path without validating that it doesn't contain path traversal sequences like `..` (parent directory references).

Attack scenarios:
```bash
# Scenario 1: Escape container home directory
TWS_SETTINGS_PATH="/home/ibgateway/../../tmp/malicious"
# mkdir creates: /tmp/malicious (outside intended /home/ibgateway scope)

# Scenario 2: Target system directories
TWS_SETTINGS_PATH="/home/ibgateway/../../../etc/pwned"
# mkdir attempts: /etc/pwned (will fail due to permissions, but demonstrates vulnerability)

# Scenario 3: Overwrite existing paths
TWS_SETTINGS_PATH="/home/ibgateway/Jts/../.ssh"
# Resolves to: /home/ibgateway/.ssh (could interfere with SSH keys)
```

While the container runs as non-root (UID 1000), limiting damage potential, successful path traversal could:
- Create directories in unintended locations within the user's writable space
- Interfere with other container functionality (SSH keys, IBC configs, TWS installation)
- Confuse volume mounts if the traversed path happens to overlap with mount points
- Violate principle of least privilege and defense-in-depth

**Step 3 - jts.ini Configuration (lines 31-37):**

After determining the settings path, the function checks if `jts.ini` already exists in the target directory. The `jts.ini` file controls TWS timezone settings and other runtime configuration. If the file doesn't exist (first run or fresh settings directory), the script uses `envsubst` to populate it from a template (`/home/ibgateway/Jts/jts.ini.tmpl`), replacing `${TIME_ZONE}` with the user's configured timezone.

This is why `TWS_SETTINGS_PATH` is important for persistent settings - if you mount a volume here, your `jts.ini` customizations survive container restarts. Without validation, however, an attacker could potentially create this file in unintended locations.

**Integration with IBC (IB Controller):**

The `_JTS_PATH` variable set by this function is later passed to IBC (the automation tool) when starting the gateway. The IBC start command (in run.sh:88-92) includes:

```bash
"${IBC_PATH}/scripts/ibcstart.sh" "${TWS_MAJOR_VRSN}" -g \
    "--tws-path=${TWS_PATH}" \
    "--ibc-path=${IBC_PATH}" "--ibc-ini=${IBC_INI}" \
    "--on2fatimeout=${TWOFA_TIMEOUT_ACTION}" \
    "--tws-settings-path=${TWS_SETTINGS_PATH:-}"
```

The `--tws-settings-path` parameter tells IBC where to find TWS configuration files. If an attacker has traversed to an arbitrary path, IBC will look for settings there, potentially causing runtime failures or unexpected behavior.

**Dual Mode Complexity (TRADING_MODE=both):**

The situation becomes more complex when `TRADING_MODE=both` is used (runs both live and paper trading instances simultaneously). In this case (run.sh:139-148), the code modifies `TWS_SETTINGS_PATH` by appending `_live` and `_paper` suffixes:

```bash
if [ -n "$TWS_SETTINGS_PATH" ]; then
    _TWS_SETTINGS_PATH="${TWS_SETTINGS_PATH}"
    export _TWS_SETTINGS_PATH
    TWS_SETTINGS_PATH="${_TWS_SETTINGS_PATH}_${TRADING_MODE}"
fi
```

This means if a user sets `TWS_SETTINGS_PATH=/config/settings`, the code creates:
- `/config/settings_live` (for live trading)
- `/config/settings_paper` (for paper trading)

**Critical insight**: The path traversal vulnerability affects BOTH paths in dual mode. An attacker could use:
```bash
TWS_SETTINGS_PATH="/home/ibgateway/../tmp/evil"
# Results in mkdir for:
#   /tmp/evil_live
#   /tmp/evil_paper
```

**Typical User Configuration:**

From the README.md and docker-compose.yml examples, typical legitimate usage looks like:

```yaml
environment:
  TWS_SETTINGS_PATH: /home/ibgateway/Jts  # For IB Gateway
  # OR
  TWS_SETTINGS_PATH: /config/tws_settings  # For TWS image
volumes:
  - ./tws_settings:/home/ibgateway/Jts
  # OR
  - ./config:/config
```

Users mount a host directory to persist settings across container restarts. The environment variable tells the container where that mount point is. The README (lines 287-310) specifically recommends this pattern for preserving IB Gateway configuration.

**Why This Matters - Defense in Depth:**

Even though the container is non-root, path traversal violations are a security anti-pattern because:

1. **Principle of Least Surprise**: Users expect paths to be validated and contained
2. **Future-proofing**: Container permissions might change, image might be run in different contexts
3. **CWE-22 Compliance**: Industry-standard security frameworks classify path traversal as a vulnerability regardless of impact severity
4. **Recent Security Focus**: This codebase recently fixed CWE-78 (command injection in SSH) and added strict error handling. Path validation fits this security hardening trend.
5. **Audit Requirements**: Financial trading platforms (IB Gateway's use case) often face compliance audits that flag path traversal issues

**Error Handling Context:**

A recent fix (commit 48322ac) added strict error handling to common.sh by ensuring `set -Eeo pipefail` is active at line 4. This means:
- `set -e`: Exit immediately if any command fails
- `set -E`: ERR trap is inherited by shell functions
- `set -o pipefail`: Pipelines fail if any command in the pipe fails

This fail-fast behavior is critical for security. If the mkdir command fails (wrong permissions, disk full, etc.), the entire container startup aborts rather than silently continuing with broken configuration. Our fix should maintain this behavior - validation should exit with error code 1 on invalid input, causing the container to stop.

### What Needs to Connect: Path Validation Implementation

**The Fix - Add Validation Before mkdir:**

We need to add validation that rejects paths containing `..` before the mkdir operation at line 25 (and equivalents in latest/ and image-files/). The validation should:

1. Check if `TWS_SETTINGS_PATH` contains the literal string `..`
2. Display a clear, actionable error message
3. Exit with code 1 to halt container startup (leveraging existing `set -e` behavior)
4. Preserve all existing functionality for valid paths

**Security Pattern to Follow:**

The codebase has established patterns for validation. Looking at common.sh:75-114, we see the `set_ports()` function validates `TRADING_MODE` values:

```bash
if [ "$TRADING_MODE" = "paper" ]; then
    # valid - set paper ports
elif [ "$TRADING_MODE" = "live" ]; then
    # valid - set live ports
else
    # invalid option
    echo ".> Invalid TRADING_MODE: $TRADING_MODE"
    exit 1
fi
```

We should follow the same pattern: test for invalid input, echo an error message prefixed with `.>` (the established logging convention), and exit 1.

**Error Message Design:**

The error message should:
- Be clear about what's wrong ("contains invalid path traversal")
- Help users fix it (implicit - they'll see the .. in their path and remove it)
- Match the existing message style (`.>` prefix, concise, informative)

Example from the task recommendation:
```bash
if [[ "$TWS_SETTINGS_PATH" =~ \.\. ]]; then
    echo ".> Error: TWS_SETTINGS_PATH contains invalid path traversal"
    exit 1
fi
```

This uses bash's `=~` regex operator to match the literal string `..` anywhere in the path. The `[[` double-bracket test is preferred over `[` because it doesn't require quoting the regex and has better error handling.

**Defensive mkdir Flag:**

The task also recommends adding `-p` flag to mkdir. This is a defense-in-depth measure:

```bash
mkdir -p "$TWS_SETTINGS_PATH"
```

The `-p` flag:
- Creates parent directories if they don't exist (defensive - handles paths like `/home/ibgateway/custom/settings`)
- Succeeds silently if the directory already exists (idempotent behavior)
- Is a standard practice in initialization scripts

However, it's important to note this does NOT prevent path traversal - it just makes mkdir more robust. The validation check is still required.

**Why Validation BEFORE mkdir:**

The check must happen BEFORE the mkdir call, not after:

```bash
# CORRECT ORDER:
if [[ "$TWS_SETTINGS_PATH" =~ \.\. ]]; then
    echo ".> Error: TWS_SETTINGS_PATH contains invalid path traversal"
    exit 1
fi
mkdir -p "$TWS_SETTINGS_PATH"

# WRONG - mkdir happens before check (too late):
mkdir -p "$TWS_SETTINGS_PATH"
if [[ "$TWS_SETTINGS_PATH" =~ \.\. ]]; then
    # Directory already created!
```

This ensures we never execute the dangerous operation on invalid input.

**Insertion Point:**

The validation should be inserted in the apply_settings function immediately after the "Settings directory set to" log line and before the directory existence check. The logical flow becomes:

```bash
if [ -n "$TWS_SETTINGS_PATH" ]; then
    echo ".> Settings directory set to: $TWS_SETTINGS_PATH"

    # NEW: Validation block
    if [[ "$TWS_SETTINGS_PATH" =~ \.\. ]]; then
        echo ".> Error: TWS_SETTINGS_PATH contains invalid path traversal"
        exit 1
    fi

    _JTS_PATH=$TWS_SETTINGS_PATH
    if [ ! -d "$TWS_SETTINGS_PATH" ]; then
        echo ".> Creating directory: $TWS_SETTINGS_PATH"
        mkdir -p "$TWS_SETTINGS_PATH"  # Added -p flag
    fi
```

This placement ensures:
- User sees their configured path in the log before validation fails (helpful for debugging)
- Validation happens before any filesystem operations
- The variable assignment to `_JTS_PATH` only happens for valid paths
- Existing logic flow is minimally disrupted

**Impact on Dual Mode:**

In dual mode (TRADING_MODE=both), the validation will run twice:
1. First call to `start_process()` for live mode (TWS_SETTINGS_PATH with `_live` suffix)
2. Second call to `start_process()` for paper mode (TWS_SETTINGS_PATH with `_paper` suffix)

This is correct behavior - both paths should be validated. If the base path contains `..`, both derived paths will also be invalid, and the container will fail on the first (live) startup.

**Testing Strategy:**

After implementation, test cases should verify:

1. **Valid absolute path**: `TWS_SETTINGS_PATH=/home/ibgateway/custom_settings` → SUCCESS, directory created
2. **Valid absolute path with subdirectories**: `TWS_SETTINGS_PATH=/home/ibgateway/deep/nested/path` → SUCCESS, all parents created (via -p flag)
3. **Path with double-dot traversal**: `TWS_SETTINGS_PATH=/home/ibgateway/../malicious` → FAIL, error message shown, container exits
4. **Path with traversal mid-path**: `TWS_SETTINGS_PATH=/home/../tmp/evil` → FAIL, error message shown
5. **Path with multiple traversals**: `TWS_SETTINGS_PATH=/home/ibgateway/../../etc/pwned` → FAIL
6. **Empty path**: `TWS_SETTINGS_PATH=` → SUCCESS, falls through to else branch (uses default TWS_PATH)
7. **Dual mode with traversal**: `TRADING_MODE=both TWS_SETTINGS_PATH=/tmp/../evil` → FAIL on first startup
8. **Existing directory (idempotent)**: Run container twice with same valid path → Both succeed

**Shellcheck Compliance:**

After modification, all three common.sh files should pass shellcheck without errors:

```bash
shellcheck -x stable/scripts/common.sh
shellcheck -x latest/scripts/common.sh
shellcheck -x image-files/scripts/common.sh
```

The regex test `[[ "$TWS_SETTINGS_PATH" =~ \.\. ]]` is shellcheck-compliant and won't generate warnings.

**Backward Compatibility:**

This change is backward compatible for all legitimate use cases. No valid configuration would intentionally use `..` in TWS_SETTINGS_PATH because:
- Docker volumes are mounted at absolute paths
- IBC expects absolute paths for --tws-settings-path
- Relative paths don't make sense in a containerized environment where working directory is fixed

Users with malformed configurations (unlikely) will get a clear error message and can fix their docker-compose.yml.

### Technical Reference Details

#### File Locations and Line Numbers

**Files requiring changes:**
- `/home/pandashark/projects/ib-gateway-docker/stable/scripts/common.sh:19-26` (apply_settings function)
- `/home/pandashark/projects/ib-gateway-docker/latest/scripts/common.sh:19-26` (apply_settings function)
- `/home/pandashark/projects/ib-gateway-docker/image-files/scripts/common.sh:19-26` (apply_settings function)

**Specific line numbers:**
- Insertion point for validation: After line 20 (echo statement), before line 21 (_JTS_PATH assignment)
- Line to modify: Line 25 (mkdir command) - add `-p` flag

#### Function Signatures

**apply_settings()**
- Location: common.sh:6-41
- Purpose: Apply environment variables to IBC config and set up TWS settings directory
- Called by: start_process() in run.sh:103
- Dependencies: file_env(), unset_env(), envsubst command
- Environment inputs: CUSTOM_CONFIG, TWS_PASSWORD, TWS_SETTINGS_PATH, TIME_ZONE
- Filesystem outputs: ${IBC_INI} (config file), ${TWS_SETTINGS_PATH} (directory), ${_JTS_PATH}/${TWS_INI} (jts.ini)
- Side effects: Creates directories, writes config files, modifies file permissions (chmod 600)

#### Environment Variables

**TWS_SETTINGS_PATH**
- Type: String (filesystem path)
- Default: Empty (falls back to TWS_PATH which is `/home/ibgateway/Jts`)
- Configurable via: docker-compose.yml environment section
- Used by: apply_settings(), IBC start command (--tws-settings-path parameter)
- Expected format: Absolute path (e.g., `/home/ibgateway/Jts`, `/config/tws_settings`)
- Validation: None (currently) - this is what we're fixing
- In dual mode: Modified to append `_live` or `_paper` suffix

**Related Environment Variables:**
- `TWS_PATH`: Default TWS installation directory (`/home/ibgateway/Jts`), set in Dockerfile:76
- `TWS_INI`: Filename for jts.ini (`jts.ini`), set in Dockerfile:77
- `TWS_INI_TMPL`: Template filename (`jts.ini.tmpl`), set in Dockerfile:78
- `IBC_INI`: IBC config file path (`/home/ibgateway/ibc/config.ini`), set in Dockerfile:80
- `IBC_INI_TMPL`: IBC template path (`/home/ibgateway/ibc/config.ini.tmpl`), set in Dockerfile:81
- `CUSTOM_CONFIG`: If set to `yes`, skips apply_settings entirely (user provides own configs)
- `TIME_ZONE`: Timezone for jts.ini (e.g., `America/New_York`, `Europe/Zurich`), default `Etc/UTC`

#### Docker Context

**Container User:**
- Username: `ibgateway`
- UID: 1000 (default, configurable via USER_ID build arg)
- GID: 1000 (default, configurable via USER_GID build arg)
- Home: `/home/ibgateway`
- Shell: `/bin/bash`

**File Permissions:**
- IBC config (config.ini): 600 (owner read/write only) - set at common.sh:16
- SSH keys (if used): 600 (documented in README)
- Created directories: Default umask (typically 755 or 775)

**Volume Mount Patterns (from README and docker-compose.yml):**
```yaml
# IB Gateway settings persistence
volumes:
  - ./tws_settings:/home/ibgateway/Jts
environment:
  TWS_SETTINGS_PATH: /home/ibgateway/Jts

# TWS (tws-rdesktop) settings persistence
volumes:
  - ./config:/config
environment:
  TWS_SETTINGS_PATH: /config/tws_settings
```

#### Validation Pattern Implementation

**Recommended regex-based validation:**
```bash
if [[ "$TWS_SETTINGS_PATH" =~ \.\. ]]; then
    echo ".> Error: TWS_SETTINGS_PATH contains invalid path traversal"
    exit 1
fi
```

**Why this pattern:**
- `[[` - Bash conditional expression (preferred over `[` for regex)
- `=~` - Regex match operator
- `\.\.` - Escaped dots match literal ".." string (backslash escapes special regex meaning of `.`)
- Exit code 1 triggers set -e behavior (container stops)

**Alternative validation approaches (not recommended):**
```bash
# Using grep (unnecessary external process)
echo "$TWS_SETTINGS_PATH" | grep -q '\.\.' && exit 1

# Using case statement (more verbose)
case "$TWS_SETTINGS_PATH" in
  *..*) echo "Error"; exit 1 ;;
esac

# Using string substitution (less clear)
[[ "${TWS_SETTINGS_PATH//../}" != "$TWS_SETTINGS_PATH" ]] && exit 1
```

The `[[...=~...]]` pattern is clearest and most idiomatic for bash validation.

#### Related Security Fixes (Context for This Fix)

**Recent security improvements in this codebase:**

1. **CWE-78 Command Injection** (commit ce2847e, 2025-10-14)
   - Fixed: run_ssh.sh removed `bash -c` wrapper to prevent injection
   - CVSS: 9.1 Critical
   - Pattern: Direct execution instead of secondary shell parsing

2. **CWE-200 Information Exposure** (commit 08ae2f4, 2025-10-14)
   - Fixed: VNC password no longer visible in process list
   - Pattern: Temporary file with secure permissions instead of command-line arg

3. **Strict Error Handling** (commit 48322ac, 2025-10-14)
   - Fixed: Added `set -Eeo pipefail` to common.sh
   - Impact: Configuration failures now halt startup instead of silently continuing

**This fix continues the security hardening trend:**
- CWE-22 Path Traversal (this task)
- Pattern: Input validation before filesystem operations
- Defense-in-depth: Complements existing non-root container, file permissions

## Work Log
- [2025-10-14] Task created from code review findings
- [2025-10-14] Context manifest created with comprehensive analysis of TWS_SETTINGS_PATH flow, dual-mode implications, and validation strategy
- [2025-10-14] Implementation complete: Added path traversal validation to all three common.sh files (stable, latest, image-files)
  - Inserted validation block at lines 22-26: Regex check for `..` in TWS_SETTINGS_PATH
  - Added `-p` flag to mkdir at line 32 for defense-in-depth
  - All files pass shellcheck with zero errors
- [2025-10-14] Testing complete: Validated implementation with comprehensive test suite
  - Unit tests: 16/16 passed (valid paths, malicious paths, edge cases)
  - Integration tests: All passed (validation block present, correct placement, error handling)
  - Changes are identical across all three files
- [2025-10-14] Ready for code review and commit
