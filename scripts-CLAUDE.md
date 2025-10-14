# IB Gateway Docker - Scripts Module

## Purpose
Container startup and runtime scripts that initialize IB Gateway/TWS, manage port forwarding, and provide secure SSH tunneling for remote access.

## Architecture Overview
The scripts system orchestrates container initialization through a startup sequence that configures X11, port forwarding, SSH tunnels, and launches IB Gateway/TWS with IBC control. All three version directories (stable/, latest/, image-files/) contain identical script implementations that are copied into their respective Docker images.

## Module Structure
- `stable/scripts/` - Scripts for stable IB Gateway version (10.37.1l)
  - `run.sh:1-122` - Main entry point, orchestrates startup sequence
  - `common.sh:1-249` - Shared functions for all startup operations
  - `run_ssh.sh:1-24` - SSH tunnel maintenance loop (SECURITY CRITICAL)
  - `run_socat.sh:1-16` - Port forwarding via socat
- `latest/scripts/` - Scripts for latest IB Gateway version (10.40.1c)
  - Identical structure to stable/scripts/
- `image-files/scripts/` - Template scripts for builds
  - Identical structure to stable/scripts/
- `tests/` - Security and functionality tests
  - `security_test_ssh_injection.sh:1-238` - Command injection prevention tests

## Key Components

### Startup Orchestration (run.sh)
- `start_xvfb:47-54` - Initializes X virtual framebuffer
- `start_vnc:56-76` - Starts VNC server with secure password handling (SECURITY CRITICAL)
- `start_IBC:78-97` - Launches IB Gateway/TWS with IBC control
- `start_process:99-108` - Configures ports, applies settings, starts forwarding
- Main sequence: Lines 114-123 (Xvfb → SSH setup → Java heap → VNC → IBC)

### Configuration Functions (common.sh) - CRITICAL ERROR HANDLING
- `common.sh:4` - **`set -Eeo pipefail`** (added 2025-10-14) - All functions fail loudly on errors
- `apply_settings:6-41` - Writes credentials to IBC config, sets file permissions
- `set_ports:75-115` - Determines API/SOCAT ports by trading mode (paper/live)
- `set_java_heap:117-127` - Modifies JVM memory settings via sed
- `file_env:47-63` - Loads secrets from Docker secret files
- `unset_env:67-73` - Cleans up secret variables after use
- Why strict mode matters: Silent failures in these functions could expose credentials, misconfigure ports, or disable security features

### SSH Tunnel System (common.sh)
- `setup_ssh:150-196` - Builds SSH options, starts ssh-agent, loads keys
- `start_ssh:198-232` - Validates environment and launches run_ssh.sh
- `port_forwarding:127-148` - Routes between socat and SSH tunnel modes

### VNC Server Startup (run.sh:start_vnc) - SECURITY CRITICAL
- `run.sh:56-76` - VNC server initialization with secure credential handling
- **Fixed CWE-200 (Information Exposure)** - VNC password no longer visible in process list
- Uses temporary password file with 600 permissions instead of command-line argument
- Pattern: Create temp file → Write password → Start x11vnc with -passwdfile → Cleanup
- File cleanup: 1-second delay for x11vnc to read, then rm -f
- Follows same secure pattern as file_env/unset_env in common.sh

### SSH Tunnel Loop (run_ssh.sh) - SECURITY CRITICAL
- Lines 11-23: Infinite loop maintaining SSH remote port forward
- Line 20: **Direct ssh execution prevents CWE-78 command injection**
- See SECURITY.md for critical security patterns

### Port Forwarding (run_socat.sh)
- Maps 127.0.0.1:4001/4002 to 0.0.0.0:4003/4004 for external access
- Uses socat for TCP relay without authentication

## Security Considerations

### CRITICAL: VNC Password Exposure Prevention (CWE-200)
The VNC server startup in run.sh was hardened to prevent password exposure in process listings. Previously, the VNC password was passed via x11vnc's `-passwd` command-line argument, making it visible to all users via `ps aux` or `/proc` filesystem.

**Security Fix (2025-10-14):**
- Changed from `-passwd "$VNC_SERVER_PASSWORD"` (visible in ps) to `-passwdfile` (secure file-based)
- Creates temporary password file `/tmp/.vncpass.$$` with 600 permissions (process-specific PID suffix)
- x11vnc reads password from file, preventing command-line exposure
- File cleanup after 1-second delay (allows x11vnc to read before deletion)
- Environment variable cleaned with unset_env after use

**Fixed Files:**
- stable/scripts/run.sh:56-76
- latest/scripts/run.sh:56-76
- image-files/scripts/run.sh:56-76

**Impact:** VNC password only exposed if VNC_SERVER_PASSWORD is set (optional feature, ib-gateway only)

### CRITICAL: Command Injection Prevention (CWE-78)
The SSH tunnel implementation in run_ssh.sh was hardened against command injection vulnerabilities. See `/home/pandashark/projects/ib-gateway-docker/SECURITY.md` for details.

**Key Security Patterns:**
1. **NEVER use `bash -c` wrapper around user-controlled variables**
2. **Quote variables containing user@host strings** (prevents injection through connection target)
3. **Quote port forwarding specifications** (prevents tunnel manipulation)
4. **Intentionally unquote SSH_OPTIONS and SSH_SCREEN** (allows word splitting for multiple arguments)
5. **Validate with shellcheck** on all script changes

**Fixed Files:**
- stable/scripts/run_ssh.sh:20
- latest/scripts/run_ssh.sh:20
- image-files/scripts/run_ssh.sh:20

**Test Suite:**
- tests/security_test_ssh_injection.sh - Validates injection prevention

### Environment Variables (User-Controlled)
| Variable | Risk Level | Usage | Security Measures |
|----------|------------|-------|-------------------|
| `VNC_SERVER_PASSWORD` | HIGH | VNC authentication | Temporary file (600 perms), immediate cleanup, unset after use |
| `SSH_USER_TUNNEL` | HIGH | SSH connection target | Must be quoted in ssh command |
| `SSH_OPTIONS` | HIGH | Additional SSH options | Word splitting required, validated by ssh |
| `SSH_SCREEN` | MEDIUM | VNC/RDP tunnel spec | Word splitting required, validated by ssh |
| `SSH_PASSPHRASE` | NONE | SSH key passphrase | Only used by ssh-add, never in shell expansion |
| `SSH_REMOTE_PORT` | LOW | Numeric port | Validated by ssh |
| `SSH_ALIVE_INTERVAL` | LOW | Numeric timeout | Validated by ssh |

### Defense in Depth
1. Non-root execution (user ibgateway, UID 1000)
2. Secrets via file_env pattern (immediate unset after use)
3. Config files with 600 permissions (IBC config, VNC password file)
4. VNC password in temporary file, not process arguments (prevents ps exposure)
5. SSH key validation before agent loading
6. Shellcheck validation in CI/CD
7. Strict error handling in common.sh prevents silent configuration failures (added 2025-10-14)

## Configuration
All configuration comes from environment variables set in docker-compose.yml:

### SSH Tunnel Configuration
- `SSH_TUNNEL` - "yes" (tunnel only), "both" (tunnel + socat), or unset (socat only)
- `SSH_USER_TUNNEL` - Required: user@server connection string
- `SSH_OPTIONS` - Additional ssh client options
- `SSH_ALIVE_INTERVAL` - ServerAliveInterval (default: 20)
- `SSH_ALIVE_COUNT` - ServerAliveCountMax (default: 3)
- `SSH_PASSPHRASE` or `SSH_PASSPHRASE_FILE` - SSH key passphrase
- `SSH_REMOTE_PORT` - Remote port for tunnel (default: same as API_PORT)
- `SSH_RESTART` - Restart delay in seconds (default: 5)
- `SSH_VNC_PORT` - Optional VNC tunnel remote port
- `SSH_RDP_PORT` - Optional RDP tunnel remote port (TWS only)

### Port Configuration (Set by Code)
- Gateway live: API_PORT=4001, SOCAT_PORT=4003
- Gateway paper: API_PORT=4002, SOCAT_PORT=4004
- TWS live: API_PORT=7496, SOCAT_PORT=7498
- TWS paper: API_PORT=7497, SOCAT_PORT=7499

## Testing
Run security tests before any script modifications:
```bash
cd /home/pandashark/projects/ib-gateway-docker
./tests/security_test_ssh_injection.sh
```

Expected: All 6 tests PASS (injection prevention + legitimate usage)

Run shellcheck validation:
```bash
shellcheck -x stable/scripts/*.sh
shellcheck -x latest/scripts/*.sh
shellcheck -x image-files/scripts/*.sh
```

Expected: 0 errors, 0 warnings

## Key Patterns & Conventions

### Script Synchronization
All three directories (stable/, latest/, image-files/) maintain identical scripts. When modifying scripts:
1. Apply changes to all three directories
2. Verify byte-for-byte consistency where intended
3. Test with both stable and latest images

### Logging Pattern
All scripts use `.>` prefix for status messages to distinguish from IB Gateway/TWS output

### Error Handling
- `set -Eeo pipefail` in all scripts including common.sh (added 2025-10-14) for strict error detection
- Critical: common.sh:4 - Ensures configuration failures halt startup loudly instead of silently
- Explicit validation before starting services (API_PORT, SOCAT_PORT checks)
- Graceful handling of optional features (SSH_PASSPHRASE, VNC, etc.)
- Functions protected: apply_settings(), set_ports(), setup_ssh(), set_java_heap(), port_forwarding(), start_ssh(), start_socat()

### Background Process Management
- Uses `pgrep -f` with specific patterns to detect running processes
- Prevents duplicate socat/ssh instances
- Automatic restart on disconnection via while loops

## Related Documentation
- README.md:365-455 - SSH Tunnel user documentation
- README.md:312-364 - Security considerations for network exposure
- SECURITY.md - Detailed security patterns and vulnerability mitigation
- tests/security_test_ssh_injection.sh - Security validation tests
- sessions/tasks/done/h-fix-command-injection-ssh.md - SSH command injection security fix
- sessions/tasks/done/h-fix-missing-error-handling.md - Strict error handling in common.sh (2025-10-14)
- sessions/tasks/h-fix-vnc-password-exposure.md - VNC password exposure fix (2025-10-14)
