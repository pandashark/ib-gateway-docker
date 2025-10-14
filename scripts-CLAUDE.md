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
- `start_xvfb:45-58` - Initializes X virtual framebuffer
- `setup_ssh:107` - Configures SSH tunnel if enabled
- `set_java_heap:108` - Sets JVM memory limits
- `start_vnc:110-111` - Starts VNC server for GUI access
- `start_process:113-122` - Configures ports and launches IB Gateway/TWS

### SSH Tunnel System (common.sh)
- `setup_ssh:150-196` - Builds SSH options, starts ssh-agent, loads keys
- `start_ssh:198-232` - Validates environment and launches run_ssh.sh
- `port_forwarding:127-148` - Routes between socat and SSH tunnel modes

### SSH Tunnel Loop (run_ssh.sh) - SECURITY CRITICAL
- Lines 11-23: Infinite loop maintaining SSH remote port forward
- Line 20: **Direct ssh execution prevents CWE-78 command injection**
- See SECURITY.md for critical security patterns

### Port Forwarding (run_socat.sh)
- Maps 127.0.0.1:4001/4002 to 0.0.0.0:4003/4004 for external access
- Uses socat for TCP relay without authentication

## Security Considerations

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
| Variable | Risk Level | Usage |
|----------|------------|-------|
| `SSH_USER_TUNNEL` | HIGH | SSH connection target - must be quoted |
| `SSH_OPTIONS` | HIGH | Additional SSH options - word splitting required |
| `SSH_SCREEN` | MEDIUM | VNC/RDP tunnel spec - word splitting required |
| `SSH_PASSPHRASE` | NONE | Only used by ssh-add, never in shell expansion |
| `SSH_REMOTE_PORT` | LOW | Numeric, validated by ssh |
| `SSH_ALIVE_INTERVAL` | LOW | Numeric, validated by ssh |

### Defense in Depth
1. Non-root execution (user ibgateway, UID 1000)
2. Secrets via file_env pattern (immediate unset after use)
3. Config files with 600 permissions
4. SSH key validation before agent loading
5. Shellcheck validation in CI/CD

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
- `set -Eo pipefail` in all scripts for early error detection
- Explicit validation before starting services (API_PORT, SOCAT_PORT checks)
- Graceful handling of optional features (SSH_PASSPHRASE, VNC, etc.)

### Background Process Management
- Uses `pgrep -f` with specific patterns to detect running processes
- Prevents duplicate socat/ssh instances
- Automatic restart on disconnection via while loops

## Related Documentation
- README.md:365-455 - SSH Tunnel user documentation
- README.md:312-364 - Security considerations for network exposure
- SECURITY.md - Detailed security patterns and vulnerability mitigation
- tests/security_test_ssh_injection.sh - Security validation tests
- sessions/tasks/h-fix-command-injection-ssh.md - Security fix context
