---
task: h-fix-missing-error-handling
branch: fix/missing-error-handling
status: pending
created: 2025-10-14
modules: [image-files/scripts, stable/scripts, latest/scripts]
---

# Add Strict Error Handling to common.sh

## Problem/Goal
The `common.sh` script lacks bash strict mode (`set -euo pipefail`) while other scripts depend on it. This creates a critical gap where failures in configuration functions like `apply_settings()`, `setup_ssh()`, or `set_ports()` could silently fail, leading to misconfiguration and security issues.

**Location**: `stable/scripts/common.sh`, `latest/scripts/common.sh`, `image-files/scripts/common.sh`

**Issue**: All other scripts use `set -Eeo pipefail` (lines 5 in run.sh, run_ssh.sh, run_socat.sh) but common.sh doesn't.

## Success Criteria
- [ ] Add `set -Eeo pipefail` to the top of common.sh (after shebang and shellcheck directives)
- [ ] Apply fix to all three copies: stable/, latest/, image-files/
- [ ] Test container startup to ensure no unexpected script exits
- [ ] Verify error handling works correctly (critical functions fail loudly)
- [ ] Run shellcheck on modified files to verify no new issues

## Context Files
- @stable/scripts/common.sh:1-10
- @latest/scripts/common.sh:1-10
- @image-files/scripts/common.sh:1-10
- @stable/scripts/run.sh:5  # Shows correct pattern
- @stable/scripts/run_ssh.sh:5  # Shows correct pattern

## User Notes
This is critical because silent failures in configuration can lead to security misconfigurations (wrong ports, missing credentials, etc.). The fix is simple but important.

## Work Log
- [2025-10-14] Task created from code review findings
