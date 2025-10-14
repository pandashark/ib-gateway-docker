---
task: h-fix-path-traversal
branch: fix/path-traversal
status: pending
created: 2025-10-14
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
- [ ] Add validation to reject paths containing `..` (path traversal)
- [ ] Add `-p` flag to mkdir for parent directory creation (defensive)
- [ ] Apply fix to all three copies: stable/, latest/, image-files/
- [ ] Test with valid paths (should work)
- [ ] Test with malicious paths containing `..` (should fail with error)
- [ ] Ensure error message is clear and helpful

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

## Work Log
- [2025-10-14] Task created from code review findings
