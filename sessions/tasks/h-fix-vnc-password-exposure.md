---
task: h-fix-vnc-password-exposure
branch: fix/vnc-password-exposure
status: pending
created: 2025-10-14
modules: [image-files/scripts, stable/scripts, latest/scripts]
---

# Fix VNC Password Exposure in Process List

## Problem/Goal
VNC password is passed directly on the x11vnc command line using the `-passwd` option, making it visible to all users via `ps aux` or the `/proc` filesystem. This is a critical credential exposure vulnerability.

**Location**: `stable/scripts/run.sh:61`, `latest/scripts/run.sh:61`, `image-files/scripts/run.sh:61`

**Current vulnerable code**:
```bash
x11vnc -ncache_cr -display :1 -forever -shared -bg -noipv6 -passwd "$VNC_SERVER_PASSWORD" &
```

## Success Criteria
- [ ] Change x11vnc to use `-passwdfile` option instead of `-passwd`
- [ ] Create temporary password file with secure permissions (600)
- [ ] Clean up password file after x11vnc starts
- [ ] Apply fix to all three copies: stable/, latest/, image-files/
- [ ] Test VNC connection still works with new method
- [ ] Verify password not visible in `ps aux` output
- [ ] Ensure cleanup happens even if x11vnc fails to start

## Context Files
- @stable/scripts/run.sh:55-65
- @latest/scripts/run.sh:55-65
- @image-files/scripts/run.sh:55-65
- @stable/scripts/common.sh:45-61  # file_env function shows good secure credential handling

## User Notes
This affects the ib-gateway image only (TWS uses RDP, not VNC). The password is only exposed if VNC_SERVER_PASSWORD is set.

Recommended fix pattern:
```bash
_vnc_pass_file="/tmp/.vncpass.$$"
echo "$VNC_SERVER_PASSWORD" > "$_vnc_pass_file"
chmod 600 "$_vnc_pass_file"
x11vnc -ncache_cr -display :1 -forever -shared -bg -noipv6 -passwdfile "$_vnc_pass_file" &
sleep 1  # Give x11vnc time to read the file
rm -f "$_vnc_pass_file"
```

## Work Log
- [2025-10-14] Task created from code review findings
