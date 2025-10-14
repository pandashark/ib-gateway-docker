#!/bin/bash
set -Eo pipefail

_OPTIONS="$SSH_ALL_OPTIONS"
_LOCAL_PORT="$API_PORT"
_REMOTE_PORT="$SSH_REMOTE_PORT"
_SCREEN="$SSH_SCREEN"
_USER_TUNNEL="$SSH_USER_TUNNEL"
_RESTART="$SSH_RESTART"

while true; do
	echo ".> Starting ssh tunnel with ssh sock: $SSH_AUTH_SOCK"

	# SECURITY: Direct execution prevents command injection (CWE-78)
	# - DO NOT wrap this command in 'bash -c "..."' as it enables arbitrary command execution
	# - _OPTIONS and _SCREEN are intentionally unquoted to allow word splitting for multiple SSH arguments
	# - _USER_TUNNEL is quoted to prevent injection through the user@host field
	# - Port forwarding spec is quoted to prevent manipulation of tunnel configuration
	# shellcheck disable=SC2086  # Word splitting intentional for _OPTIONS and _SCREEN
	ssh ${_OPTIONS} -TNR "127.0.0.1:${_LOCAL_PORT}:localhost:${_REMOTE_PORT}" ${_SCREEN:-} "${_USER_TUNNEL}"

	sleep "${_RESTART:-5}"
done
