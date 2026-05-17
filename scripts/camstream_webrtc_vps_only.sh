#!/usr/bin/env bash
# Alias: то же, что camstream_webrtc.sh (VPS + --ice-vps-only).
exec "$(dirname "$0")/camstream_webrtc.sh" "$@"
