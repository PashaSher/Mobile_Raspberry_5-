#!/usr/bin/env bash
# WebRTC только через Hetzner (TURN relay): см. --ice-vps-only в stream_camera.py webrtc.
exec "$(dirname "$0")/camstream_webrtc.sh" --ice-vps-only "$@"
