#!/usr/bin/env bash
set -euo pipefail

COUNT="${1:-5}"
INTERVAL="${2:-0.2}"
WECHAT_APP="${WECHAT_APP:-/Applications/WeChat.app}"
WECHAT_BUNDLE_ID="${WECHAT_BUNDLE_ID:-com.tencent.xinWeChat}"

if [[ ! -d "$WECHAT_APP" ]]; then
  echo "WeChat app not found at: $WECHAT_APP" >&2
  echo "Set WECHAT_APP=/path/to/WeChat.app and rerun." >&2
  exit 1
fi

case "$COUNT" in
  ''|*[!0-9]*)
    echo "COUNT must be a positive integer." >&2
    exit 1
    ;;
esac

if [[ "$COUNT" -lt 1 ]]; then
  echo "COUNT must be greater than 0." >&2
  exit 1
fi

osascript \
  -e "tell application \"$WECHAT_APP\" to activate" \
  -e "delay 0.8" \
  -e "tell application \"System Events\"" \
  -e "set frontmost of the first process whose bundle identifier is \"$WECHAT_BUNDLE_ID\" to true" \
  -e "delay 0.2" \
  -e "repeat $COUNT times" \
  -e "key code 125 using {option down, command down}" \
  -e "delay $INTERVAL" \
  -e "end repeat" \
  -e "end tell"
