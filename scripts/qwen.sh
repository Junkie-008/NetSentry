#!/bin/bash
# Supervised one-shot prompt runner for the local qwen3.5:9b model.
#
# Usage:   bash scripts/qwen.sh "your prompt" [timeout_seconds]
#
# Uses think=false (CPU-only box: ~4.5 tok/s, reasoning burn is unaffordable),
# strips ANSI spinner codes, prints clean answer + token timings.
PROMPT="$1"
TIMEOUT="${2:-280}"
MODEL="${QWEN_MODEL:-qwen3.5:9b}"
THINK="${QWEN_THINK:-false}"

printf '%s' "$PROMPT" | timeout "$TIMEOUT" ollama run "$MODEL" \
  --think="$THINK" --hidethinking --nowordwrap --verbose 2>/tmp/qwen_stderr.log \
  | sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g'
STATUS=${PIPESTATUS[1]}

if [ "$STATUS" -eq 124 ]; then
  echo "[SUPERVISOR] TIMEOUT: model did not finish within ${TIMEOUT}s"
fi
if [ "$STATUS" -ne 0 ] && [ "$STATUS" -ne 124 ]; then
  echo "[SUPERVISOR] ollama exited with status $STATUS:"
  sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' /tmp/qwen_stderr.log | tail -5
fi
