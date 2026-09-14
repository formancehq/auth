#!/usr/bin/env bash
set -euo pipefail

readonly minimum_coverage=80
[[ "$#" -eq 1 ]] || { printf 'usage: check-coverage.sh COVERAGE_PROFILE\n' >&2; exit 2; }
[[ -f "$1" ]] || { printf 'coverage profile is missing: %s\n' "$1" >&2; exit 1; }

coverage="$(go tool cover -func="$1" | awk '$1 == "total:" { gsub(/%/, "", $3); print $3 }')"
readonly coverage
[[ -n "$coverage" ]] || { printf 'could not read total coverage from %s\n' "$1" >&2; exit 1; }

awk -v actual="$coverage" -v minimum="$minimum_coverage" 'BEGIN {
  if (actual + 0 < minimum + 0) {
    printf "fctl Auth plugin coverage %s%% is below the required %s%%\n", actual, minimum > "/dev/stderr"
    exit 1
  }
}'
printf 'fctl Auth plugin coverage: %s%% (minimum %s%%)\n' "$coverage" "$minimum_coverage"
