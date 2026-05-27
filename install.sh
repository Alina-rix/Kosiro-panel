#!/usr/bin/env bash
# Kosiro panel — установка на VPS одной командой:
#   curl -fsSL https://raw.githubusercontent.com/OWNER/kosiro-panel/main/install.sh | bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$ROOT/scripts/install.sh" "$@"
