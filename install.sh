#!/usr/bin/env bash
# Kosiro panel — установка на VPS одной командой:
#   curl -fsSL https://raw.githubusercontent.com/Alina-rix/Kosiro-panel/main/install.sh | bash
set -eo pipefail

KOSIRO_GITHUB_OWNER="${KOSIRO_GITHUB_OWNER:-Alina-rix}"
KOSIRO_GITHUB_REPO="${KOSIRO_GITHUB_REPO:-Kosiro-panel}"
KOSIRO_GITHUB_BRANCH="${KOSIRO_GITHUB_BRANCH:-main}"

_self="${BASH_SOURCE[0]:-}"
if [[ -n "$_self" && "$_self" != "bash" && -f "$_self" ]]; then
  _root="$(cd "$(dirname "$_self")" && pwd)"
  if [[ -f "$_root/scripts/install.sh" ]]; then
    exec bash "$_root/scripts/install.sh" "$@"
  fi
fi

# curl | bash — локального файла нет, тянем основной скрипт с GitHub
exec bash <(curl -fsSL "https://raw.githubusercontent.com/${KOSIRO_GITHUB_OWNER}/${KOSIRO_GITHUB_REPO}/${KOSIRO_GITHUB_BRANCH}/scripts/install.sh")
