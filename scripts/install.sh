#!/usr/bin/env bash
# Kosiro: установка на VPS — Docker, compose, admin key A_R:SRV-xxx#NNNNNN
set -euo pipefail

# Публичный репозиторий (переопределите при форке):
KOSIRO_GITHUB_OWNER="${KOSIRO_GITHUB_OWNER:-Alina-rix}"
KOSIRO_GITHUB_REPO="${KOSIRO_GITHUB_REPO:-Kosiro-panel}"
KOSIRO_GITHUB_BRANCH="${KOSIRO_GITHUB_BRANCH:-main}"
export KOSIRO_REPO_TARBALL="${KOSIRO_REPO_TARBALL:-https://github.com/${KOSIRO_GITHUB_OWNER}/${KOSIRO_GITHUB_REPO}/archive/refs/heads/${KOSIRO_GITHUB_BRANCH}.tar.gz}"

log() { echo "[kosiro] $*" >&2; }

progress() {
  if [ "${KOSIRO_PROGRESS_JSON:-}" = "1" ]; then
    echo "$1"
  fi
}

run_compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    echo '{"phase":"error","error":"no_compose","message":"Нет docker compose"}' >&2
    exit 1
  fi
}

generate_admin_key() {
  local host="$1"
  local secret="$2"
  local slug
  slug="$(printf '%s' "${host}:${secret}" | sha256sum | awk '{print $1}' | cut -c1-6)"
  local id="482917"
  if command -v od >/dev/null 2>&1; then
    id="$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | awk -v s="$RANDOM" '{printf "%06d\n", (int($1+s) % 900000) + 100000}')"
  fi
  echo "A_R:SRV-${slug}#${id}"
}

ensure_docker() {
  progress '{"phase":"docker_check"}'
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1; then
      log "Docker уже установлен."
      progress '{"phase":"docker_ok"}'
      return 0
    fi
  fi

  progress '{"phase":"docker_install"}'
  log "Ставим Docker…"
  if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
  fi
  local id="${ID:-}"

  case "$id" in
    arch|archlinux)
      pacman -Sy --needed --noconfirm docker docker-compose >/dev/null
      systemctl enable --now docker 2>/dev/null || true
      ;;
    alpine)
      apk add --no-cache docker docker-cli-compose
      rc-update add docker boot 2>/dev/null || true
      service docker start 2>/dev/null || true
      ;;
    *)
      if ! command -v curl >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
          apt-get update -qq && apt-get install -y -qq curl ca-certificates
        elif command -v dnf >/dev/null 2>&1; then
          dnf install -y curl ca-certificates
        elif command -v yum >/dev/null 2>&1; then
          yum install -y curl ca-certificates
        fi
      fi
      curl -fsSL https://get.docker.com | sh
      systemctl enable --now docker 2>/dev/null || true
      ;;
  esac

  local n=0
  while ! docker info >/dev/null 2>&1; do
    n=$((n + 1))
    if [ "$n" -gt 60 ]; then
      echo '{"phase":"error","error":"docker_daemon"}' >&2
      exit 1
    fi
    sleep 1
  done

  if ! docker compose version >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq docker-compose-plugin || true
  fi
  progress '{"phase":"docker_ok"}'
}

find_compose_dir() {
  local root="$1"
  if [ -f "$root/deploy/compose/docker-compose.yml" ]; then
    echo "$root/deploy/compose"
    return 0
  fi
  if [ -f "$root/server/deploy/compose/docker-compose.yml" ]; then
    echo "$root/server/deploy/compose"
    return 0
  fi
  return 1
}

SCRIPT_PATH="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
if [ -n "$SCRIPT_PATH" ] && [ "$SCRIPT_PATH" != "bash" ] && [ -f "$SCRIPT_PATH" ]; then
  SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
fi

progress '{"phase":"ssh_ok"}'

if [ -n "$SCRIPT_DIR" ] && COMPOSE_DIR="$(find_compose_dir "$(cd "$SCRIPT_DIR/.." && pwd)")"; then
  ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
  log "Локальный репозиторий: $COMPOSE_DIR"
  progress '{"phase":"kosiro_files_ok","source":"local"}'
else
  if [ -z "${KOSIRO_REPO_TARBALL:-}" ]; then
    echo '{"phase":"error","error":"missing_tarball"}' >&2
    exit 1
  fi

  INSTALL_ROOT="${KOSIRO_INSTALL_ROOT:-/opt/kosiro}"
  progress '{"phase":"kosiro_files_check"}'
  log "Качаю репозиторий → $INSTALL_ROOT"
  tmpd="$(mktemp -d)"
  curl -fL --retry 3 --retry-delay 2 "$KOSIRO_REPO_TARBALL" -o "$tmpd/kosiro.tgz"
  tar -xzf "$tmpd/kosiro.tgz" -C "$tmpd"
  extracted="$(find "$tmpd" -mindepth 1 -maxdepth 1 -type d ! -name '.*' | head -1)"
  rm -rf "$tmpd/kosiro.tgz"
  if [ -z "$extracted" ] || ! COMPOSE_DIR="$(find_compose_dir "$extracted")"; then
    echo '{"phase":"error","error":"bad_tarball"}' >&2
    rm -rf "$tmpd"
    exit 1
  fi
  rm -rf "$INSTALL_ROOT"
  mv "$extracted" "$INSTALL_ROOT"
  rm -rf "$tmpd"
  if ! COMPOSE_DIR="$(find_compose_dir "$INSTALL_ROOT")"; then
    echo '{"phase":"error","error":"bad_tarball"}' >&2
    exit 1
  fi
  progress '{"phase":"kosiro_files_ok","source":"tarball"}'
fi

ensure_docker

KOSIRO_INSTALL_SECRET="${KOSIRO_INSTALL_SECRET:-$(openssl rand -hex 16)}"
KOSIRO_PUBLIC_HOST="${KOSIRO_PUBLIC_HOST:-$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo 127.0.0.1)}"
KOSIRO_ADMIN_TOKEN="${KOSIRO_ADMIN_TOKEN:-$(generate_admin_key "$KOSIRO_PUBLIC_HOST" "$KOSIRO_INSTALL_SECRET")}"

export KOSIRO_ADMIN_TOKEN KOSIRO_INSTALL_SECRET KOSIRO_PUBLIC_HOST

ENV_FILE="$COMPOSE_DIR/.env"
{
  echo "KOSIRO_ADMIN_TOKEN=$KOSIRO_ADMIN_TOKEN"
  echo "KOSIRO_INSTALL_SECRET=$KOSIRO_INSTALL_SECRET"
  echo "KOSIRO_PUBLIC_HOST=$KOSIRO_PUBLIC_HOST"
  echo "KOSIRO_PORT=8443"
} >"$ENV_FILE"
chmod 600 "$ENV_FILE"

progress '{"phase":"compose_up"}'
log "Сборка и запуск контейнеров…"
run_compose -f "$COMPOSE_DIR/docker-compose.yml" --env-file "$ENV_FILE" up -d --build

progress '{"phase":"agent_health"}'
n=0
API_BASE="${KOSIRO_API_BASE_URL:-http://${KOSIRO_PUBLIC_HOST}:8443}"
while ! curl -fsS --max-time 3 "${API_BASE}/health" >/dev/null 2>&1; do
  n=$((n + 1))
  if [ "$n" -gt 90 ]; then
    echo '{"phase":"error","error":"agent_health"}' >&2
    exit 1
  fi
  sleep 2
done

progress '{"phase":"done"}'
printf '{"api_base_url":"%s","admin_token":"%s","admin_key":"%s","install_secret":"%s"}\n' \
  "$API_BASE" "$KOSIRO_ADMIN_TOKEN" "$KOSIRO_ADMIN_TOKEN" "$KOSIRO_INSTALL_SECRET"
