# Kosiro Panel

VPN-панель для Linux VPS: Go-агент, Docker Compose (Xray, sing-box/Hysteria2, MTProto).

## Установка

```bash
curl -fsSL https://raw.githubusercontent.com/Alina-rix/kosiro-panel/main/install.sh | bash
```

После установки откройте **https://IP:8443/panel/** — веб-дашборд (логин: admin key из вывода установки).

## Структура

| Путь | Назначение |
|------|------------|
| `agent/` | REST API, SQLite, конфиги Xray/sing-box |
| `deploy/compose/` | Docker Compose |
| `deploy/static/panel/` | Веб-дашборд (`/panel/`) — пользователи, протоколы, метрики |
| `install.sh` | Установка: `curl \| bash` |
| `scripts/install.sh` | Логика установки |

## Разработка

```bash
cd agent && go mod tidy && go run ./cmd/agent
```

```bash
cd deploy/compose
cp env.example .env
docker compose up -d --build
```

## Протоколы (пресеты)

| Пресет | Движок |
|--------|--------|
| VLESS + REALITY | Xray |
| VLESS + XHTTP | Xray |
| VLESS + REALITY + XHTTP | Xray |
| VLESS + REALITY + Vision + Mux | Xray |
| VMess, SS, Trojan | Xray |
| Hysteria2, TUIC, AnyTLS | sing-box |
| MTProto | Docker sidecar |

Установка пресета в UI → «Применить все» перегенерирует конфиги и перезапускает контейнеры.

## API

- `GET /health`
- `POST /v1/auth/token` — JWT (`admin_token` / `install_secret`)
- `GET /sub/{token}` — подписка
- Остальное — `Authorization: Bearer …`
