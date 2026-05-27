# Kosiro Panel

VPN-панель для Linux VPS: Go-агент, Docker Compose (Xray, sing-box/Hysteria2, MTProto).

## Установка

```bash
curl -fsSL https://raw.githubusercontent.com/Alina-rix/kosiro-panel/main/install.sh | bash
```

После установки в выводе будут `api_base_url` и `admin_key` (`A_R:SRV-…#……`).

## Структура

| Путь | Назначение |
|------|------------|
| `agent/` | REST API, SQLite, конфиги Xray/sing-box |
| `deploy/compose/` | Docker Compose |
| `deploy/static/panel/` | Статика веб-дашборда (`/panel/`) |
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

## API

- `GET /health`
- `POST /v1/auth/token` — JWT (`admin_token` / `install_secret`)
- `GET /sub/{token}` — подписка
- Остальное — `Authorization: Bearer …`
