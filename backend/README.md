# CHANXAI API

Flask backend for the CHANXAI SOC dashboard.

## Run locally

```bash
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
gunicorn -w 2 -b 0.0.0.0:8000 wsgi:app
```

## Production path

The intended Wazuh VM path is `/opt/chanxai-api`. Copy this directory there, fill `.env`, and expose it as `https://api.chanxai.com` through Cloudflare Tunnel or a reverse proxy.

Frontend must call only this API. It must not call Wazuh or Kali directly.

## Wazuh Threat Hunting events

`/api/security/events` reads real alerts from Wazuh Indexer, using `WAZUH_ALERT_INDEX` and `WAZUH_ALERT_TIME_RANGE`. Demo events are returned only when `WAZUH_DEMO_FALLBACK=true`; keep it `false` in production.

## Public API

Expose the gunicorn listener on port `8000` as `https://api.chanxai.com` with Cloudflare Tunnel or a reverse proxy. The public route must forward to `http://127.0.0.1:8000`, and `ALLOWED_ORIGINS` must include `https://chanxai.com`.
