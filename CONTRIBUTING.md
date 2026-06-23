# Contributing to LAN Scout

Thanks for your interest! LAN Scout aims to stay small, dependency-free, and
easy to read.

## Principles

- **No third-party Python dependencies.** The backend uses only the standard
  library (`http.server`, `sqlite3`, `xml.etree`). Please keep it that way — if
  a feature seems to need a package, open an issue to discuss first.
- **Single-file frontend.** `static/index.html` holds the markup, styles, and
  vanilla JS. No build step.
- **nmap is the one system dependency.**

## Development

```bash
git clone <repo>
cd lan-scout
python3 server.py          # http://127.0.0.1:8770
# or, for full device discovery on your LAN:
sudo python3 server.py
```

There are no compiled assets and no test framework yet. If you add backend
logic, a small `unittest` module under `tests/` is welcome.

## Project layout

| File | Responsibility |
|------|----------------|
| `server.py` | HTTP server, routes, background scan scheduler |
| `scanner.py` | nmap invocation + XML parsing |
| `db.py` | SQLite persistence (hosts, services, scans, settings) |
| `settings.py` | user-editable settings with validation |
| `config.py` | seed defaults + default service categories |
| `static/index.html` | the dashboard |

## Pull requests

- Keep changes focused and described.
- Match the existing code style (no formatter is enforced; just be consistent).
- Don't commit `lanscout.db` or anything under `data/`.

## Scope & ethics

LAN Scout is for discovering services on **networks you own or are authorized
to scan**. Please don't add features whose primary purpose is scanning or
attacking third-party networks.
