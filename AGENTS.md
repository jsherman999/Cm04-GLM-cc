# Repository Guidelines

## Project Structure & Module Organization
`src/` contains the runtime code: `api/` (FastAPI server, WebSockets, templates), `cli/` (Click entrypoints for `cm04-scan`, `cm04-monitor`, `cm04-server`), `core/` (scan orchestration), `models/` (Pydantic schemas, persistence objects), and `utils/` (SSH, reporting, auth helpers). UI assets stay under `static/`, deployment snippets live in `config/`, and operational docs live in `docs/`. Keep tests in `tests/` with fixtures under `tests/fixtures/`.

## Build, Test, and Development Commands
- `python -m venv .venv && source .venv/bin/activate` – create a local sandbox.
- `pip install -e .[dev]` – install the package and dev tooling.
- `cm04-server --host 0.0.0.0 --port 8000` – run the API/UI locally at `http://localhost:8000`.
- `cm04-scan scan -h host -p "/home,/var/log"` – CLI smoke test against a host/path list.
- `pytest --maxfail=1 --cov=src` – default CI-equivalent test sweep.

## Coding Style & Naming Conventions
Use Black’s 88-character wrap and the bundled `isort` profile. Keep modules, functions, and CLI options in `snake_case`; config classes and Pydantic models use `PascalCase`. Environment variables in `src/config/settings.py` stay `SCREAMING_SNAKE_CASE`. Type hints are mandatory because `mypy` runs in strict mode. Execute `black . && isort . && flake8 && mypy src` before pushing.

## Testing Guidelines
`pytest` is the single entry point. Keep files `test_*.py` or `*_test.py`, classes `Test*`, and functions `test_*` for discovery. Use markers declared in `pyproject.toml`: `pytest -m "not slow"` filters fast scenarios, `pytest -m integration` runs SSH/DB checks. Coverage targets only `src/`; justify exclusions with `# pragma: no cover`. Store host fixtures or mock responses inside `tests/fixtures/` and prefer `asyncssh` fakes over real network calls.

## Commit & Pull Request Guidelines
Recent commits follow a short, imperative pattern (`Add enhanced HTML report`, `Fix progress updates`). Mirror that style: start with a verb, keep ≤70 characters, and scope to one logical change. PRs should summarize intent, list user-visible impacts, attach UI screenshots when touching `static/`, and include test command output. Reference related issues and call out config or infra changes (e.g., edits under `config/nginx.conf` or `.env` variables) so deployers can prepare.

## Security & Configuration Tips
Never commit secrets; create `.env` from `.env.example` and document new keys in `README.md` or `docs/DEPLOYMENT.md`. SSH credentials referenced by `SSH_KEY_FILE` must exist on the scanning node; for shared hosts rely on vault-managed keys. All inbound payloads must pass through Pydantic validators before hitting business logic, and downloaded reports under `static/reports/` should be sanitized to avoid leaking unintended paths or usernames.
