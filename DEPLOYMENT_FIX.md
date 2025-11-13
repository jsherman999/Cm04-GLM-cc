# CM-04 Scanner - Deployment Fix

## Issue Resolved
Fixed Pydantic v2 compatibility issues that were causing startup failures.

## Changes Made

### 1. Updated `src/config/settings.py`
- **Fixed import**: Changed from `from pydantic import BaseSettings, Field` to `from pydantic_settings import BaseSettings`
- **Updated Config**: Changed inner `class Config` to `model_config` dictionary (Pydantic v2 standard)

### 2. Updated `src/api/main.py`
- **Added CLI entry point**: Created `start_server()` function to properly handle command-line arguments
- **Added Click integration**: Supports `--host`, `--port`, and `--reload` flags

### 3. Updated `pyproject.toml`
- **Fixed script entry**: Changed `cm04-server = "src.api.main:app"` to `cm04-server = "src.api.main:start_server"`

## Deployment Steps

After pulling these changes, run:

```bash
# Reinstall the package to pick up the new entry point
pip install -e .

# Or if already installed, reinstall
pip uninstall cm04-scanner
pip install -e .

# Now start the server
cm04-server --host 0.0.0.0 --port 9000
```

## CLI Options

The `cm04-server` command now supports:

- `--host` - Host to bind to (default: 0.0.0.0)
- `--port` - Port to bind to (default: 8000)
- `--reload` - Enable auto-reload for development

### Examples

```bash
# Basic startup
cm04-server

# Custom host and port
cm04-server --host 0.0.0.0 --port 9000

# Development mode with auto-reload
cm04-server --host 127.0.0.1 --port 8000 --reload
```

## Verification

To verify the fix worked:

1. Check that imports work:
   ```bash
   python -c "from src.config.settings import settings; print('Settings loaded:', settings.app_name)"
   ```

2. Check the server starts:
   ```bash
   cm04-server --port 9000
   ```

3. Test the health endpoint:
   ```bash
   curl http://localhost:9000/health
   ```

## Common Issues

### If you still get import errors:
- Ensure `pydantic-settings` is installed: `pip install pydantic-settings`
- Check Pydantic version: `pip list | grep pydantic`
- Should see both `pydantic` (2.5.0+) and `pydantic-settings` (2.1.0+)

### If cm04-server command not found:
- Run `pip install -e .` from the project root directory
- Check that the script is installed: `which cm04-server`

### Static files not found:
- Ensure `static/` directory exists in the project root
- Ensure `reports/` directory exists or will be created automatically

## Dependencies

The application requires:
- Python 3.8+
- pydantic >= 2.5.0
- pydantic-settings >= 2.1.0
- fastapi >= 0.104.0
- uvicorn >= 0.24.0

All dependencies are listed in `requirements.txt` and `pyproject.toml`.
