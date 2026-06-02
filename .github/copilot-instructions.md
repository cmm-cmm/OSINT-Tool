# Copilot Instructions — OSINT Tool

## Running the tool

```bash
# Interactive TUI menu (primary usage)
python osint.py menu

# CLI commands (non-interactive)
python osint.py domain example.com --report
python osint.py domain example.com --secrets --cloud --report
python osint.py domain --targets domains.txt --report
python osint.py email user@example.com
python osint.py username johndoe
python osint.py phone +84123456789
python osint.py ip 1.2.3.4

# Docker
docker build -t osint-tool .
docker run --rm -it osint-tool menu
docker compose up
```

**Python 3.10+ required.** Install dependencies:

```bash
pip install -r requirements.txt
```

## Architecture

```
osint.py          ← Click CLI entry point + all @cli.command definitions
modules/
  base.py         ← OsintModule base class + ALL_MODULES registry (one class per scan category)
  tui.py          ← Interactive TUI menu engine (Rich-based, 2-column grid)
  constants.py    ← VERSION, theme constants, USER_CONFIG_DIR, OPTIONAL_TOOLS registry
  external_tools.py ← ExternalTool dataclass + install/update/run manager
  utils.py        ← make_session(), safe_get(), RateLimiter, sanitize_for_shell(), scan history
  report.py       ← save_report() — exports HTML + JSON + CSV to output dir
  config.py       ← Persistent config at ~/.osint-tool/config.json
  <feature>.py    ← One module file per scan category (whois_lookup, email_recon, etc.)
```

**Data flow:** `osint.py` CLI → calls module functions directly. `python osint.py menu` → `tui.py` renders the menu → user selects a number → `OsintModule.run()` in `base.py` calls `run_interactive()` on the matching subclass → that subclass imports and calls functions from the feature module files.

**Config persistence:** `~/.osint-tool/config.json` (merged with `DEFAULT_CONFIG` at load). Scan history appended to `~/.osint-tool/history.jsonl`. Both paths come from `modules/constants.py`.

## Adding a new module

1. Create `modules/<feature>.py` with the core logic functions (`<feature>_scan(target) -> dict`, `print_<feature>_results(data)`).
2. Add a subclass of `OsintModule` in `modules/base.py` with class attributes:
   - `TITLE`, `DESCRIPTION`, `TAGS`, `ICON`, `REQUIRES_ENV`, `OPTIONAL_DEPS`
   - `ARCHIVED = False` (set `True` + `ARCHIVED_REASON` to hide from main menu)
   - `SUPPORTED_OS = []` (empty = all platforms; set `["linux", "darwin"]` for Linux-only tools)
3. Implement `run_interactive(self)` — use `Prompt.ask(...)` for user input, call feature functions, optionally `save_report()`.
4. Register the instance in `ALL_MODULES` list at the bottom of `base.py`.
5. If the module needs a CLI command, add a `@cli.command(...)` in `osint.py`.

## Key conventions

**Optional dependencies:** Add package names to `OPTIONAL_DEPS` on the module class. The base class `is_available` / `missing_deps` properties handle detection at runtime — never import optional packages at module top level; import inside the function that needs them with a `try/except ImportError` fallback.

**External binaries** (Go tools, standalone CLIs): Register in `OPTIONAL_TOOLS` dict in `constants.py` with `install`, `install_win`, `binary`, `py_module`, `requires_go` fields. The `ExternalTool.is_installed` property checks `shutil.which` + Windows venv Scripts dir.

**HTTP requests:** Always use `utils.make_session()` (returns a `requests.Session` with retry/backoff + certifi SSL). Use `utils.safe_get()` for fire-and-forget GETs that should never raise. Use `RateLimiter` as a context manager for rate-limited loops.

**Shell safety:** Any user-supplied value passed to `subprocess` must go through `utils.sanitize_for_shell()` first — raises `ValueError` if it contains non-safe characters.

**UI/output:** All output uses `rich`. Theme color constants are in `constants.py` (`THEME_PRIMARY`, `THEME_ACCENT`, `THEME_SUCCESS`, `THEME_WARNING`, `THEME_ERROR`, `THEME_DIM`). Use these instead of hard-coded color strings.

**Reports:** Call `modules.report.save_report(target, all_data_dict, output_dir)` to export HTML + JSON + CSV. The `all_data` dict keys become section headers in the report.

**API keys:** All keys come from `.env` (loaded via `python-dotenv` at startup) or environment variables. Never hard-code keys. Check `REQUIRES_ENV` on the module class for the relevant variable names. The tool always degrades gracefully when keys are absent.

**Output directory:** Retrieve via `config.get_output_dir()` (respects `OSINT_OUTPUT_DIR` env var, then config file, then CWD).

## Modules reference

| Module class | File | CLI command | Key dep |
|---|---|---|---|
| DomainModule | whois_lookup, ssl_analyzer, ip_lookup, ... | `domain` | — |
| EmailModule | email_recon | `email` | holehe (opt) |
| UsernameModule | username_search | `username` | maigret (opt) |
| PhoneModule | phone_lookup | `phone` | — |
| IPModule | ip_lookup | `ip` | — |
| SSLModule | ssl_analyzer | `ssl` | — |
| InstagramModule | instagram_recon | `instagram` | instaloader (opt) |
| SocialModule | social_recon | `social` | — |
| BreachModule | breach_check | `breach` | — |
| SecretsModule | secrets_scanner | `secrets` | — |
| CloudModule | cloud_recon | `cloud` | — |
| CertModule | cert_transparency | `certs` | — |
| ImageModule | image_recon | `image` | — |
| YoutubeModule | youtube_recon | `youtube` | — |
| ContactsModule | website_contacts | `contacts` | — |
| DorksModule | google_dorks | `person` | — |
| **SocialFootprintModule** | **social_footprint** | **`footprint`** | **ddgs** |

### SocialFootprintModule (`modules/social_footprint.py`)

Searches username mentions via DuckDuckGo `site:` operator — no API key needed.

```python
# Single platform search
footprint_search(username, platform="instagram", limit=10, limited=False) -> dict

# Two-person connection detection
association_search(username1, username2, platform="facebook", limit=10) -> dict
```

CLI usage:
```bash
python osint.py footprint johndoe --platform instagram
python osint.py footprint johndoe --platform instagram --limited  # URL-only filter
python osint.py footprint johndoe --associate janedoe --platform facebook  # detect link
python osint.py footprint johndoe --output-format json
```

Supported platform keywords: `instagram`, `tiktok`, `twitter`/`x`, `github`, `facebook`, `linkedin`, `youtube`, `reddit`, `pinterest`, `snapchat`, `tumblr`, `medium`, `telegram`, `vk`, `all`.
