# MacOS-Maid

**macOS cleanup and security auditing tool for developers**

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](https://github.com/jgamblin/macos-maid-v2)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![macOS](https://img.shields.io/badge/macOS-12%2B-000000?logo=apple)](https://www.apple.com/macos/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## What It Does

MacOS-Maid is a command-line tool designed for developers who want to keep their macOS workstations clean, secure, and running efficiently. It combines automated cleanup tasks with comprehensive security auditing in a single, easy-to-use package. Whether you need to reclaim disk space from Docker images, update Homebrew packages, or verify your system's security posture, MacOS-Maid handles it with safety and transparency.

The tool is built around modules that fall into two categories: development cleanup (removing caches, updating tools, managing containers) and security auditing (checking system integrity, auditing permissions, scanning for vulnerabilities). Run them together for a complete workstation refresh, or use them independently when you need targeted maintenance or security checks.

## Quick Start

Install via Homebrew (recommended):

```bash
brew install jgamblin/tap/macos-maid
```

Run a security audit (read-only, no changes):

```bash
maid audit
```

Preview cleanup operations before executing:

```bash
maid clean --dry-run
```

## Example Output

```
MacOS Maid Report — 2026-04-12
macOS Sequoia 15.4 | Apple M3 Pro | APFS
════════════════════════════════════════════

Cleanup
───────
Disk: 12.4 GB reclaimed
Homebrew: 12 packages updated, 3.1 GB cache cleaned
Docker: 8 dangling images removed (6.4 GB)
Dev caches: 2.1 GB (pip: 800 MB, Xcode: 1.3 GB)
Trash: 890 MB emptied
WiFi: 12 stale networks removed

Security Audit
──────────────
SIP: PASS          FileVault: PASS
Gatekeeper: PASS   Firewall: FAIL — disabled
XProtect: PASS

Apps: 3 unsigned (2 with elevated permissions)
Launch daemons: 2 non-Apple
TCC: Screen recording: 4 apps, Full disk access: 6 apps
Network: 3 open ports, 1 VPN profile

Duration: 47 seconds
Full log: ~/.maid/last_run.json
```

## Installation

### Homebrew (Recommended)

```bash
brew install jgamblin/tap/macos-maid
```

### pip / pipx

```bash
# Using pip
pip install macos-maid

# Using pipx (isolated environment)
pipx install macos-maid
```

### Development Installation

```bash
git clone https://github.com/jgamblin/macos-maid-v2.git
cd macos-maid-v2
pip install -e ".[dev]"
```

## Usage

MacOS-Maid provides several commands for different workflows:

### Commands

**`maid clean`** — Run cleanup modules (dev tools, caches, containers)

```bash
maid clean                    # First run defaults to dry-run
maid clean --dry-run          # Preview changes without executing
maid clean --sudo             # Enable modules requiring elevated privileges
maid clean --dev              # Run only development cleanup modules
maid clean --security         # Run only security-related cleanup
maid clean --modules=trash,docker  # Run specific modules
```

**`maid audit`** — Run security audit (read-only checks)

```bash
maid audit                    # Basic security checks
maid audit --sudo             # Enable privileged audit checks
maid audit --output=json      # Output in JSON format
```

**`maid report`** — Run full cleanup + security audit

```bash
maid report                   # Complete workstation report
maid report --dry-run         # Preview full report
maid report --sudo            # Enable all privileged operations
```

**`maid init`** — Generate default configuration file

```bash
maid init                     # Creates ~/.maid.yml
maid init --path=custom.yml   # Create config at custom path
```

**`maid list`** — List all available modules

```bash
maid list                     # Show all modules with categories
```

**`maid log`** — Show the last run log

```bash
maid log                      # Display ~/.maid/last_run.json
maid log --log-dir=/path      # Show log from custom directory
```

### Common Flags

- `--dry-run` — Preview changes without executing (enabled by default on first run)
- `--sudo` — Allow modules requiring elevated privileges (disabled by default)
- `--modules` — Run specific modules (comma-separated: `trash,homebrew,docker`)
- `--dev` — Run only development cleanup modules
- `--security` — Run only security-related modules
- `--output` — Output format: `terminal` (default), `json`, or `markdown`

## Configuration

MacOS-Maid uses `~/.maid.yml` for configuration. Generate a default config with `maid init`.

### Example Configuration

```yaml
# Which module categories to run (dev, security, or both)
categories:
  - dev
  - security

# Report settings
report:
  show_disk_before_after: true
  output: terminal # terminal, json, or markdown

# Homebrew cleanup
homebrew:
  update: true
  upgrade: true
  cleanup: true
  audit_casks: true
  check_untapped: true

# Docker cleanup
docker:
  remove_dangling_images: true
  remove_unused_volumes: true
  remove_stopped_containers: false # Conservative default

# Developer caches to clean
dev_caches:
  clean:
    - pip
    - npm
    - cargo
    - gradle
    - cocoapods
    - xcode_derived

# Git repository maintenance
git:
  enabled: false # Opt-in only
  repos_dir: ~/Projects
  prune_remotes: true
  delete_merged_branches: false
  protected_branches:
    - main
    - master
    - develop

# WiFi network cleanup
wifi:
  keep_days: 90 # Remove networks not used in 90 days
  keep_ssids:
    - HomeNetwork
    - WorkNetwork

# Network security
network:
  flush_dns: true
  check_open_ports: true
  audit_vpn_profiles: true
  check_firewall: true

# Privacy settings
privacy:
  clear_recent_items: true
  report_old_downloads: true
  downloads_move_to_trash: false
  downloads_older_than: 90
  audit_tcc_permissions: true

# System integrity checks
system_integrity:
  check_sip: true
  check_filevault: true
  check_gatekeeper: true
  check_xprotect: true

# Optional security tools (run if installed)
tools:
  lynis: true
  osquery: true
  knockknock: false
```

## Modules

MacOS-Maid includes 13 modules across development and security categories:

| Module           | Category | Description                                       | Sudo? |
| ---------------- | -------- | ------------------------------------------------- | ----- |
| trash            | dev      | Empty user trash                                  | No    |
| homebrew         | dev      | Update/upgrade/cleanup Homebrew packages          | No    |
| docker           | dev      | Remove dangling images and unused volumes         | No    |
| dev_caches       | dev      | Clean pip/npm/cargo/gradle/CocoaPods/Xcode caches | No    |
| git              | dev      | Prune remotes and delete merged branches          | No    |
| system_cache     | both     | Clean system logs and user caches                 | Yes   |
| system_integrity | security | Check SIP/FileVault/Gatekeeper/XProtect/firewall  | No    |
| network          | security | Flush DNS, audit open ports and VPN profiles      | Yes   |
| wifi             | security | Remove stale saved networks                       | Yes   |
| privacy          | security | Audit TCC permissions and clear recent items      | Yes   |
| app_audit        | security | Check for unsigned applications                   | No    |
| launch_audit     | security | Audit launch daemons and agents                   | No    |
| tools            | security | Integration with Lynis/osquery/KnockKnock         | No    |

## Safety

MacOS-Maid is designed with safety as a priority:

- **Dry-run first** — The first run without a config file defaults to `--dry-run`, showing exactly what would happen without making changes
- **No sudo by default** — Modules requiring elevated privileges are skipped unless you explicitly pass `--sudo`
- **Allowlist-only deletion** — Only removes well-known cache directories and artifacts; never performs broad filesystem sweeps
- **Action logging** — Every operation is logged to `~/.maid/last_run.json` for accountability and debugging
- **Recoverable where possible** — Trash is emptied to system trash (recoverable for 30 days), WiFi networks can be re-added
- **No network calls** — All operations are local; no data is sent to external services

## Optional Tools

MacOS-Maid integrates with optional security tools if they're installed:

- **Lynis** — System security auditing tool. If installed, runs a quick audit and includes results.
- **osquery** — SQL-powered system introspection. If installed, runs security-focused queries.
- **KnockKnock** — Scans for persistent malware. If installed, checks launch items and applications.

If these tools aren't found, MacOS-Maid suggests installing them but continues without failure. Install via Homebrew:

```bash
brew install lynis osquery
```

## Compatibility

- **macOS versions**: macOS 12 (Monterey) through macOS 15 (Sequoia) and later
- **Architectures**: Intel (x86_64) and Apple Silicon (arm64)
- **Python**: Python 3.10, 3.11, and 3.12

## Contributing

Contributions are welcome! To get started:

1. **Development setup**:

   ```bash
   git clone https://github.com/jgamblin/macos-maid-v2.git
   cd macos-maid-v2
   pip install -e ".[dev]"
   ```

2. **Run tests**:

   ```bash
   pytest
   pytest --cov=macos_maid  # With coverage
   ```

3. **Lint and type-check**:

   ```bash
   ruff check src/
   mypy src/
   ```

4. **Add a new module**:
   - Create a new file in `src/macos_maid/modules/`
   - Inherit from `BaseModule`
   - Implement `run_clean()` and/or `run_audit()`
   - Register in `modules/__init__.py`

## License

MIT License. See [LICENSE](LICENSE) for details.
