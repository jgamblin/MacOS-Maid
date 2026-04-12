# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - TBD

### Added

- Complete rewrite from bash to Python for improved maintainability and safety
- 13 modular modules organized by category (dev/security):
  - Dev modules: trash, homebrew, docker, dev_caches, git
  - Security modules: system_integrity, network, wifi, privacy, app_audit, launch_audit, tools
  - Hybrid module: system_cache
- CLI with six commands:
  - `maid clean` - Run cleanup operations
  - `maid audit` - Run security audits (read-only)
  - `maid report` - Generate comprehensive report card
  - `maid init` - Generate default configuration file
  - `maid list` - List all available modules
  - `maid log` - Show last run log
- YAML configuration file (`~/.maid.yml`) with safe defaults
- Dry-run mode enabled by default for first-time users
- Sudo gating: modules that require elevated privileges are opt-in via `--sudo` flag
- Action logging: all cleanup and audit actions logged to `~/.maid/last_run.json`
- Report card output in three formats: terminal (with color), JSON, and markdown
- Apple Silicon and Intel support via platform detection
- Security tool integration (Lynis, osquery, KnockKnock) - runs if installed, suggests installation if not
- Retention-based WiFi cleanup: removes networks older than 90 days (configurable), always keeps current network
- Strict allowlist approach for dev cache cleaning: only touches known regenerable cache directories
- TCC (Transparency, Consent, and Control) permission auditing: reads user-level privacy database
- System integrity checks: SIP, FileVault, Gatekeeper, XProtect, Firewall
- Application and launch daemon auditing: identifies unsigned apps and non-Apple launch items
- Network security checks: firewall status, open listening ports, VPN profiles

### Removed

- Original `maid.sh` bash script
- `diskutil secureErase freespace` - extremely slow and unnecessary on modern SSDs
- `/private/var/folders` deletion - dangerous and breaks system functionality
- Hardcoded SSID deletion - replaced with retention-based approach
- `known_hosts` file deletion - removed for safety
- Forced memory purge - removed as macOS handles memory management automatically
