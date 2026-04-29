# Security Policy

## Privacy and Telemetry

MacOS Maid respects your privacy:

- **No network calls**: MacOS Maid never makes network connections or sends telemetry
- **No data collection**: All operations are performed locally on your machine
- **No external dependencies**: Only uses system utilities and Python standard library (plus click, pyyaml, rich for CLI)

## Privilege Model

MacOS Maid follows the principle of least privilege:

### Unprivileged by Default

Most operations run without elevated privileges. Modules that require `sudo` are:

- `wifi` - Removing WiFi networks requires admin privileges
- `network` - DNS cache flush requires admin privileges
- `system_cache` - Cleaning system logs requires admin privileges
- `privacy` - Clearing recent items requires admin privileges

### Sudo Opt-In

Privileged modules are **disabled by default**. To enable them, use the `--sudo` flag:

```bash
maid clean --sudo
maid audit --sudo
```

When you use `--sudo`, you will be prompted for your password. MacOS Maid never stores or caches credentials.

### What Gets Sudo and Why

| Module         | Operation             | Why Sudo?                                                           |
| -------------- | --------------------- | ------------------------------------------------------------------- |
| `wifi`         | Remove WiFi networks  | macOS requires admin privileges to modify network settings          |
| `network`      | Flush DNS cache       | `dscacheutil -flushcache` and restarting mDNSResponder require sudo |
| `system_cache` | Clean diagnostic logs | `/Library/Logs/DiagnosticReports` requires admin access             |
| `privacy`      | Clear recent items    | Writing to system preferences requires elevated privileges          |

All other modules operate on user-owned files and directories.

## Safe Defaults

MacOS Maid ships with safe defaults:

### Dry-Run Mode

First-time users automatically run in dry-run mode:

```bash
# First run without config - automatically dry-run
maid clean

# Generate config to enable real operations
maid init
maid clean
```

### Git Module Disabled

The `git` module is **disabled by default** and requires explicit configuration:

```yaml
git:
  enabled: true
  repos_dir: ~/Code
  delete_merged: false # Even when enabled, deletion is opt-in
```

### WiFi Safety

The `wifi` module **always keeps** the currently connected network, regardless of configuration. This is hardcoded and not configurable to prevent locking yourself out of your network.

### No Downloads Deletion

The `privacy` module **never deletes** files from your Downloads folder. It only reports on old files in audit mode.

## Audit-Only Modules

Several modules are **read-only** and never modify your system:

- `system_integrity` - Checks SIP, FileVault, Gatekeeper, XProtect, Firewall
- `app_audit` - Scans for unsigned applications
- `launch_audit` - Lists non-Apple launch daemons and agents
- `tools` - Runs external security tools (Lynis, osquery, KnockKnock)

These modules have empty `clean()` implementations and only report findings via `audit()`.

## Dangerous Operations Removed

The original `maid.sh` performed several dangerous operations that have been **permanently removed**:

- ❌ `/private/var/folders` deletion - breaks system functionality
- ❌ `diskutil secureErase freespace` - extremely slow and unnecessary on modern SSDs
- ❌ Hardcoded SSID deletion - replaced with retention-based approach
- ❌ `known_hosts` file deletion - removed for safety
- ❌ Forced memory purge - removed as macOS handles memory automatically

## Reporting Vulnerabilities

We take security seriously. If you discover a security vulnerability in MacOS Maid, please report it via:

### GitHub Security Advisories

Use [GitHub Security Advisories](https://github.com/jgamblin/macos-maid-v2/security/advisories/new) to privately report vulnerabilities.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### Response Timeline

- We will acknowledge your report within 48 hours
- We will provide a detailed response within 7 days
- We will work with you to understand and fix the issue
- We will credit you in the security advisory (unless you prefer to remain anonymous)

## Security Best Practices

When using MacOS Maid:

1. **Review the config**: Run `maid init` and review `~/.maid.yml` before enabling real operations
2. **Use dry-run first**: Always run `maid clean --dry-run` before real operations
3. **Check the report**: Review module actions in the terminal output
4. **Review logs**: Check `~/.maid/last_run.json` after each run
5. **Be cautious with sudo**: Only use `--sudo` when you need privileged modules
6. **Review Git config**: Only enable the `git` module with `delete_merged: false` initially
7. **Check audit results**: Run `maid audit --sudo` to review security findings

## Code Signing and Distribution

- MacOS Maid is distributed via PyPI and Homebrew
- The Python package is built with modern packaging standards (PEP 517)
- Homebrew formula verifies checksums before installation
- No pre-compiled binaries - all code is source-distributed and installed via pip
