# MacOS Maid Modules

This document provides detailed information about each of the 13 modules in MacOS Maid.

## Table of Contents

- [Dev Modules](#dev-modules)
  - [trash](#trash)
  - [homebrew](#homebrew)
  - [docker](#docker)
  - [dev_caches](#dev_caches)
  - [git](#git)
- [Security Modules](#security-modules)
  - [system_integrity](#system_integrity)
  - [network](#network)
  - [wifi](#wifi)
  - [privacy](#privacy)
  - [app_audit](#app_audit)
  - [launch_audit](#launch_audit)
  - [tools](#tools)
- [Hybrid Modules](#hybrid-modules)
  - [system_cache](#system_cache)

---

## Dev Modules

### trash

**Category:** dev  
**Requires sudo:** No

#### What it does

Reports the size of your Trash and optionally empties it.

#### System commands

- `du -sk ~/.Trash` - Calculate trash size
- `osascript -e 'tell application "Finder" to empty trash'` - Empty trash via AppleScript

#### Config options

None. This module has no configuration options.

#### Usage

```bash
# Preview trash size
maid clean --dry-run

# Empty trash
maid clean
```

#### Known limitations

- Only empties user Trash (`~/.Trash`), not system-wide trash
- Does not bypass "locked" files - Finder's empty trash behavior applies

---

### homebrew

**Category:** dev  
**Requires sudo:** No

#### What it does

Updates Homebrew, upgrades outdated packages, and cleans up old versions and cache.

#### System commands

- `brew --cache` - Get cache directory location
- `brew outdated --quiet` - List outdated packages
- `brew update` - Update Homebrew itself
- `brew upgrade` - Upgrade all outdated packages
- `brew cleanup --prune=all` - Remove old versions and clean cache
- `du -sk <cache-dir>` - Calculate cache size

#### Config options

None. This module has no configuration options.

#### Usage

```bash
# Preview what would be updated/cleaned
maid clean --dry-run

# Run homebrew cleanup
maid clean --modules homebrew
```

#### Known limitations

- Only runs if `brew` command is found in PATH
- Returns empty results if Homebrew is not installed
- Does not prompt for confirmation before upgrading packages

---

### docker

**Category:** dev  
**Requires sudo:** No

#### What it does

Cleans up Docker dangling (untagged) images and unused (dangling) volumes. Never touches stopped containers.

#### System commands

- `docker info` - Check if Docker daemon is running
- `docker images -q --filter dangling=true` - List dangling images
- `docker volume ls -q --filter dangling=true` - List unused volumes
- `docker image prune -f` - Remove dangling images
- `docker volume prune -f` - Remove unused volumes

#### Config options

None. This module has no configuration options.

#### Usage

```bash
# Preview what would be cleaned
maid clean --dry-run

# Clean docker resources
maid clean --modules docker
```

#### Known limitations

- Only runs if Docker is installed and daemon is running
- Returns empty results if Docker is not running
- Does not calculate actual bytes reclaimed (reports 0)
- Does not remove stopped containers (by design - safety feature)

---

### dev_caches

**Category:** dev  
**Requires sudo:** No

#### What it does

Safely removes and recreates regenerable development tool caches. Uses strict allowlist approach - only touches known cache directories.

#### System commands

- `du -sk <cache-dir>` - Calculate cache size
- Python's `shutil.rmtree()` - Remove cache directories
- Python's `Path.mkdir()` - Recreate empty directories

#### Cleaned cache directories

- **pip**: `~/Library/Caches/pip`
- **npm**: `~/.npm/_cacache`
- **cargo**: `~/.cargo/registry/cache` (NOT registry/src - source files preserved)
- **gradle**: `~/.gradle/caches`
- **cocoapods**: `~/Library/Caches/CocoaPods`
- **xcode_derived**: `~/Library/Developer/Xcode/DerivedData`

#### Config options

None. This module has no configuration options.

#### Usage

```bash
# Preview cache sizes
maid clean --dry-run

# Clean dev caches
maid clean --modules dev_caches
```

#### Known limitations

- Does NOT clean `node_modules`, `.venv`, `target/`, `build/`, or any project directories
- Only cleans the specific cache directories listed above
- Directories are recreated empty after deletion

#### Safety features

- **Strict allowlist**: Only touches explicitly listed cache directories
- **Never touches project directories**: Will not delete `node_modules`, virtual environments, or build artifacts
- **Preserves source**: Does not delete Cargo's `registry/src` (compiled sources)

---

### git

**Category:** dev  
**Requires sudo:** No

#### What it does

Cleans up git repositories: prunes remote branches, optionally deletes merged branches, reports large repos.

#### System commands

- `git symbolic-ref refs/remotes/origin/HEAD` - Get default branch name
- `git branch --merged <default-branch>` - List merged branches
- `git remote prune origin` - Remove stale remote-tracking branches
- `git branch -d <branch>` - Delete merged local branch
- `du -sk <repo-path>` - Calculate repo size

#### Config options

```yaml
git:
  enabled: false # REQUIRED - must be explicitly enabled
  repos_dir: ~/Code # REQUIRED - directory containing git repos
  prune_remotes: true # Prune stale remote-tracking branches
  delete_merged: false # Delete local branches merged into default branch
  protected_branches: # Branches to never delete
    - main
    - master
    - develop
  report_large_repos: true # Report repos over 1GB
```

#### Usage

```bash
# Module is disabled by default
maid clean --dry-run  # Will skip git module

# Enable in config first
maid init
# Edit ~/.maid.yml and set git.enabled: true

# Preview git cleanup
maid clean --dry-run

# Run git cleanup
maid clean --modules git
```

#### Known limitations

- **Disabled by default**: Must be explicitly enabled in config
- Requires `repos_dir` to be set
- Only scans direct subdirectories of `repos_dir` (not recursive)
- Does not calculate bytes reclaimed from pruning/deleting

#### Safety features

- **Disabled by default**: Must opt-in via config
- **Protected branches**: Never deletes main/master/develop (configurable)
- **Merged check**: Only deletes branches that are fully merged
- **Current network preserved**: If WiFi module, always keeps current SSID

---

## Security Modules

### system_integrity

**Category:** security  
**Requires sudo:** No

#### What it does

Audit-only module that checks critical macOS security settings. Never modifies the system.

#### System commands

- `csrutil status` - Check System Integrity Protection (SIP)
- `fdesetup status` - Check FileVault encryption status
- `spctl --status` - Check Gatekeeper status
- `system_profiler SPInstallHistoryDataType` - Check for XProtect installation
- `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` - Check firewall status

#### Checks performed

1. **System Integrity Protection (SIP)**: Verifies SIP is enabled
2. **FileVault**: Verifies disk encryption is enabled
3. **Gatekeeper**: Verifies Gatekeeper is enabled
4. **XProtect**: Verifies Apple's malware protection is installed
5. **Firewall**: Verifies macOS Application Firewall is enabled

#### Config options

None. This module has no configuration options.

#### Usage

```bash
# Run security audit
maid audit

# Include in full report
maid report
```

#### Severity levels

- **pass**: Security feature is enabled
- **fail**: Security feature is disabled (action required)
- **warn**: Could not verify status (manual check needed)

---

### network

**Category:** security  
**Requires sudo:** Yes

#### What it does

Flushes DNS cache and audits network security (firewall, open ports, VPN profiles).

#### System commands

**Clean operations (requires sudo):**

- `sudo dscacheutil -flushcache` - Flush DNS cache
- `sudo killall -HUP mDNSResponder` - Restart DNS responder

**Audit operations (no sudo):**

- `lsof -iTCP -sTCP:LISTEN -nP` - List open TCP listening ports
- `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` - Check firewall status
- `scutil --nc list` - List VPN profiles

#### Config options

None. This module has no configuration options.

#### Usage

```bash
# Flush DNS (requires --sudo)
maid clean --sudo --modules network

# Audit network security (no sudo needed for audit)
maid audit
```

#### Audit findings

- **Firewall Status**: Reports if firewall is enabled/disabled
- **Open Listening Ports**: Reports processes listening on TCP ports
- **VPN Profiles**: Reports configured VPN connections

---

### wifi

**Category:** security  
**Requires sudo:** Yes

#### What it does

Removes stale WiFi networks based on retention policy. Always keeps the currently connected network.

#### System commands

- `networksetup -getairportnetwork <interface>` - Get current WiFi network
- `networksetup -listpreferredwirelessnetworks <interface>` - List saved networks
- `sudo networksetup -removepreferredwirelessnetwork <interface> <ssid>` - Remove network

#### Config options

```yaml
wifi:
  keep_days: 90 # Keep networks joined within this many days
  keep_ssids: # Always keep these networks
    - HomeNetwork
    - WorkNetwork
  interface: en0 # Network interface (default: en0)
```

#### Usage

```bash
# Preview which networks would be removed
maid clean --dry-run --sudo

# Remove stale networks
maid clean --sudo --modules wifi
```

#### Known limitations

- `networksetup` does not expose last-joined timestamps, so time-based retention is not yet implemented
- Currently only removes networks not in `keep_ssids` list
- Requires sudo to modify network settings

#### Safety features

- **Always keeps current network**: Hardcoded safety check, not configurable
- **Allowlist approach**: Networks in `keep_ssids` are never removed
- **Requires sudo flag**: Must explicitly opt-in with `--sudo`

---

### privacy

**Category:** security  
**Requires sudo:** Yes

#### What it does

Clears recent items (applications, documents, servers) and audits TCC privacy permissions. Reports on old Downloads files but never deletes them.

#### System commands

**Clean operations (requires sudo):**

- `osascript` - Clear recent items via AppleScript

**Audit operations (no sudo):**

- SQLite read of `~/Library/Application Support/com.apple.TCC/TCC.db` (read-only)
- File scanning of `~/Downloads` directory

#### Config options

```yaml
privacy:
  clear_recent: true # Clear recent items
  downloads_move_to_trash: false # Report only (deletion not implemented)
  downloads_older_than: 90 # Age threshold for old downloads (days)
```

#### Usage

```bash
# Clear recent items (requires --sudo)
maid clean --sudo --modules privacy

# Audit privacy settings
maid audit
```

#### Audit findings

- **TCC Permissions**: Reports apps with sensitive permissions:
  - Screen Capture
  - Full Disk Access
  - Accessibility
  - Camera
  - Microphone
- **Old Downloads**: Reports files in Downloads older than threshold (report only, never deletes)

#### Safety features

- **Never deletes Downloads**: Only reports in audit mode
- **Read-only TCC access**: Opens database in read-only mode (`?mode=ro`)
- **User-level only**: Only reads user TCC database, never requests Full Disk Access

---

### app_audit

**Category:** security  
**Requires sudo:** No

#### What it does

Audit-only module that scans installed applications for code signing status and elevated permissions.

#### System commands

- `codesign -v <app-path>` - Verify code signature
- `codesign -d --verbose=2 <app-path>` - Check if from App Store
- `defaults read <Info.plist> SMPrivilegedExecutables` - Check for privileged helpers
- File system scanning of helper paths

#### Checks performed

1. **Code signing**: Is the app signed by a developer?
2. **App Store**: Is the app from the Mac App Store?
3. **Elevated permissions**: Does the app have privileged helper tools?

#### Config options

None. This module has no configuration options.

#### Usage

```bash
# Run app security audit
maid audit

# Include in full report
maid report
```

#### Severity levels

- **pass**: All apps are signed or from App Store
- **info**: Unsigned app but appears sandboxed
- **warn**: Unsigned app with elevated permissions

#### Scanned locations

- `/Applications` - System-wide applications
- Does not scan user applications in `~/Applications`

---

### launch_audit

**Category:** security  
**Requires sudo:** No

#### What it does

Audit-only module that lists non-Apple launch daemons and agents. Never removes or disables them.

#### System commands

- File system scanning of launch directories
- No system commands executed

#### Scanned directories

- `/Library/LaunchDaemons` - System-wide daemons
- `/Library/LaunchAgents` - System-wide agents
- `~/Library/LaunchAgents` - User agents

#### Config options

None. This module has no configuration options.

#### Usage

```bash
# Run launch item audit
maid audit

# Include in full report
maid report
```

#### Behavior

- Scans for `.plist` files in launch directories
- Filters out `com.apple.*` items (Apple's own services)
- Reports non-Apple items as "info" findings
- Never disables or removes items

---

### tools

**Category:** security  
**Requires sudo:** No

#### What it does

Integrates with external security tools (Lynis, osquery, KnockKnock). Runs tools if installed, suggests installation if not.

#### External tools

**Lynis** - Comprehensive security auditing

- Install: `brew install lynis`
- Command: `lynis audit system --quick --no-colors`

**osquery** - System querying and monitoring

- Install: `brew install osquery`
- Command: `osqueryi --json <query>`

**KnockKnock** - Persistent malware detection

- Download: https://objective-see.org/products/knockknock.html
- GUI application (CLI integration limited)

#### Config options

```yaml
tools:
  lynis_enabled: true # Run Lynis if installed
  osquery_enabled: true # Run osquery if installed
  knockknock_enabled: false # Run KnockKnock if installed
```

#### Usage

```bash
# Run security tools audit
maid audit

# Include in full report
maid report
```

#### Lynis checks

- Parses hardening index (0-100 score)
- Reports warnings and suggestions
- Severity based on hardening index:
  - 80+: pass
  - 60-79: warn
  - <60: fail

#### osquery checks

- Unsigned processes detection
- Network listener detection
- Custom SQL queries against system tables

#### Known limitations

- Only runs tools if already installed
- Never installs tools automatically
- KnockKnock integration limited (primarily a GUI app)
- Lynis can be slow (120 second timeout)

---

## Hybrid Modules

### system_cache

**Category:** both (dev + security)  
**Requires sudo:** Yes

#### What it does

Cleans system caches and diagnostic logs. Never touches `/private/var/folders` (unlike the original script).

#### System commands

- `du -sk <directory>` - Calculate directory size
- Python's `Path.unlink()` - Delete files
- `rm -rf <directory>` - Remove directories (for cache contents)

#### Cleaned directories

**Caches (contents removed, directory kept):**

- `~/Library/Caches`

**Logs (files removed):**

- `/Library/Logs/DiagnosticReports` (requires sudo)
- `~/Library/Logs/DiagnosticReports`

#### Config options

None. This module has no configuration options.

#### Usage

```bash
# Preview what would be cleaned
maid clean --dry-run --sudo

# Clean system caches and logs
maid clean --sudo --modules system_cache
```

#### Safety features

- **Never touches `/private/var/folders`**: The original script cleaned this directory and it was extremely dangerous
- **Keeps directory structure**: Removes contents but keeps the directories themselves
- **User-facing only**: Only cleans user-accessible cache and diagnostic logs

#### Known limitations

- Requires sudo for system-level diagnostic reports
- Does not clean `/private/var/` directories (by design)
- Does not clean system logs in `/var/log` (by design)

---

## Module Selection

You can run specific modules or categories:

```bash
# Run all dev modules
maid clean --dev

# Run all security modules
maid clean --security

# Run specific modules
maid clean --modules trash,homebrew,docker

# Run with sudo for privileged modules
maid clean --sudo

# Dry-run mode (preview only)
maid clean --dry-run
```

## Module Status

Check which modules are available:

```bash
maid list
```

Output:

```
Module               Category      Sudo?
----------------------------------------
trash                dev           no
homebrew             dev           no
docker               dev           no
dev_caches           dev           no
git                  dev           no
system_integrity     security      no
network              security      yes
wifi                 security      yes
privacy              security      yes
app_audit            security      no
launch_audit         security      no
tools                security      no
system_cache         both          yes
```

## Writing Your Own Module

See [CONTRIBUTING.md](../CONTRIBUTING.md) for a guide on writing custom modules.
