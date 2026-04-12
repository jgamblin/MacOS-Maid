# Contributing to MacOS Maid

Thank you for your interest in contributing to MacOS Maid! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- Python 3.10 or later
- macOS (this tool is macOS-specific)
- Git

### Clone and Install

```bash
# Clone the repository
git clone https://github.com/jgamblin/macos-maid-v2.git
cd macos-maid-v2

# Install in development mode with dev dependencies
pip install -e ".[dev]"
```

This installs MacOS Maid in editable mode along with development dependencies:

- `pytest` - Testing framework
- `pytest-cov` - Code coverage
- `ruff` - Fast Python linter and formatter
- `mypy` - Static type checker

### Verify Installation

```bash
# Check that the CLI works
maid --help

# Run tests
pytest

# Run linter
ruff check .

# Run type checker
mypy src/
```

## How to Write a Module

MacOS Maid uses a modular architecture. Each module implements the `scan()`, `clean()`, and `audit()` pattern.

### Module Structure

1. **Create a new file** in `src/macos_maid/modules/` (e.g., `my_module.py`)
2. **Inherit from `Module`** base class
3. **Implement three methods**: `scan()`, `clean()`, `audit()`
4. **Register in `__init__.py`**

### Example Module

```python
"""My custom module for MacOS Maid."""

from __future__ import annotations

from macos_maid.modules.base import (
    AuditResult,
    CleanResult,
    Module,
    ScanResult,
)


class MyModule(Module):
    """Brief description of what this module does."""

    name = "my_module"  # CLI name (lowercase, underscores)
    category = "dev"  # or "security" or "both"
    requires_sudo = False  # Set to True if module needs admin privileges

    def scan(self) -> ScanResult:
        """Preview what this module would do (dry-run).

        This method should:
        - Identify what would be cleaned
        - Estimate bytes that would be reclaimed
        - Never modify the system

        Returns:
            ScanResult with items and bytes_reclaimable
        """
        items = ["Preview item 1", "Preview item 2"]
        return ScanResult(
            items=items,
            bytes_reclaimable=1024 * 1024,  # 1 MB
            requires_sudo=False,
        )

    def clean(self) -> CleanResult:
        """Execute cleanup operations.

        This method should:
        - Perform actual cleanup
        - Track bytes reclaimed
        - Capture errors without crashing

        Returns:
            CleanResult with items_cleaned, bytes_reclaimed, and errors
        """
        items_cleaned = []
        errors = []
        bytes_reclaimed = 0

        try:
            # Perform cleanup here
            items_cleaned.append("Cleaned item 1")
            bytes_reclaimed = 1024 * 1024
        except Exception as e:
            errors.append(f"Cleanup failed: {e}")

        return CleanResult(
            items_cleaned=items_cleaned,
            bytes_reclaimed=bytes_reclaimed,
            errors=errors,
        )

    def audit(self) -> AuditResult:
        """Run security checks (read-only, never modifies anything).

        This method should:
        - Perform read-only security checks
        - Return findings with severity levels
        - Never modify the system

        Returns:
            AuditResult with status and findings
        """
        # For modules without security checks:
        return AuditResult.empty()

        # For modules with checks:
        # findings = [
        #     Finding(
        #         severity="pass",  # or "info", "warn", "fail"
        #         title="Check Name",
        #         detail="Check result details",
        #         remediation="How to fix (or None)",
        #     )
        # ]
        # return AuditResult(status="pass", findings=findings)
```

### Register Your Module

Edit `src/macos_maid/modules/__init__.py`:

```python
from macos_maid.modules.my_module import MyModule

def get_all_modules() -> list[Module]:
    """Return instances of all available modules."""
    return [
        # ... existing modules ...
        MyModule(),
    ]
```

### Safety Guidelines

When writing a module:

1. **Use allowlists, not denylists**: Only touch files you explicitly know are safe
2. **Never delete user data**: Move to Trash instead, or report in audit mode
3. **Check before cleanup**: Verify files exist and are what you expect
4. **Handle errors gracefully**: Catch exceptions and add to `errors` list
5. **Respect sudo flag**: If `requires_sudo = True`, module is skipped unless `--sudo` is used
6. **Make audit() read-only**: Never modify system in `audit()` method
7. **Test dry-run mode**: Ensure `scan()` never modifies the system

## Testing Requirements

All new modules must include tests.

### Test Structure

Create tests in `tests/modules/test_my_module.py`:

```python
"""Tests for my_module."""

import pytest
from macos_maid.modules.my_module import MyModule


def test_scan_returns_valid_result():
    """Test that scan returns a valid ScanResult."""
    module = MyModule()
    result = module.scan()
    assert isinstance(result.items, list)
    assert result.bytes_reclaimable >= 0


def test_clean_handles_errors():
    """Test that clean handles errors gracefully."""
    module = MyModule()
    result = module.clean()
    assert isinstance(result.errors, list)
    # Should not raise exception


def test_audit_returns_valid_result():
    """Test that audit returns a valid AuditResult."""
    module = MyModule()
    result = module.audit()
    assert result.status in ["pass", "info", "warn", "fail"]
```

### Safety Tests

Include safety tests to prevent dangerous operations:

```python
def test_scan_does_not_modify_system(tmp_path):
    """Verify scan() never modifies the system."""
    module = MyModule()
    # Create test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("test")

    # Run scan
    module.scan()

    # Verify file unchanged
    assert test_file.exists()
    assert test_file.read_text() == "test"


def test_audit_is_read_only(tmp_path):
    """Verify audit() never modifies the system."""
    module = MyModule()
    test_file = tmp_path / "test.txt"
    test_file.write_text("test")

    # Run audit
    module.audit()

    # Verify file unchanged
    assert test_file.exists()
    assert test_file.read_text() == "test"
```

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=macos_maid --cov-report=html

# Run specific test file
pytest tests/modules/test_my_module.py

# Run specific test
pytest tests/modules/test_my_module.py::test_scan_returns_valid_result
```

## Code Style

MacOS Maid uses strict code style enforced by automated tools.

### Ruff (Linter and Formatter)

```bash
# Check for issues
ruff check .

# Auto-fix issues
ruff check --fix .

# Format code
ruff format .
```

Configuration is in `pyproject.toml`:

- Target: Python 3.10+
- Line length: 100 characters
- Rules: E, F, I, N, W, UP (pycodestyle, pyflakes, isort, naming, warnings, pyupgrade)

### Mypy (Type Checker)

```bash
# Run type checker
mypy src/
```

Configuration is in `pyproject.toml`:

- Strict mode enabled
- All type hints required
- No implicit optional

### Code Style Guidelines

1. **Use type hints**: All functions must have type hints for parameters and return values
2. **Use `from __future__ import annotations`**: For forward references
3. **Prefer explicit over implicit**: Clear, verbose code over clever one-liners
4. **Document with docstrings**: All modules, classes, and public functions
5. **Keep functions small**: Each function should do one thing well
6. **Use descriptive names**: `get_cache_size()` not `get_size()`

## Pull Request Process

### Before Submitting

1. **Run tests**: `pytest`
2. **Run linter**: `ruff check .`
3. **Run type checker**: `mypy src/`
4. **Test manually**: Install and test your changes with `maid` CLI
5. **Update docs**: Add your module to `docs/modules.md` if applicable

### PR Guidelines

1. **Create a feature branch**: `git checkout -b feature/my-module`
2. **Write clear commit messages**: Describe what and why, not how
3. **Keep PRs focused**: One feature or fix per PR
4. **Update tests**: Add tests for new features
5. **Update CHANGELOG.md**: Add entry under `[Unreleased]`
6. **Link issues**: Reference related issues in PR description

### Commit Message Format

```
type: brief description

Longer description if needed. Explain what and why, not how.
The how is shown in the code.

Fixes #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:

```
feat: add homebrew module for package cleanup
fix: handle missing config file gracefully
docs: add module development guide to CONTRIBUTING.md
test: add safety tests for system_cache module
```

### Review Process

1. **Automated checks**: GitHub Actions will run tests, linting, and type checking
2. **Code review**: A maintainer will review your PR
3. **Address feedback**: Make changes as requested
4. **Merge**: Once approved, a maintainer will merge your PR

## Questions?

- **Bug reports**: [Open an issue](https://github.com/jgamblin/macos-maid-v2/issues/new)
- **Feature requests**: [Open an issue](https://github.com/jgamblin/macos-maid-v2/issues/new)
- **Questions**: [Open a discussion](https://github.com/jgamblin/macos-maid-v2/discussions/new)

Thank you for contributing to MacOS Maid!
