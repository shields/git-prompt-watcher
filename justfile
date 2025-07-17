# Default recipe
default:
  just --list

# Install dependencies
sync:
  uv sync --dev

# Run tests
test: sync
  uv run --no-project pytest

# Run tests with verbose output
test-verbose: sync
  uv run --no-project pytest -v

# Clean up build artifacts
clean:
  rm -rf .pytest_cache/
  rm -rf __pycache__/
  rm -rf .venv/
  find . -name "*.pyc" -delete
  find . -name "*.pyo" -delete

# Format code with ruff
fmt: sync
  uv run --no-project ruff format .

# Lint code with ruff
lint: sync
  uv run --no-project ruff format --check .
  uv run --no-project ruff check .

# Fix linting issues automatically
fix: sync fmt
  uv run --no-project ruff check . --fix

# Check types with ruff
check: sync
  uv run --no-project ruff check . --select=E,W,F

# Run all checks
ci: lint check test-verbose
