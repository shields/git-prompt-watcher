# Default recipe
default:
  just --list

# Install dependencies
sync:
  cd tests && uv sync --dev

# Run tests
test: sync
  cd tests && uv run --no-project pytest

# Run tests with verbose output
test-verbose: sync
  cd tests && uv run --no-project pytest -v

# Clean up build artifacts
clean:
  rm -rf .pytest_cache/
  rm -rf __pycache__/
  rm -rf .venv/
  find . -name "*.pyc" -delete
  find . -name "*.pyo" -delete

# Format code with ruff
fmt: sync
  cd tests && uv run --no-project ruff format .

# Lint code with ruff
lint: sync
  cd tests && uv run --no-project ruff format --check .
  cd tests && uv run --no-project ruff check .

# Fix linting issues automatically
fix: sync fmt
  cd tests && uv run --no-project ruff check . --fix

# Check types with ruff
check: sync
  cd tests && uv run --no-project ruff check . --select=E,W,F

# Run all checks
ci: lint check test-verbose

# Run CI checks in Docker container
docker-ci:
  docker build -t git-prompt-watcher-test -f tests/Dockerfile .
  docker run --rm git-prompt-watcher-test
