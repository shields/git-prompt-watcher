# Default recipe
default:
  just --list

# Install Rust dependencies and build
sync:
  cargo fetch

# Run Rust tests
test:
  cargo test

# Run tests with verbose output (parallel)
test-verbose:
  cargo test -- --nocapture

# Run specific test
test-one TEST:
  cargo test {{TEST}}

# Run only the simple basic tests
test-simple:
  cargo test --test simple_test

# Run the main test suite (may have some unimplemented parts)
test-main:
  cargo test --test git_prompt_watcher_tests

# Clean up build artifacts
clean:
  cargo clean
  rm -rf .pytest_cache/
  rm -rf __pycache__/
  rm -rf .venv/
  find . -name "*.pyc" -delete
  find . -name "*.pyo" -delete

# Format Rust code
fmt:
  cargo fmt

# Lint Rust code with aggressive settings
lint:
  cargo fmt --check
  cargo clippy --all-targets --all-features -- -D warnings -D clippy::all -D clippy::pedantic -D clippy::nursery -D clippy::cargo

# Fix linting issues automatically
fix:
  cargo fmt
  cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features

# Lint with even more aggressive settings (may be too strict for some projects)
lint-aggressive:
  cargo fmt --check
  cargo clippy --all-targets --all-features -- \
    -D warnings \
    -D clippy::all \
    -D clippy::pedantic \
    -D clippy::nursery \
    -D clippy::cargo \
    -D clippy::restriction \
    -W clippy::missing_docs_in_private_items \
    -W clippy::unwrap_used \
    -W clippy::expect_used \
    -W clippy::panic \
    -W clippy::unimplemented \
    -W clippy::todo

# Check Rust code
check:
  cargo check

# Build the project
build:
  cargo build

# Build in release mode
build-release:
  cargo build --release

# Run all checks (Rust version)
ci: lint check test-verbose

# Legacy Python test support (if Python tests directory exists)
test-python:
  #!/usr/bin/env bash
  if [ -d "tests" ] && [ -f "tests/pyproject.toml" ]; then
    cd tests && uv sync --extra dev
    cd tests && uv run --no-project pytest -n auto -v
  else
    echo "No Python tests found"
  fi

# Run CI checks in Docker container (legacy)
docker-ci:
  #!/usr/bin/env bash
  if [ -f "tests/Dockerfile" ]; then
    docker build -t git-prompt-watcher-test -f tests/Dockerfile .
    docker run --rm git-prompt-watcher-test
  else
    echo "No Dockerfile found, running Rust tests instead"
    just ci
  fi
