FROM rust:1.93.1-slim-bookworm@sha256:fbd2b275db4cf82b6ffd911264ea7dd6ef7af1940e3244e6a4e9d1120d0b12af

# Use Debian snapshot for reproducible builds.
# The snapshot provides immutable package versions; the base image is pinned by
# digest. Together these give reproducibility without fragile version pins that
# break when the base image's pre-installed packages drift from the snapshot.
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260212T022628Z bookworm main" > /etc/apt/sources.list \
    && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260212T143415Z bookworm-security main" >> /etc/apt/sources.list \
    && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260212T022628Z bookworm-updates main" >> /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    curl \
    fswatch \
    git \
    zsh \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/0.8.0/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

RUN curl --proto '=https' -sSf https://just.systems/install.sh | bash -s -- --to /usr/local/bin --tag 1.42.2

RUN curl -sS https://starship.rs/install.sh | sh -s -- --yes --version v1.21.1

RUN git config --global init.defaultBranch main

# Install Rust components needed for CI
RUN rustup component add rustfmt clippy

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY tests/ ./tests/
COPY git-prompt-watcher.plugin.zsh ./
COPY justfile ./

CMD ["just", "ci"]
