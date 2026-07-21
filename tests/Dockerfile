FROM rust:1.97.1-slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777

# Use Debian snapshot for reproducible builds.
# The snapshot provides immutable package versions; the base image is pinned by
# digest. Together these give reproducibility without fragile version pins that
# break when the base image's pre-installed packages drift from the snapshot.
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260523T211231Z bookworm main" > /etc/apt/sources.list \
    && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260523T195511Z bookworm-security main" >> /etc/apt/sources.list \
    && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260523T211231Z bookworm-updates main" >> /etc/apt/sources.list \
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

RUN curl --proto '=https' -fsSL https://starship.rs/install.sh | sh -s -- --yes --version v1.21.1

RUN git config --global init.defaultBranch main

# Install Rust components needed for CI
RUN rustup component add rustfmt clippy

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY tests/ ./tests/
COPY git-prompt-watcher.plugin.zsh ./
COPY justfile ./

CMD ["just", "ci"]
