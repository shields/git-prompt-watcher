FROM rust:1.89.0-slim-bookworm@sha256:21e2ac30e72a6d5b6d667b573eadad0578be9a5a99bac0b2b99b3d37795f90f9

# Use Debian snapshot for reproducible builds
RUN echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20250718T023724Z bookworm main" > /etc/apt/sources.list \
    && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20250718T023724Z bookworm-security main" >> /etc/apt/sources.list \
    && echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20250718T023724Z bookworm-updates main" >> /etc/apt/sources.list \
    && apt-get update && apt-get install -y \
    curl=7.88.1-10+deb12u12 \
    fswatch=1.14.0+repack-13.1+b1 \
    git=1:2.39.5-0+deb12u2 \
    zsh=5.9-4+b6 \
    pkg-config=1.8.1-1 \
    libssl-dev=3.0.17-1~deb12u2 \
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
