# 1. Use a specific version of the Debian image
FROM debian:12.5-slim

ENV DEBIAN_FRONTEND=noninteractive

COPY sources.list /etc/apt/sources.list

# 3. Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    dracut \
    linux-image-amd64 \
    kmod \
    curl \
    build-essential \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# 4. Install Rust
ARG RUST_VERSION=1.77.2
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# We use the full path for 'sh' to ensure standard behavior
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain ${RUST_VERSION} --no-modify-path

# --- FIX 1: Install the Rust Musl target ---
# We use '. $CARGO_HOME/env' to load the path variables into the current shell session
# before running rustup. This guarantees the command is found.
RUN . "$CARGO_HOME/env" && rustup target add x86_64-unknown-linux-musl

# 5. Set up environment for reproducible musl builds
ENV CC_x86_64_unknown_linux_musl="musl-gcc" \
    CXX_x86_64_unknown_linux_musl="musl-g++" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="musl-gcc" \
    AR_x86_64_unknown_linux_musl="ar"

# 6. Set up the application build environment
WORKDIR /app

# 7. Copy all project files
COPY . .

# 8. Make the build script executable
RUN chmod +x ./build-initramfs-dracut.sh

# --- FIX 2: Explicitly source the Cargo environment ---
# We use '.' (dot) instead of 'source' for strict POSIX compliance (Debian/Dash).
# This ensures PATH is correct even if the shell ignores the ENV instruction.
RUN . "$CARGO_HOME/env" && ./build-initramfs-dracut.sh

# 10. Output handling
RUN mkdir /output && \
    mv initramfs-paypal-auth.img /output/ && \
    mv luks.key /output/ && \
    mv build-manifest.json /output/ && \
    mv initramfs-paypal-auth.img.sha256 /output/

WORKDIR /output

CMD ["ls", "-l", "/output"]