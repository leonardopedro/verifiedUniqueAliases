FROM docker.io/library/ubuntu:25.10 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Update and install minimal build dependencies for a measured initramfs
RUN apt-get update && apt-get install -y --no-install-recommends \
    dracut-core \
    dracut-network \
    linux-image-gcp \
    linux-modules-extra-gcp \
    shim-signed \
    grub-efi-amd64-signed \
    tpm2-tools \
    curl \
    gcc \
    g++ \
    make \
    python3 \
    python3-pip \
    python3-venv \
    libarchive-tools \
    binutils \
    ca-certificates \
    zlib1g-dev \
    perl \
    iproute2 \
    isc-dhcp-client \
    net-tools \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Setup diffoscope for reproducibility checks
RUN python3 -m venv /opt/diffoscope-venv \
    && /opt/diffoscope-venv/bin/pip install --upgrade pip \
    && /opt/diffoscope-venv/bin/pip install diffoscope
ENV PATH="/opt/diffoscope-venv/bin:$PATH"

ARG RUST_VERSION=1.91.1
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal --no-modify-path \
    && . /usr/local/cargo/env \
    && export RUST_MIN_STACK=16777216 \
    && cargo install -j 1 add-determinism \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git

# --- Pre-build dependencies for caching ---
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
# Provide the exact same RUSTFLAGS and profile variables as module-setup.sh uses!
# If these don't match, Cargo's fingerprint will change and it will recompile everything.
ENV RUSTFLAGS="-C target-cpu=generic -C codegen-units=1 -C strip=symbols" \
    CARGO_PROFILE_RELEASE_LTO=true \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=2
RUN cargo build --release -j 1 --target x86_64-unknown-linux-gnu && rm -rf src

# --- Actual build ---
COPY src ./src
COPY dracut-module ./dracut-module
COPY build-initramfs-dracut.sh dracut.conf ./
RUN chmod +x build-initramfs-dracut.sh

# Build the real application and initramfs
RUN sh -c ". /usr/local/cargo/env && ./build-initramfs-dracut.sh"

# Extract minimal OS artifacts
RUN mkdir /output && \
    mv initramfs-paypal-auth.img /output/ && \
    mv build-manifest.json /output/ && \
    mv initramfs-paypal-auth.img.sha256 /output/ && \
    cp /boot/vmlinuz-*gcp /output/vmlinuz && \
    cp /usr/lib/shim/shimx64.efi.signed /output/shimx64.efi && \
    cp /usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed /output/grubx64.efi || echo "Bootloader not found"

WORKDIR /output

FROM scratch AS export-stage
COPY --from=builder /output/ ./img/
