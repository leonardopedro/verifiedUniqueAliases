FROM docker.io/library/ubuntu:25.10 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Update and install minimal build dependencies for a measured initramfs
RUN apt-get update && apt-get upgrade -y --no-install-recommends && apt-get install -y --no-install-recommends \
    initramfs-tools \
    linux-image-gcp \
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
    sudo \
    mtools \
    dosfstools \
    fdisk \
    gdisk \
    qemu-utils \
    pkg-config \
    libssl-dev \
    file \
    zstd \
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
ENV RUSTFLAGS="-C target-cpu=generic -C codegen-units=1 -C strip=symbols" \
    CARGO_PROFILE_RELEASE_LTO=true \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=2
RUN cargo build --release -j 1 --target x86_64-unknown-linux-gnu && rm -rf src

# --- Actual build ---
COPY src ./src
COPY hooks ./hooks
COPY scripts ./scripts
COPY build-initramfs-tools.sh ./build-initramfs-tools.sh
COPY build-gcp-gpt-image.sh ./build-gcp-gpt-image.sh
RUN chmod +x build-initramfs-tools.sh build-gcp-gpt-image.sh hooks/* scripts/init-premount/*

# Build the real application and initramfs
RUN sh -c ". /usr/local/cargo/env && ./build-initramfs-tools.sh"

# Extract minimal OS artifacts to root for GPT script
RUN cp /boot/vmlinuz-*gcp ./output/vmlinuz && \
    cp $(find /usr/lib/shim/ -name 'shimx64.efi.signed' 2>/dev/null | head -1) ./output/shimx64.efi && \
    cp $(find /usr/lib/grub/ -name 'grubx64.efi.signed' 2>/dev/null | head -1) ./output/grubx64.efi || echo "Bootloader not found"

# Run the generic GPT image synthesizer exactly as it runs in the cloud
RUN ./build-gcp-gpt-image.sh

# Extract minimal OS artifacts
RUN mkdir /final_export && cp disk.tar.gz /final_export/ && cp disk.raw /final_export/ && cp output/initramfs-paypal-auth.img /final_export/

WORKDIR /final_export

FROM scratch AS export-stage
COPY --from=builder /final_export/ ./img/
