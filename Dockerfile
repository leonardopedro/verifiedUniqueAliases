# Dockerfile for building reproducible initramfs on Oracle Linux
# This runs Dracut in a proper FHS environment where all tools work correctly

# Use Oracle Linux 9 with UEK R7 for SEV-SNP compatibility
FROM oraclelinux:9-slim AS builder

# Install UEK R7 repository and core packages
RUN microdnf install -y oracle-epel-release-el9 \
    && microdnf install -y \
    # UEK R7 kernel (SEV-SNP compatible)
    kernel-uek-core \
    kernel-uek-modules \
    kmod \
    # Dracut for initramfs generation
    dracut \
    # Build essentials
    curl \
    gcc \
    gcc-c++ \
    make \
    util-linux \
    # Python for reproducibility tools
    python3 \
    python3-pip \
    libarchive \
    git \
    cpio \
    gzip \
    xz \
    && microdnf clean all

# Verify UEK kernel is installed (this is the EXACT kernel used on OCI instances)
RUN echo "=== Installed UEK Kernel ===" && \
    rpm -qa | grep kernel-uek && \
    KERNEL_VER=$(ls /lib/modules | head -n1) && \
    echo "Kernel version: $KERNEL_VER" && \
    ls -la /lib/modules/$KERNEL_VER/

# Install Rust
ARG RUST_VERSION=1.91.1
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal --no-modify-path \
    && source /usr/local/cargo/env \
    && rustup target add x86_64-unknown-linux-gnu \
    && export RUST_MIN_STACK=16777216 \
    && cargo install -j 1 add-determinism \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git

# Set up application directory
WORKDIR /app

# Copy project files
COPY . .

# Copy dracut module to system location
COPY dracut-module/99paypal-auth-vm /usr/lib/dracut/modules.d/99paypal-auth-vm

# Copy dracut configuration
RUN mkdir -p /etc/dracut.conf.d
COPY dracut.conf /etc/dracut.conf.d/99-paypal-auth.conf
COPY dracut.conf /etc/dracut.conf

# Set permissions
RUN chmod +x ./build-initramfs-dracut.sh \
    && chmod +x /usr/lib/dracut/modules.d/99paypal-auth-vm/*.sh

# DEBUG: Verify setup
RUN echo "=== Kernel Version ===" && \
    ls /lib/modules/ && \
    echo "=== Dracut Module ===" && \
    ls -la /usr/lib/dracut/modules.d/99paypal-auth-vm/

# Run the build
RUN sh -c "source /usr/local/cargo/env && ./build-initramfs-dracut.sh"

# Create output directory
RUN mkdir /output && \
    cp initramfs-paypal-auth.img /output/ 2>/dev/null || true && \
    cp vmlinuz /output/ 2>/dev/null || true && \
    cp build-manifest.json /output/ 2>/dev/null || true && \
    cp *.sha256 /output/ 2>/dev/null || true

WORKDIR /output

# Export stage
FROM scratch AS export-stage
COPY --from=builder /output/ ./img/
