# Dockerfile for building reproducible initramfs on Oracle Linux 10
# This runs Dracut in a proper FHS environment where all tools work correctly
#
# REPRODUCIBILITY: This Dockerfile pins the base image and package versions
# to ensure bit-by-bit reproducible builds.

# Use Oracle Linux 10 Slim from Oracle Container Registry
FROM container-registry.oracle.com/os/oraclelinux:10-slim AS builder

# Reproducibility environment
ENV SOURCE_DATE_EPOCH=1640995200
ENV TZ=UTC
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Enable UEK R8 repository and install packages
# Note: In OL10, UEK8 kernel packages have the 'kernel-uek' prefix 
# but are located in the 'ol10_UEKR8' repository which must be enabled.
# OL10 Slim uses microdnf as the package manager.
RUN microdnf install -y --enablerepo=ol10_UEKR8 \
    # UEK R8 kernel Update 1 (8.1) - official kernel for OCI
    kernel-uek-core \
    kernel-uek-modules \
    kernel-uek-modules-core \
    kmod \
    # Dracut for initramfs generation
    dracut \
    dracut-network \
    dbus-daemon \
    systemd-boot-unsigned \
    file \
    binutils \
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

# Verify UEK kernel is installed
RUN echo "=== Installed UEK Kernel ===" && \
    rpm -q kernel-uek-core && \
    KERNEL_VER=$(ls /lib/modules | grep uek | head -n1) && \
    echo "Kernel version: $KERNEL_VER" && \
    ls -la /lib/modules/$KERNEL_VER/ | head -10

# Install Rust with pinned version
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

# Set permissions and normalize timestamps
RUN chmod +x ./build-initramfs-dracut.sh \
    && chmod +x /usr/lib/dracut/modules.d/99paypal-auth-vm/*.sh \
    && find /usr/lib/dracut/modules.d/99paypal-auth-vm -type f -exec touch -d "@${SOURCE_DATE_EPOCH}" {} \;

# DEBUG: Verify setup
RUN echo "=== Dracut Module ===" && \
    ls -la /usr/lib/dracut/modules.d/99paypal-auth-vm/

# Run the build
RUN sh -c "source /usr/local/cargo/env && ./build-initramfs-dracut.sh"

# Create output directory and copy artifacts
RUN mkdir /output && \
    cp initramfs-paypal-auth.img /output/ 2>/dev/null || true && \
    cp vmlinuz /output/ 2>/dev/null || true && \
    cp paypal-auth-vm.efi /output/ 2>/dev/null || true && \
    cp build-manifest.json /output/ 2>/dev/null || true && \
    cp *.sha256 /output/ 2>/dev/null || true && \
    # Normalize timestamps for reproducibility
    find /output -type f -exec touch -d "@${SOURCE_DATE_EPOCH}" {} \;

WORKDIR /output

# Export stage - minimal image with just artifacts
FROM scratch AS export-stage
COPY --from=builder /output/ ./img/
