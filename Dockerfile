# docker buildx rm default
# 1. Use a specific version of the Fedora minimal image for reproducibility.
#    See https://registry.fedoraproject.org/
#FROM registry.fedoraproject.org/fedora-minimal:43 AS builder
#docker buildx imagetools inspect oraclelinux:10-slim  #to know the sha256 of the docker image
FROM docker.io/library/oraclelinux@sha256:2d7cd00cea5d1422e1b8242418c695e902dfd6ceeac164d8fae880fa688e5bb2 AS builder

#FROM oraclelinux:10-slim AS builder
# 2. Install dependencies for building the initramfs
#    - dracut is a core tool on Fedora, but we ensure it and its dependencies are present.
#    - microdnf is the lightweight package manager available on Fedora Minimal.
#    - fakeroot is needed to allow dracut to run without full container privileges.
#    - musl-devel provides the headers and libraries needed for musl compilation.
#    - util-linux provides the 'logger' utility for dracut.
RUN microdnf install -y \
    dracut-105-4.0.1.el10_0.x86_64 \
    kernel-core-6.12.0-55.43.1.0.1.el10_0.x86_64 \
    kernel-modules-6.12.0-55.43.1.0.1.el10_0.x86_64 \
    kmod-31-11.0.2.el10.x86_64 \
    curl-8.9.1-5.el10.x86_64 \
    gcc-14.2.1-7.el10.x86_64 \
    gcc-c++-14.2.1-7.el10.x86_64 \
    make-4.4.1-9.el10.x86_64 \
    # musl-gcc \
    # musl-devel \
    #fakeroot \
    util-linux-2.40.2-10.el10.x86_64 \
    linux-firmware-20251030-999.44.1.gite9292517.el10.noarch \
    # Install python for diffoscope
    python3-3.12.9-2.0.1.el10_0.3.x86_64 \
    python3-pip-23.3.2-7.el10.noarch \
    libarchive-3.7.7-4.el10_0.x86_64 \
    && microdnf clean all

# Install diffoscope in a Python virtual environment
RUN python3 -m venv /opt/diffoscope-venv \
    && /opt/diffoscope-venv/bin/pip install --upgrade pip \
    && /opt/diffoscope-venv/bin/pip install diffoscope

# Add diffoscope venv to PATH
ENV PATH="/opt/diffoscope-venv/bin:$PATH"

# 3. Install a specific version of Rust for a reproducible build environment
#    - We install to /usr/local to make it available system-wide in the container.
#    - See https://rust-lang.github.io/rustup/installation/index.html for installer options.
ARG RUST_VERSION=1.91.1
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal --no-modify-path \
    && source /usr/local/cargo/env \
    && export RUST_MIN_STACK=16777216 \
    && cargo install -j 1 add-determinism \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git

# 4. Set up environment for reproducible musl builds
#    These are sourced from the project's .idx/dev.nix file to align the
#    container environment with the local development environment.
#ENV CC_x86_64_unknown_linux_musl="musl-gcc" \
#    CXX_x86_64_unknown_linux_musl="musl-g++" \
#    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="musl-gcc" \
#    AR_x86_64_unknown_linux_musl="ar"

# 5. Set up the application build environment
WORKDIR /app

# 6. Copy all project files into the container
#    Using .dockerignore is recommended to exclude unnecessary files.
COPY . .

# 7. Copy the custom dracut module to the system-wide location
COPY dracut-module/99paypal-auth-vm /usr/lib/dracut/modules.d/99paypal-auth-vm

# 7.1 Copy dracut configuration
RUN mkdir -p /etc/dracut.conf.d
COPY dracut.conf /etc/dracut.conf.d/99-paypal-auth.conf

# 7.5 Debug: Verify the module was copied
RUN echo "=== Verifying module copy ===" && \
    ls -la /usr/lib/dracut/modules.d/ | grep -i paypal && \
    ls -la /usr/lib/dracut/modules.d/99paypal-auth-vm/ && \
    echo "=== Module files ===" && \
    cat /usr/lib/dracut/modules.d/99paypal-auth-vm/module-setup.sh | head -20 && \
    echo "=== Dracut config ===" && \
    cat /etc/dracut.conf.d/99-paypal-auth.conf | head -20

# 8. Make the build script executable
RUN chmod +x ./build-initramfs-dracut.sh

# 9. Run the build script within a fakeroot environment to allow dracut to work
#    - `sh -c` is used to source the cargo environment before running the script
#    - This ensures that both dracut permissions and the cargo path are correct
RUN sh -c "source /usr/local/cargo/env && ./build-initramfs-dracut.sh"
#RUN fakeroot sh -c "source /usr/local/cargo/env && ./build-initramfs-dracut.sh"
# 10. Create an output directory and move the build artifacts
RUN mkdir /output && \
    mv initramfs-paypal-auth.img /output/ && \
    mv build-manifest.json /output/ && \
    mv initramfs-paypal-auth.img.sha256 /output/

# 11. Set the output directory as the final working directory
WORKDIR /output

# 12. Expose the output of the build
FROM scratch AS export-stage
COPY --from=builder /output/ ./img/
