# 1. Use a specific version of the Fedora minimal image for reproducibility.
#    See https://registry.fedoraproject.org/
FROM registry.fedoraproject.org/fedora-minimal:43 AS builder

# 2. Install dependencies for building the initramfs
#    - dracut is a core tool on Fedora, but we ensure it and its dependencies are present.
#    - microdnf is the lightweight package manager available on Fedora Minimal.
#    - fakeroot is needed to allow dracut to run without full container privileges.
#    - musl-devel provides the headers and libraries needed for musl compilation.
#    - util-linux provides the 'logger' utility for dracut.
RUN microdnf install -y \
    dracut \
    kernel-core \
    kernel-modules \
    kmod \
    curl \
    gcc \
    gcc-c++ \
    make \
    musl-gcc \
    musl-devel \
    fakeroot \
    util-linux \
    && microdnf clean all

# 3. Install a specific version of Rust for a reproducible build environment
#    - We install to /usr/local to make it available system-wide in the container.
#    - See https://rust-lang.github.io/rustup/installation/index.html for installer options.
ARG RUST_VERSION=1.91.1
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain ${RUST_VERSION} --no-modify-path

# 4. Set up environment for reproducible musl builds
#    These are sourced from the project's .idx/dev.nix file to align the
#    container environment with the local development environment.
ENV CC_x86_64_unknown_linux_musl="musl-gcc" \
    CXX_x86_64_unknown_linux_musl="musl-g++" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="musl-gcc" \
    AR_x86_64_unknown_linux_musl="ar"

# 5. Set up the application build environment
WORKDIR /app

# 6. Copy all project files into the container
#    Using .dockerignore is recommended to exclude unnecessary files.
COPY . .

# 7. Copy the custom dracut module to the system-wide location
COPY dracut-module/99paypal-auth-vm /usr/lib/dracut/modules.d/99paypal-auth-vm

# 8. Make the build script executable
RUN chmod +x ./build-initramfs-dracut.sh

# 9. Run the build script within a fakeroot environment to allow dracut to work
#    - `sh -c` is used to source the cargo environment before running the script
#    - This ensures that both dracut permissions and the cargo path are correct
RUN fakeroot sh -c "source /usr/local/cargo/env && ./build-initramfs-dracut.sh"

# 10. Create an output directory and move the build artifacts
RUN mkdir /output && \
    mv initramfs-paypal-auth.img /output/ && \
    mv luks.key /output/ && \
    mv build-manifest.json /output/ && \
    mv initramfs-paypal-auth.img.sha256 /output/

# 11. Set the output directory as the final working directory
WORKDIR /output

# 12. Expose the output of the build
FROM scratch AS export-stage
COPY --from=builder /output/ .
