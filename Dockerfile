# 1. Use a specific version of the Debian image for reproducibility.
#    See https://hub.docker.com/_/debian for available tags.
FROM debian:12.5-slim

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# 2. Use a fixed snapshot of Debian repositories for reproducible package versions.
#    - Copy the custom sources.list pointing to a snapshot.debian.org timestamp.
#    - This ensures that apt-get install will always fetch the exact same package versions.
COPY sources.list /etc/apt/sources.list

# 3. Install dependencies for building the initramfs
RUN apt-get update && apt-get install -y --no-install-recommends \
    dracut \
    linux-image-amd64 \
    kmod \
    curl \
    build-essential \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# 4. Install a specific version of Rust for a reproducible build environment
#    - We install to /usr/local to make it available system-wide in the container.
#    - See https://rust-lang.github.io/rustup/installation/index.html for installer options.
ARG RUST_VERSION=1.77.2
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain ${RUST_VERSION} --no-modify-path

# 5. Set up environment for reproducible musl builds
#    These are sourced from the project's .idx/dev.nix file to align the
#    container environment with the local development environment.
ENV CC_x86_64_unknown_linux_musl="musl-gcc" \
    CXX_x86_64_unknown_linux_musl="musl-g++" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="musl-gcc" \
    AR_x86_64_unknown_linux_musl="ar"

# 6. Set up the application build environment
WORKDIR /app

# 7. Copy all project files into the container
#    Using .dockerignore is recommended to exclude unnecessary files.
COPY . .

# 8. Make the build script executable
RUN chmod +x ./build-initramfs-dracut.sh

# 9. Run the build script to generate the initramfs
#    The script will now find cargo in the PATH and use the MUSL env vars.
RUN ./build-initramfs-dracut.sh

# 10. Create an output directory and move the build artifacts
RUN mkdir /output && \
    mv initramfs-paypal-auth.img /output/ && \
    mv luks.key /output/ && \
    mv build-manifest.json /output/ && \
    mv initramfs-paypal-auth.img.sha256 /output/

# 11. Set the output directory as the final working directory
WORKDIR /output

# 12. Default command: List the generated artifacts for easy inspection
CMD ["ls", "-l", "/output"]
