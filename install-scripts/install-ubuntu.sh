#!/usr/bin/env bash
set -ex

PYTHON_VERSION=3.9.15
PYTHON_MINOR_VERSION=${PYTHON_VERSION%.*}

sudo apt update -y

# Install Rust and Cargo
curl https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env"

# Make sure Rust has been installed correctly
rustc --version

# Install uv dependencies
sudo apt-get install -y make build-essential libssl-dev zlib1g-dev libbz2-dev \
        libreadline-dev libsqlite3-dev wget llvm libncurses5-dev libncursesw5-dev \
        xz-utils tk-dev libffi-dev liblzma-dev libgmp3-dev

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Make sure uv has been installed correctly
uv --version

make deps
