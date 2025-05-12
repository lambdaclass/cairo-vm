#!/usr/bin/env bash
set -ex

apt update -y

# Install curl in order to install Rust, Cargo and UV.
apt install -y curl

# Install general dependencies
apt install -y git make

# Install Rust and Cargo
curl https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env"

# Make sure Rust has been installed correctly
rustc --version

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Make sure uv has been installed correctly
uv --version

make deps
