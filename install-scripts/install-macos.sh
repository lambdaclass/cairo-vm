#!/usr/bin/env bash
set -ex

# This installation has been tested on Ubuntu 

# Install Rust and Cargo
curl https://sh.rustup.rs -sSf | sh -s -- -y

# Make sure Rust has been installed correctly
rustc --version

# Install pyenv
brew install pyenv

# Make sure pyenv has been installed correctly
pyenv -v

# Installing python 3.9 with pyenv
pyenv install 3.9

# Setting python 3.9 as the default local version
pyenv local 3.9 # is this needed given that we then create a virtual environment?

# Create and enter a virtual environment
python3.9 -m venv ~/cairo_venv
source ~/cairo_venv/bin/activate

# Install cairo dependencies
pip3 install ecdsa fastecdsa sympy

# Install cairo
pip3 install cairo-lang

