# This installation has been tested on Debian 11 XFCE

# Install curl in order to install Rust and Cargo
sudo apt install curl

# Install Rust and Cargo
curl https://sh.rustup.rs -sSf | sh

# TODO Restart console? (It's necessary in order to ensure PATH is configured correctly by rustup)

# Make sure Rust has been installed correctly
rustc --version

# Install pyenv dependencies
sudo apt-get install -y make build-essential libssl-dev zlib1g-dev libbz2-dev 
libreadline-dev libsqlite3-dev wget llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev

# Install pyenv
curl -L https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer | bash

# Install make, necessary for installing python 3.9 with pyenv
sudo apt-get install -y make

# TODO Add the following lines at the end of your .bashrc file if you use bash or .zshrc file if you use zsh

"export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
if command -v pyenv 1>/dev/null 2>&1; then
 eval "$(pyenv init -)"
fi"

# TODO Restart shell ??

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
sudo apt install -y libgmp3-dev
pip3 install ecdsa fastecdsa sympy

# Install cairo
pip3 install cairo-lang

