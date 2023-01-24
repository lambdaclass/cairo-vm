#!/bin/bash
set -ex

apt update -y

apt install -y make

lsb_release -a
