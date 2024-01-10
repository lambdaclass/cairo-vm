#!/usr/bin/env bash

case "$OSTYPE" in
  linux*)           for file in ../*.cairo; do ln -s "$file" .; done ;;
  darwin*)          ln -s ../*.cairo . ;; 
  *)                echo "unknown: ${OSTYPE}" ;;
esac
