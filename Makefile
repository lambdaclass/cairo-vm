# Make sure debug exists
debug ?=

# Print out debug's contents
$(info debug is $(debug))

# Set up to use relese or debug when compiling
ifdef debug
  release :=
else
  release :=--release
endif

.PHONY: build
build:
	cargo build $(release)
