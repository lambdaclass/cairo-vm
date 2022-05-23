.PHONY: build run check test clippy coverage

build:
	cargo build

run: 
	cargo run

check:
	cargo check

test:
	cargo test

clippy:
	cargo clippy  -- -D warnings

coverage:
	docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin
