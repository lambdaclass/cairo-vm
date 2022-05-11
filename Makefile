.PHONY: build run check test coverage

build:
	cargo build

run: 
	cargo run

check:
	cargo check

test:
	cargo test

coverage:
	docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin