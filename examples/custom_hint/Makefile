.PHONY: compile, run, clean, example

compile:
	cairo-compile custom_hint.cairo --output custom_hint.json

run: 
	cargo run

clean: 
	rm custom_hint.json

example:
	make compile
	make run
	make clean


