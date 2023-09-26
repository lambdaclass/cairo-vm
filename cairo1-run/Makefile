.PHONY: corelib factorial fibonacci test clean run

CAIRO_1_FOLDER=../cairo_programs/cairo-1-programs

$(CAIRO_1_FOLDER)/%.trace: $(CAIRO_1_FOLDER)/%.cairo
	cargo run --release $< --trace_file $@ 

$(CAIRO_1_FOLDER)/%.memory: $(CAIRO_1_FOLDER)/%.cairo
	cargo run --release $< --memory_file $@ 

CAIRO_1_PROGRAMS=$(wildcard ../cairo_programs/cairo-1-programs/*.cairo)
TRACES:=$(patsubst $(CAIRO_1_FOLDER)/%.cairo, $(CAIRO_1_FOLDER)/%.trace, $(CAIRO_1_PROGRAMS))
MEMORY:=$(patsubst $(CAIRO_1_FOLDER)/%.cairo, $(CAIRO_1_FOLDER)/%.memory, $(CAIRO_1_PROGRAMS))

corelib:
	git clone https://github.com/starkware-libs/cairo.git \
	&& cd cairo \
	&& git checkout v2.2.0 \
	&& cd .. \
	&& mv cairo/corelib/ . \
	&& rm -rf cairo/

run: $(TRACES) $(MEMORY)

test: corelib 
	cargo test

clean:
	rm -rf corelib 
	
