.PHONY: corelib factorial fibonacci test clean

corelib:
	git clone git@github.com:starkware-libs/cairo.git \
	&& mv cairo/corelib/ . \
	&& rm -rf cairo/

factorial: 
	cargo run ../cairo_programs/cairo-1-programs/factorial.cairo --trace_file memory_trace/fac.trace --memory_file memory_trace/fac.memory

fibonacci: 
	cargo run ../cairo_programs/cairo-1-programs/fibonacci.cairo --trace_file memory_trace/fib.trace --memory_file memory_trace/fib.memory

test: corelib 
	cargo test

clean:
	rm -rf memory_trace
	rm -rf corelib 
	