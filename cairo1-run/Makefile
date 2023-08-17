corelib:
	git clone git@github.com:starkware-libs/cairo.git \
	&& mv cairo/corelib/ . \
	&& rm -rf cairo/
	
test: corelib 
	cargo test

clean:
	rm -rf corelib 