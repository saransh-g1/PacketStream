build:
	make -C basic_test

clean:
	make -C basic_test clean

install:
	sudo apt update
	sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm