# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb

CFLAGS= -O3 -I$(RSFROOT)/include

all: build

build: export CC=gcc
build:
	gcc -g -D NO_BLAS $(CFLAGS) fwi.c fastmarch.o -o fwi.x -lrsf -lm -L$(RSFROOT)/lib

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run:
	./fwi.x vel=0 zshot=1500 >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

