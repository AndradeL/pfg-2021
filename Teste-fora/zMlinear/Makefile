# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb

CFLAGS= -O3 -I$(RSFROOT)/include

all: build

build: export CC=gcc
build:
	gcc -g -D NO_BLAS $(CFLAGS) fwi.c linear.o -o fwi.x -lrsf -lblas -lm -L$(RSFROOT)/lib

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run:
	./fwi.x >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

