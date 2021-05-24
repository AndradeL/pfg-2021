# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb

CFLAGS= -O3 -I$(RSFROOT)/include

all: build

build: export CC=gcc
build: fwi.x

fwi.x: fwi.c random.o
	gcc -g -D NO_BLAS $(CFLAGS) fwi.c random.o -o fwi.x -lrsf -lm -L$(RSFROOT)/lib

clean:
	rm fwi.x

run: fwi.x
	./fwi.x n1=200 d2=.008 n2=200 >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

