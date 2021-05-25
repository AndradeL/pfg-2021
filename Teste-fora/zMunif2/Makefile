# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb

CFLAGS= -O3 -I$(RSFROOT)/include

all: build

build: export CC=gcc
build: fwi.x

fwi.x: fwi.c
	gcc -D NO_BLAS $(CFLAGS) fwi.c -o fwi.x -lrsf -lblas -lm -L$(RSFROOT)/lib

clean:
	rm *.o fwi.x

run: fwi.x
	./fwi.x d1=0.0101 n1=199 v00=1.508,1.581,1.69,1.826,2.0 >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

