# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb

CFLAGS= -O3 -I$(RSFROOT)/include

all: build

build: export CC=gcc
build: fwi.x

fwi.x: fwi.c
	gcc -g -D NO_BLAS $(CFLAGS) fwi.c -o fwi.x -lrsf -lm -L$(RSFROOT)/lib

clean:
	rm fwi.x

run: fwi.x
	./fwi.x pick=rsf/rms.rsf >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

