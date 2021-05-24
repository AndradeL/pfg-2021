# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb

CFLAGS= -O3 -I$(RSFROOT)/include

all: build

build: export CC=gcc
build: fwi.x

fwi.x: fwi.c ricker.o kirmod.o kirmod2.o
	gcc -g -D NO_BLAS $(CFLAGS) fwi.c ricker.o kirmod.o kirmod2.o -o fwi.x -lrsf -lm -L$(RSFROOT)/lib

clean:
	rm fwi.x

run: fwi.x
	./fwi.x freq=25 >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

