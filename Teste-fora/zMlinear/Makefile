# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb

CFLAGS= -O3 -D NO_BLAS -I$(RSFROOT)/include

all: build

build: export CC=gcc
build: fwi.x

fwi.x: fwi.c linear.o
	gcc $(CFLAGS) fwi.c linear.o -o fwi.x -lrsf -lblas -lm -L$(RSFROOT)/lib

%.o: %.c %.h
	gcc -c $(CFLAGS) $< -o $@

clean:
	rm *.o fwi.x

run: fwi.x
	./fwi.x >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

