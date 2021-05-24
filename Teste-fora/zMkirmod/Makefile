# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb

CFLAGS= -O3 -I$(RSFROOT)/include

all: build

build: export CC=gcc
build: fwi.x

fwi.x: fwi.c ricker.o kirmod.o kirmod2.o
	gcc -g -D NO_BLAS $(CFLAGS) fwi.c kirmod.o kirmod2.o ricker.o -o fwi.x -lrsf -lm -L$(RSFROOT)/lib

clean:
	rm fwi.x

run: fwi.x
	./fwi.x nt=501 dt=0.004 freq=25 refl=rsf/refl.rsf ns=12 s0=1.4 ds=-0.1 nh=64 h0=0.1 dh=0.1 vel=5 gradz=2 type=v >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

