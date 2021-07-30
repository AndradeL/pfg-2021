# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb scons

CFLAGS= -O3 -I$(RSFROOT)/include
SCONSDIR=../../scons-files/sfunif2

all: build

build: export CC=gcc
build: main.x

main.x: main.c
	gcc -D NO_BLAS $(CFLAGS) main.c -o main.x -lrsf -lblas -lm -L$(RSFROOT)/lib

clean:
	rm *.o main.x

run: main.x
	./main.x d1=0.0101 n1=199 v00=1.508,1.581,1.69,1.826,2.0 >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

scons:
	scons --directory=$(SCONSDIR) --clean
	scons --directory=$(SCONSDIR)
	cp $(SCONSDIR)/refs.rsf rsf/
