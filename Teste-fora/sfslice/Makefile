# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb scons

CFLAGS= -O3 -I$(RSFROOT)/include
SCONSDIR=../../scons-files/sfslice

all: build

build: export CC=gcc
build: main.x

main.x: main.c
	gcc -D NO_BLAS $(CFLAGS) main.c -o main.x -lrsf -lm -L$(RSFROOT)/lib

clean:
	rm *.o main.x

run: main.x
	./main.x pick=rsf/rms.rsf >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

scons:
	scons --directory=$(SCONSDIR) --clean
	scons --directory=$(SCONSDIR)
	cp $(SCONSDIR)/rms.rsf rsf/
	cp $(SCONSDIR)/scan.rsf rsf/
