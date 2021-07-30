# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb scons

CFLAGS= -O3 -I$(RSFROOT)/include
SCONSDIR=../../scons-files/sfmig2

all: build

build: export CC=gcc
build: main.x

main.x: main.c
	gcc -D NO_BLAS $(CFLAGS) main.c -o main.x -lrsf -lm -L$(RSFROOT)/lib

clean:
	rm *.o main.x

run: main.x
	./main.x vel=rsf/vel2.rsf >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

scons:
	scons --directory=$(SCONSDIR) --clean
	scons --directory=$(SCONSDIR)
	cp $(SCONSDIR)/data.rsf rsf/
	cp $(SCONSDIR)/migaa.rsf rsf/
	cp $(SCONSDIR)/vel2.rsf rsf/
