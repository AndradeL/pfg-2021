# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb scons

CFLAGS= -O3 -D NO_BLAS -I$(RSFROOT)/include
SCONSDIR=../../scons-files/sfhelicon

all: build

build: export CC=gcc
build: fwi.x

fwi.x: fwi.c regrid.o
	gcc $(CFLAGS) fwi.c regrid.o -o fwi.x -lrsf -lm -L$(RSFROOT)/lib

%.o: %.c %.h
	gcc -c $(CFLAGS) $< -o $@

clean:
	rm *.o fwi.x

run: fwi.x
	./fwi.x filt=rsf/horz.rsf adj=0 div=0 >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

scons:
	scons --directory=$(SCONSDIR) --clean
	scons --directory=$(SCONSDIR)
	cp $(SCONSDIR)/horz.rsf rsf/
	cp $(SCONSDIR)/shorz1.rsf rsf/
	cp $(SCONSDIR)/spike.rsf rsf/