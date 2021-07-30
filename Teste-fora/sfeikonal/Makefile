# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb scons

CFLAGS= -O3 -D NO_BLAS -I$(RSFROOT)/include
SCONSDIR=../../scons-files/sfeikonal

all: build

build: export CC=gcc
build: main.x

main.x: main.c fastmarch.o
	gcc $(CFLAGS) main.c fastmarch.o -o main.x -lrsf -lm -L$(RSFROOT)/lib

%.o: %.c %.h
	gcc -c $(CFLAGS) $< -o $@

clean:
	rm *.o main.x

run: main.x
	./main.x vel=0 zshot=1500 >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

scons:
	scons --directory=$(SCONSDIR) --clean
	scons --directory=$(SCONSDIR)
	cp $(SCONSDIR)/seg.rsf rsf/in.rsf