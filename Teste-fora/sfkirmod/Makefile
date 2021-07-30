# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb scons

CFLAGS= -O3 -D NO_BLAS -I$(RSFROOT)/include
SCONSDIR=../../scons-files/sfkirmod

all: build

build: export CC=gcc
build: main.x

main.x: main.c ricker.o kirmod.o kirmod2.o
	gcc $(CFLAGS) main.c kirmod.o kirmod2.o ricker.o -o main.x -lrsf -lm -L$(RSFROOT)/lib

%.o: %.c %.h
	gcc -c $(CFLAGS) $< -o $@

clean:
	rm *.o main.x

run: main.x
	./main.x nt=501 dt=0.004 freq=25 refl=rsf/refl.rsf ns=12 s0=1.4 ds=-0.1 nh=64 h0=0.1 dh=0.1 vel=5 gradz=2 type=v >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

scons:
	scons --directory=$(SCONSDIR) --clean
	scons --directory=$(SCONSDIR)
	cp $(SCONSDIR)/modl.rsf rsf/
	cp $(SCONSDIR)/refl.rsf rsf/