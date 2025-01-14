# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb scons

CFLAGS= -O3 -I$(RSFROOT)/include
SCONSDIR=../../scons-files/fwi
all: build

build: export CC=gcc
build: main.x

main.x: main.c
	gcc -D NO_BLAS $(CFLAGS) main.c -o main.x -lrsf -lm -L$(RSFROOT)/lib

clean:
	rm *.o main.x

run: main.x
	./main.x shots=rsf/shots.rsf grads=rsf/grads.rsf illums=rsf/illums.rsf objs=rsf/objs.rsf < rsf/smvel.rsf >> times.txt

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

scons:
	scons --directory=$(SCONSDIR) --clean
	scons --directory=$(SCONSDIR)
	cp $(SCONSDIR)/grads.rsf rsf/
	cp $(SCONSDIR)/illums.rsf rsf/
	cp $(SCONSDIR)/objs.rsf rsf/
	cp $(SCONSDIR)/shots.rsf rsf/
	cp $(SCONSDIR)/smvel.rsf rsf/