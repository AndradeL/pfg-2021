# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb scons

SCONSDIR=../../scons-files/sfunif2

all: build

build: export CC=gcc
build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run:
	host/helloworldhost ./enclave/helloworldenc.signed d1=0.0101 n1=199 v00=1.508,1.581,1.69,1.826,2.0

simulate:
	host/helloworldhost ./enclave/helloworldenc.signed --simulate

gdb:
	/opt/openenclave/bin/oegdb -arg host/helloworldhost ./enclave/helloworldenc.signed

scons:
	scons --directory=$(SCONSDIR) --clean
	scons --directory=$(SCONSDIR)
	cp $(SCONSDIR)/refs.rsf rsf/
