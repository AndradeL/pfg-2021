# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb scons

SCONSDIR=../../scons-files/sfmig2

all: build

build: export CC=gcc
build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run:
	host/helloworldhost ./enclave/helloworldenc.signed

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
