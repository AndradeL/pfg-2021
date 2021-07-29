# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate gdb scons

SCONSDIR=../../scons-files

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
	scons --directory=$(SCONSDIR)/fwi/ --clean
	scons --directory=$(SCONSDIR)/fwi/
	cp $(SCONSDIR)/fwi/rsf/grads.rsf .
	cp $(SCONSDIR)/fwi/rsf/illums.rsf .
	cp $(SCONSDIR)/fwi/rsf/objs.rsf .
	cp $(SCONSDIR)/fwi/rsf/shots.rsf .
	cp $(SCONSDIR)/fwi/rsf/smvel.rsf .