# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=-O3 $(shell pkg-config oehost-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs) -lm
INCDIR=$(shell pkg-config oehost-$(COMPILER) --variable=includedir)

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../helloworld.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) keys.c evp.c host.c ocalls.c
	$(CC) -g -c $(CFLAGS) helloworld_u.c
	$(CC) -o helloworldhost helloworld_u.o host.o ocalls.o keys.o evp.o $(LDFLAGS)

clean:
	rm -f helloworldhost keys.o evp.o host.o ocalls.o helloworld_u.o helloworld_u.c helloworld_u.h helloworld_args.h
