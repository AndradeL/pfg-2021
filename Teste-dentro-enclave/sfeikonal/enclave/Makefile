# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

ifeq ($(LVI_MITIGATION), ControlFlow)
	ifeq ($(LVI_MITIGATION_BINDIR),)
		$(error LVI_MITIGATION_BINDIR is not set)
	endif
	# Only run once.
	ifeq (,$(findstring $(LVI_MITIGATION_BINDIR),$(CC)))
		CC := $(LVI_MITIGATION_BINDIR)/$(CC)
	endif
	COMPILER := $(COMPILER)-lvi-cfg
endif

CFLAGS= -O3 -I$(RSFROOT)/include $(shell pkg-config oeenclave-$(COMPILER) --cflags)
LDFLAGS= -L$(RSFROOT)/lib $(shell pkg-config oeenclave-$(COMPILER) --libs) -loecryptoopenssl -lopensslcrypto -loelibc
INCDIR=$(shell pkg-config oeenclave-$(COMPILER) --variable=includedir)

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../helloworld.edl --trusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -c -D NO_BLAS $(CFLAGS) -DOE_API_VERSION=2 fwi.c -o fwi.o
	$(CC) -c -D NO_BLAS $(CFLAGS) -DOE_API_VERSION=2 fastmarch.c -o fastmarch.o
	objcopy --redefine-sym main=fwi fwi.o fwi2.o
	$(CC) -c -D NO_BLAS $(CFLAGS) -DOE_API_VERSION=2 mylibc.c -o mylibc.o
	$(CC) -c -D NO_BLAS $(CFLAGS) -DOE_API_VERSION=2 enc.c -o enc.o
	$(CC) -c $(CFLAGS) -DOE_API_VERSION=2 helloworld_t.c -o helloworld_t.o
	$(CC) -z muldefs -o helloworldenc helloworld_t.o fwi2.o fastmarch.o -lrsf mylibc.o enc.o $(LDFLAGS)

sign:
	oesign sign -e helloworldenc -c helloworld.conf -k private.pem

clean:
	rm -f enc.o mylibc.o fwi.o fwi2.o helloworldenc helloworldenc.signed private.pem public.pem helloworld_t.o helloworld_t.h helloworld_t.c helloworld_args.h

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
