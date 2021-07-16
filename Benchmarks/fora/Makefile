CFLAGS= -O3 -I$(RSFROOT)/include
CC=gcc

.PHONY: all
all: disk.x mem.x cpu.x recursion.x

%.x: %.c
	$(CC) $(CFLAGS) $^ -o $@ -DMBS=$(NUM)

.PHONY: run
run: all data.txt
	./disk.x
	./mem.x
	./cpu.x
	./recursion.x

.PHONY: clean
clean:
	rm *.x