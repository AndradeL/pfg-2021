
build:
	gcc enc.c encrypt.c -o run.x -lmbedcrypto
	gcc enc.c decrypt.c -o dec.x -lmbedcrypto
	gcc enc-ctr.c encrypt-ctr.c -o ctr.x -lmbedcrypto
	gcc enc.c encrypt.c -o cbc.x -lmbedcrypto

enc-ctr: ctr.x
	./ctr.x

enc-cbc: cbc.x
	./cbc.x

dec-cbc: dec.x
	./dec.x

clean:
	rm -rf *.x