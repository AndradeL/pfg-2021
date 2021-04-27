#include "host_funcs.h"

//Generate pub & pri PEM files
RSA * generate_key2()
{
	int				ret = 0;
	RSA				*r = NULL;
	BIGNUM			*bne = NULL;
	BIO				*bp_public = NULL, *bp_private = NULL;

	int				bits = 2048;
	unsigned long	e = RSA_F4;

	// 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		goto free_all;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if(ret != 1){
		goto free_all;
	}

	// 2. save public key
	bp_public = BIO_new_file("./host/keys/public.pem", "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
	if(ret != 1){
		goto free_all;
	}

	// 3. save private key
	bp_private = BIO_new_file("./host/keys/private.pem", "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
 
	// 4. free
free_all:

	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	BN_free(bne);

	return r;
}

//Open private key file
char * pri_key()
{
    int fd = open("./host/keys/private.pem",'r',S_IRUSR);
    struct stat s;
    size_t size;
    char * buf;
    int status;

    /* Get the size of the file. */
    status = fstat (fd, &s);
    size = s.st_size;

    buf = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);

    return buf;
}

//Open public key file
char * pub_key()
{
    int fd = open("./host/keys/public.pem",'r',S_IRUSR);
    struct stat s;
    size_t size;
    char * buf;
    int status;

    /* Get the size of the file. */
    status = fstat (fd, &s);
    size = s.st_size;

    buf = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);

    return buf;
}