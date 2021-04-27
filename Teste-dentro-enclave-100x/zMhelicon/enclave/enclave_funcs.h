#include <stdio.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/aes.h>
#include "mbedtls/entropy.h"
#include <string.h>
#include <math.h>
#include <float.h>
#include <pwd.h>
#include <fcntl.h>
#include <time.h>
#include <rsf.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>

extern char mypri_key[2000], mypub_key[500];
extern unsigned char my_cbc_key[32];
extern unsigned char my_iv[16];
extern char my_ek[256];
extern int my_ekl;

int my_encrypt(char * pub_key, char* plaintext, int plain_size, unsigned char *cbc_key, unsigned char *iv, int * ekl, char* ek,
            unsigned char* encrypt, int *cipher_len);
int my_decrypt(char * pri_key, char* ciphertext, int ciphertext_size, char* encrypted_key, int ekl, char* original_iv, unsigned char* decrypt, int * plain_size, int pad);