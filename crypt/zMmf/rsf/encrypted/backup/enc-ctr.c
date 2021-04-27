#include <stdio.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/aes.h>
#include "mbedtls/entropy.h"
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>


int my_decrypt(char * pri_key, char* ciphertext, int ciphertext_size, char* encrypted_key, int ekl, char* original_iv, unsigned char* decrypt, int * plain_size)
{
    //printf("DECRYPT:\n");

    //prepare iv for the decryption
    char iv[16];
    memcpy(iv, original_iv, 16);
    
    int ret = 0;
    const unsigned char* ek = (unsigned char*) encrypted_key;
    mbedtls_pk_context pk;

    mbedtls_pk_init( &pk );
  
    // Read the RSA private key
    const unsigned char* key = (unsigned char*) pri_key;

    size_t key_length = strlen(pri_key) + 1;

    if( ( ret = mbedtls_pk_parse_key( &pk, key, key_length , NULL, 0) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parse_key returned -0x%04x\nret = %d\n", -ret, ret );
        return ret;
    }

    //buffer for aes_key 256 bits (ek 256 bytes)
    unsigned char aes_key[256];
    size_t olen = 0;

    /*
    * Calculate the RSA encryption of the data.
    */

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );

    char *personalization = "my_app_specific_string";

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy,
                    (const unsigned char *) personalization,
                    strlen( personalization ) );
    
    if( ret != 0 )
    {
        printf("Error!\n");
        return ret;
    }

    if( ( ret = mbedtls_pk_decrypt( &pk, ek, ekl, aes_key, &olen, sizeof(aes_key),
                                    mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret );
        return ret;
    }

    for(int aux=olen; aux<ekl; aux++){
        aes_key[aux] = 0;
    }

    mbedtls_aes_context context_out;

    mbedtls_aes_init(&context_out);

    // set aes 256 bits key
    ret = mbedtls_aes_setkey_enc( &context_out, aes_key, 256 );
    if(ret != 0)    return ret;

    unsigned char nonce[16], stream_block[16];
    memcpy(nonce, iv, 16);

    size_t nc_off = 0;
    
    //ctr decrypt
    ret = mbedtls_aes_crypt_ctr(&context_out, ciphertext_size, &nc_off, nonce, stream_block, (unsigned char*) ciphertext, decrypt);
    if(ret != 0)    
    {
        printf( " failed\n  ! mbedtls_ctr returned -0x%04x\nret = %d\n", -ret, ret );
        return ret;
    }

    printf("\n nonce = ");
    for(int ab=0;ab<16;ab++)    printf("%d.", (unsigned char) nonce[ab]);
    printf("\n");

    printf("nc off = %ld\n", nc_off);

    *plain_size = ciphertext_size;

    printf("\n sera = ");
    for(int ab=0;ab<*plain_size;ab++)    printf("%c", decrypt[ab]);
    printf("\n");

    printf("Leaving decrypt\n");
    return ret;
}

int my_encrypt(char * pub_key, char* plaintext, int plain_size, unsigned char *ctr_key, unsigned char *iv, int * ekl, char* ek,
            unsigned char* encrypt, int *cipher_len)
{
    
    // Set context
    int ret = 0;
    mbedtls_aes_context context_in;

    mbedtls_aes_init(&context_in);

    unsigned char buffer_iv[16];

    memcpy(buffer_iv, iv, 16);

    ret = mbedtls_aes_setkey_enc(&context_in, ctr_key, 256);
    if(ret != 0)    return ret;

    // length of the encryption buffer
    *cipher_len = plain_size;
    char * ctr_buf;
    ctr_buf = malloc(*cipher_len);  //buffer with plaintext
    
    unsigned char nonce[16], stream_block[16];
    memcpy(nonce, iv, 16);


    printf("\nnonce = ");
    for(int ab=0;ab<16;ab++)    printf("%d.", nonce[ab]);
    printf("\n");

    size_t nc_off = 0;
    
    ret = mbedtls_aes_crypt_ctr(&context_in, plain_size, &nc_off, nonce, stream_block, (unsigned char*) plaintext, encrypt);
    if(ret != 0)    
    {
        printf( " failed\n  ! mbedtls_ctr returned -0x%04x\nret = %d\n", -ret, ret );
        return ret;
    }

    printf("\n");
    for(int ab=0;ab<plain_size;ab++)    printf("%c", encrypt[ab]);
    printf("\n");

    printf("\nnonce after = ");
    for(int ab=0;ab<16;ab++)    printf("%d.", (unsigned char) nonce[ab]);
    printf("\n");

    printf("nc_off = %ld\n", nc_off);
    
    free(ctr_buf);

    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );

    char *personalization = "my_app_specific_string";

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy,
                    (const unsigned char *) personalization,
                    strlen( personalization ) );

    if(ret != 0)    return ret;

    size_t key_length = strlen(pub_key) + 1;

    if( ( ret = mbedtls_pk_parse_public_key( &pk, (const unsigned char *) pub_key, key_length) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parse_key returned -0x%04x\nret = %d\n", -ret, ret );
        return ret;
    }

    size_t olen;
    unsigned char aes_key[256]={};

    if( ( ret = mbedtls_pk_encrypt( &pk, ctr_key, 32, aes_key, &olen, sizeof(aes_key),
                                mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret );
        return ret;
    }

    memcpy(ek, aes_key, 256);
    *ekl = olen;

    printf("LEAVING ENCRYPT!\n");
    return ret;
}