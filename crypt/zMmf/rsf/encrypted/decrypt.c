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

char mypri_key[2000];
char mypub_key[500];
unsigned char my_cbc_key[32] = "chave de 256bits";
unsigned char my_iv[16] = { 14, 31, 6, 126, 18, 12, 36, 70, 100, 9, 42, 51, 111, 84, 3, 25 };
char my_ek[256];
int my_ekl;

extern int my_encrypt(char * pub_key, char* plaintext, int plain_size, unsigned char *cbc_key, unsigned char *iv, int * ekl, char* ek,
            unsigned char* encrypt, int *cipher_len);

extern int my_decrypt(char * pri_key, char* ciphertext, int ciphertext_size, char* encrypted_key, int ekl, char* original_iv, unsigned char* decrypt, int * plain_size, int pad);

size_t fwrite_enc(const void *ptr, size_t size, size_t count, FILE *stream);
size_t fread_enc(void * ptr, size_t size, size_t count, FILE * stream );

int main(int argc, char *argv[]){
    char filename[500], outputname[500];
    off_t offset;

    FILE * pub_fp = fopen("keys/public.pem", "r");
    FILE * pri_fp = fopen("keys/private.pem", "r");
    fread(mypri_key, 1, 2000, pri_fp);
    fread(mypub_key, 1, 500, pub_fp);

    fclose(pri_fp);
    fclose(pub_fp);

    printf("input path:\n");
    scanf("%s", filename);
    printf("output name:\n");
    scanf("%s", outputname);
    FILE * fp = fopen(filename, "r");

    char buffer[500];
    sprintf(buffer, "files/%s", outputname);
    FILE * fp1 = fopen(buffer, "w");

    fseeko(fp, 0, SEEK_END);
    off_t size = ftello(fp);

    char *input, *output;
    input = malloc(size);
    output = malloc(size+16);

    fseeko(fp, 0, SEEK_SET);
    fread(input, 1, size, fp);
    int output_len;
    my_encrypt(mypub_key, input, size, my_cbc_key, my_iv, &my_ekl, my_ek, output, &output_len);
    my_decrypt(mypri_key, input, size, my_ek, my_ekl, my_iv, output, &output_len, 1);
    fwrite(output, 1, output_len, fp1);
    fclose(fp);
    fclose(fp1);    

    //decrypt
    /*char * decrypted;
    decrypted = malloc(size+16);

    int new_size;
    my_decrypt(mypri_key, output, output_len, my_ek, my_ekl, my_iv, decrypted, &new_size, 1);

    char bff[50000];
    memset(bff, 0, 50000);
    FILE * fp2 = fopen(buffer,"r+");
    fseeko(fp2, offset, SEEK_SET);*/

    /*char bff1[] = "DEUS ESTA NO COMANDO FE EM QUEM VC ACREDITA";
    size_t check = fwrite_enc(bff1, 1, 20, fp2);
    if(check != 20) printf("write 1!\n");
    check = fwrite_enc(bff1, 1, 20, fp2);
    if(check != 20) printf("write 2!\n");

    fseeko(fp2, 0, SEEK_SET);
    check = fread_enc(bff, 1, 5000, fp2);
    if(check != 5000) printf("Read 5000 fail!\n");
    printf("\nfinal = %s\n", bff);*/
    
    return 0;
}

size_t fwrite_enc(const void *ptr, size_t size, size_t count, FILE *stream){
    printf("WRITE AQUI%d!\n",11);
    size_t result;
    int final = 0, pad = 1;

    size_t tot_bytes;
    char *ptr_iv, *data, *buffer;

    off_t cur, init, filelen;

    cur = ftello(stream);
    //printf("cur = %ld\n", cur);
    fseeko(stream, 0, SEEK_END);
    filelen = ftello(stream);

    printf("filelen = %ld\n", filelen);

    buffer = malloc(filelen*sizeof(char));

    init = (cur/16)*16;

    if((init == filelen) && filelen!=0) init -= 16;

    size_t data_bytes;
    if(init == 0){
        ptr_iv = my_iv;
        data = buffer;
        fseeko(stream, 0, SEEK_SET);
        tot_bytes = filelen;
        data_bytes = tot_bytes;
    }
    else{
        ptr_iv = buffer;
        data = buffer+16;
        fseeko(stream, init-16, SEEK_SET);
        tot_bytes = filelen - (init-16);
        data_bytes = tot_bytes - 16;
    }

    size_t chk = fread(buffer, 1, tot_bytes, stream);
    if(chk != tot_bytes)   printf("ERROR%d!\n",11);

    char *output_dec;
    output_dec = malloc(tot_bytes*sizeof(char));
    memset(output_dec, 0, tot_bytes);
    int output_len;

    my_decrypt(mypri_key, data, data_bytes, my_ek, my_ekl, ptr_iv, output_dec, &output_len, pad);
    //printf("output len = %d\n", output_len);

    char *append;
    off_t append_len = output_len + size*count;   
    append = malloc(append_len + 1);
    memset(append, 0, append_len+1);

    memcpy(append, output_dec, cur-init);
    append_len = cur-init;
    memcpy(append + (cur-init), ptr, size*count);
    append_len += size*count;

    if(cur - init + size*count < output_len){
        memcpy(append+size*count + (cur-init), output_dec + cur - init + size*count, output_len - (cur - init + size*count));
        append_len += output_len - (cur - init + size*count);
    }

   // printf("nwrite = %ld\n",append_len);

    //printf("append = %s\n", append);

    char *encrypt;
    encrypt = malloc(output_len + size*count + 16);
    memset(encrypt, 0, output_len + size*count + 16);
    int cipher_len;
    my_encrypt(mypub_key, append, append_len, my_cbc_key, ptr_iv, &my_ekl, my_ek, encrypt, &cipher_len);

    fseeko(stream, init, SEEK_SET);

    size_t writ = fwrite(encrypt, 1, cipher_len, stream);
    if(writ != cipher_len)  printf("ERROR%d!\n",11);

    fseeko(stream, cur + count*size, SEEK_SET);

    char *confirm;
    confirm = malloc(cipher_len);
    my_decrypt(mypri_key, encrypt, cipher_len, my_ek, my_ekl, ptr_iv, confirm, &cipher_len, pad);
    //printf("Result = %s\n", confirm);
    result = count;

    fflush(stream);

    printf("write result = %ld\n", result);
    
    return result;
}

size_t fread_enc(void * ptr, size_t size, size_t count, FILE * stream ){
    size_t result;
    int final = 0, pad = 0;

    size_t tot_bytes = count*size;
    char *buffer;
    buffer = malloc((tot_bytes + 48)*sizeof(char));
    memset(buffer, 0, tot_bytes + 48);

    off_t cur, init, end, filelen;

    cur = ftello(stream);
    fseeko(stream, 0, SEEK_END);
    filelen = ftello(stream);

    init = (cur/16)*16;
    end = cur + tot_bytes;
    end = end + 16 - (end%16);
    if(end >= filelen){
        final = 1;
        end = filelen;
        pad = 1;
    }

    //there is no read
    if(init == end || init > filelen){
        return 0;
    }

    char *ptr_iv, *data;
    size_t data_bytes;
    if(init == 0){
        ptr_iv = my_iv;
        data = buffer;
        fseeko(stream, 0, SEEK_SET);
        tot_bytes = end - init;
        data_bytes = tot_bytes;
    }
    else{
        ptr_iv = buffer;
        data = buffer + 16;
        fseeko(stream, init-16, SEEK_SET);
        tot_bytes = end - init + 16;
        data_bytes = tot_bytes - 16;
    }
    //printf("init = %ld\nend = %ld\n", init, end);
    //printf("tot_bytes = %ld\npad = %d\n", tot_bytes, pad);
    size_t chk = fread(buffer, 1, tot_bytes, stream);
    if(chk != tot_bytes)   printf("ERROR%d!\n",11);

    char *output_dec;
    output_dec = malloc(tot_bytes*sizeof(char));
    memset(output_dec, 0, tot_bytes);
    int output_len;

    my_decrypt(mypri_key, data, data_bytes, my_ek, my_ekl, ptr_iv, output_dec, &output_len, pad);
    //printf("\ndecrypt = %s\noutput len = %d\n", output_dec, output_len);

    size_t limit = init + output_len;
    //printf("limit = %ld\n", limit);
    result = cur + count*size;

    if(cur >= limit){
        free(buffer);
        free(output_dec);
        return 0;
    }

    if(limit < result){
        result = (limit - cur)/size;
    }
    else{
        result = count;
    }

    //printf("result = %ld\n", result);

    size_t limit_bytes = ((limit - cur) <= count*size)?(limit-cur):(count*size);

    //printf("limit_bytes = %ld\n",limit_bytes);
    
    memcpy(ptr, output_dec + (cur - init), limit_bytes);
    fseeko(stream, cur+limit_bytes, SEEK_SET);
    //printf("ptr = %s\n", (char *) ptr);

    free(buffer);
    free(output_dec);

    //printf("read result = %ld\n", result);
    return result;
}