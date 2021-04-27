// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.


#include "enclave_funcs.h"

#include "helloworld_t.h"

//ecall

void std_ecall(uint64_t * stdin_id, uint64_t * stdout_id, uint64_t * stderr_id){
    *stdin_id = (uint64_t) stdin;
    *stdout_id = (uint64_t) stdout;
    *stderr_id = (uint64_t) stderr;
}

void enclave_keys(char *pub, char *pri){
    memcpy(mypub_key, pub, strlen(pub));
    memcpy(mypri_key, pri, strlen(pri));
    
    char output[500], input[]="SERAQSERKASJDASDF";
    size_t size=10;
    int output_len;
    my_encrypt(mypub_key, input, size, my_cbc_key, my_iv, &my_ekl, my_ek, output, &output_len);
}

//FILE functions

int __vfprintf_chk(FILE * stream, int flag, const char * format, va_list arg){
    //printf("vfprintf_mylibc = %s\n", format);
    int result, chk;
    char buffer[4096];
    vsprintf(buffer, format, arg);
    //fprintf_ocall((uint64_t) stream, buffer, &result);
    result = fwrite(buffer, 1, strlen(buffer), stream);
    return result;
}

int __snprintf_chk(char * str, size_t maxlen, int flag, size_t strlen, const char * format, ...){
    //printf("snprintf_mylibc = %s\n", format);
    int result;
    va_list args;
    va_start(args, format);
    result = vsprintf(str, format, args);
    va_end(args);
    //printf("str = %s\n",str);
    return result;
}

int __sprintf_chk(char * str, int flag, size_t strlen, const char * format, ...){
    //printf("sprintf_mylibc = %s\n", format);
    int result;
    va_list args;
    va_start(args, format);
    result = vsprintf(str, format, args);
    va_end(args);
    //printf("str = %s\n",str);
    return result;
}

int __fprintf_chk (FILE * stream, int flag, const char * format, ...){
    //printf("fprintf_chk_mylibc = %s\n", format);
    char buffer[4096];
    int result, chk;
    va_list args;
    va_start(args, format);
    vsprintf(buffer, format, args);
    va_end(args);
    //fprintf_ocall((uint64_t) stream, buffer, &result);
    result = fwrite(buffer, 1, strlen(buffer), stream);
    return result;
}

int fprintf_chk (FILE * stream, int flag, const char * format, ...){
    //printf("fprintf_mylibc = %s\n", format);
    char buffer[4096];
    int result;
    va_list args;
    va_start(args, format);
    vsprintf(buffer, format, args);
    //fprintf_ocall((uint64_t) stream, buffer, &result);
    result = fwrite(buffer, 1, strlen(buffer), stream);
    va_end(args);
    return result;
}

int fprintf (FILE * stream, const char * format, ...){
    char buffer[4096];
    int result;
    va_list args;
    va_start(args, format);
    vsprintf(buffer, format, args);
    //fprintf_ocall((uint64_t) stream, buffer, &result);
    result = fwrite(buffer, 1, strlen(buffer), stream);
    va_end(args);
    return result;
}

size_t fwrite1( const void * ptr, size_t size, size_t count, FILE * stream ){
    size_t result;
    fwrite_ocall(ptr, size, count, size*count, (uint64_t) stream, &result);
    return result;
}

// read
size_t fread1(void * ptr, size_t size, size_t count, FILE * stream ){
    size_t result;
    fread_ocall(ptr, size, count,(uint64_t) stream, size*count, &result);
    return result;
}

//test encrypt
size_t fwrite( const void * ptr, size_t size, size_t count, FILE * stream ){
    //printf("WRITE AQUI%d!\n",11);
    size_t result;
    int final = 0, pad = 1;

    size_t tot_bytes;
    char *ptr_iv, *data, *buffer;

    off_t cur, init, filelen;

    cur = ftello(stream);
    //printf("cur = %ld\n", cur);
    fseeko(stream, 0, SEEK_END);
    filelen = ftello(stream);

    //printf("filelen = %ld\n", filelen);

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

    size_t chk = fread1(buffer, 1, tot_bytes, stream);
    if(chk != tot_bytes);   //printf("ERROR%d!\n",11);

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

    size_t writ = fwrite1(encrypt, 1, cipher_len, stream);
    if(writ != cipher_len);  //printf("ERROR%d!\n",11);

    fseeko(stream, cur + count*size, SEEK_SET);

    char *confirm;
    confirm = malloc(cipher_len);
    my_decrypt(mypri_key, encrypt, cipher_len, my_ek, my_ekl, ptr_iv, confirm, &cipher_len, pad);
    //printf("Result = %s\n", confirm);
    result = count;

    fflush(stream);

    //printf("write result = %ld\n", result);
    
    return result;
}

//write
size_t fwrite_unlocked( const void * ptr, size_t size, size_t count, FILE * stream ){
    size_t result;
    //printf("IM HERE!%d\n",12312);
    fwrite_ocall(ptr, size, count, size*count, (uint64_t) stream, &result);
    return result;
}

//write
int fputs(const char * string, FILE * file){
    int result;
    //fputs_ocall(string,(uint64_t) file, &result);
    result = fwrite(string, 1, strlen(string), file);
    int aux;
    return result;
}

//write
int fputc(int c, FILE * file){
    int result;
    //fputc_ocall(c,(uint64_t) file, &result);
    result = fwrite(&c, 1, 1, file);
    return result;
}

int fflush(FILE * stream){
    int result;
    fflush_ocall((uint64_t) stream, &result);
    return result;
}

FILE * fopen(const char * path, const char * mode){
    uint64_t stream;
    fopen_ocall(path, mode, &stream);
    return (FILE *) stream;
}

int fclose(FILE * stream){
    int result;
    fclose_ocall((uint64_t) stream, &result);
    return result;
}

// read
char* fgets(char * string, int size, FILE * stream){
    off_t cur = ftello(stream);
    char *buffer;
    buffer = malloc(size);
    memset(buffer, '\n', size);
    /*fgets_ocall(string, size,(uint64_t) stream, &null_chk);
    if(null_chk == 0){
        return string;
    }
    else{
        return NULL;
    }*/
    size_t chk = fread(buffer, 1, size - 1, stream);
    if(chk == 0) {
        return NULL;
    }
    else
    {
        char * pt = (char *) memchr(buffer, '\n', chk);
        if(pt == NULL){
            memcpy(string, buffer, chk);
            fseeko(stream, cur + chk, SEEK_SET);
            string[chk] = 0;
        }
        else{
            chk = pt - buffer + 1;
            memcpy(string, buffer, chk);
            fseeko(stream, cur + chk, SEEK_SET);
            string[chk] = 0;
        }
    }
    return string;
}

//test encrypt
size_t fread(void * ptr, size_t size, size_t count, FILE * stream ){
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
    size_t chk = fread1(buffer, 1, tot_bytes, stream);
    if(chk != tot_bytes)   ;//printf("ERROR%d!\n",11);

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

// read
int fgetc(FILE * stream){
    int result;
    //fgetc_ocall((uint64_t) stream, &result);
    result = fread(&result, 1, 1, stream);
    return result;
}

int fseeko(FILE *stream, off_t offset, int whence){
    int result;
    fseeko_ocall((uint64_t) stream, offset, whence, &result);
    return result;
}

FILE * freopen(const char * filename, const char * mode, FILE * stream ){
    uint64_t result = (uint64_t) stream;
    //printf("stream = %p %lx\n", &result ,result);
    freopen_ocall(filename, mode, &result);
    return (FILE *) result;
}

off_t ftello(FILE *stream){
    long int result;
    ftello_ocall((uint64_t) stream, &result);
    return result;
}

FILE* fdopen(int fd, const char *mode){
    uint64_t stream;
    fdopen_ocall(fd, mode, &stream);
    return (FILE *) stream;
}

//write
int ungetc (int c, FILE * stream){
    int result;
    //ungetc_ocall(c,(uint64_t) stream, &result);
    result = fwrite(&c, 1, 1, stream);
    fseeko(stream, -1, SEEK_CUR);
    return result;
}

int unlink(const char *pathname){
    int result;
    unlink_ocall(pathname, &result);
    return result;
}

int remove(const char *path){
    int result;
    remove_ocall(path, &result);
    return result;
}

//to do
/*
int atexit(void (* func) (void)){
    //printf("atexit! %d\n", 10);
    int result;
    //atexit_ocall((* func), &result);
    return result;
}*/

int uname(struct utsname *buf){
    int result;
    size_t len = sizeof(*buf);
    char * buffer = malloc(len);
    uname_ocall(buffer, len, &result);
    memcpy(buf, buffer, len);
    return result;
}

int fileno(FILE *stream){
    int result;
    fileno_ocall( (uint64_t) stream, &result);
    return result;
}

int fileno_unlocked(FILE *stream){
    int result;
    fileno_ocall( (uint64_t) stream, &result);
    return result;
}

DIR * opendir(const char *name){
    uint64_t result; 
    opendir_ocall(name, &result);
    return (DIR *) result;
}

struct dirent *readdir(DIR *dirp){
    uint64_t result;
    readdir_ocall((uint64_t) dirp, &result);
    return (struct dirent *) result;
}

int closedir(DIR *dirp){
    int result;
    closedir_ocall((uint64_t) dirp, &result);
    return result;
}

int close(int fd){
    int result;
    close_ocall(fd, &result);
    return result;
}

int mkstemp(char *template){
    int result;
    mkstemp_ocall(template, &result);
    return result;
}

void rewind(FILE * fluxo){
    rewind_ocall((uint64_t) fluxo);
}

char* ctime(const time_t *timer){
    char * result;
    result = malloc(100);
    ctime_ocall(timer, result);
    return result;
}

int getlogin_r(char *buf, size_t bufsize){
    int result;
    getlogin_r_ocall(buf, bufsize, &result);
    return result;
}

char* getcwd(char *buf, size_t size){
    getcwd_ocall(buf, size);
    return buf;
}

uid_t geteuid(){
    uid_t result;
    geteuid_ocall(&result);
    return result;
}

int xdr_opaque(){
    //printf("xdr! %d\n", 10);

    return 1;
}

int xdr_vector(){
    //printf("xdr! %d\n", 10);

    return 1;
}

int xdr_float(){
    //printf("xdr! %d\n", 10);

    return 1;
}

int xdr_int(){
    //printf("xdr! %d\n", 10);

    return 1;
}

int xdrmem_create(){
    //printf("xdr! %d\n", 10);
    return 1;
}

int isatty(int fd){
    int result;
    isatty_ocall(fd, &result);
    return result;
}

struct passwd * getpwuid(uid_t uid){
    //printf("getpwuid! %d\n", 10);
    struct passwd * result;
    return result;
}

//to do
int __longjmp_chk(){
    //printf("lomgjmp! %d\n", 10);

    return 1;
}

//to do
int __fxstat(int vers, int fd, struct stat *buf){
    int result;
    fstat_ocall(fd,(uint64_t) buf, &result);
    return result;
}

void * __memcpy_chk(void * dest, const void * src, size_t len, size_t destlen){
    memcpy(dest, src, len);
    //memcpy_chk_ocall(dest, src, len, destlen, &result);
    //printf("memcpy dest = %s\n", (char *) dest);
    return dest;
}

//to do
int __xstat(){
    //printf("xstat! %d\n", 10);
    return 1;
}

char * __strncpy_chk(char * s1, const char * s2, size_t n, size_t s1len){
    strncpy(s1,s2,n);
    return s1;
}

int execl(const char *path, const char *arg, ...){
    int result;
    //execl_ocall(file, arg1, arg2, arg3, &result);
    return result;
}

int execlp(const char *path, const char *arg, ...){
    int result;
    //execlp_ocall(file, arg1, arg2, arg3, &result);
    return result;
}

char * getenv(const char * buf){
    int aux;
    char * result;
    result = malloc(500);
    int null_chk;
    memset(result, 0, 500);
    getenv_ocall(buf, result, &null_chk);
    if(null_chk == -1) {
        free(result);
        return NULL;
    }
    else{
        return result;
    }
}