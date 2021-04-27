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
}

//FILE functions

int __vfprintf_chk(FILE * stream, int flag, const char * format, va_list arg){
    printf("vfprintf_mylibc = %s\n", format);
    int result, chk;
    char buffer[4096];
    vsprintf(buffer, format, arg);
    //fprintf_ocall((uint64_t) stream, buffer, &result);
    result = fwrite(buffer, 1, strlen(buffer), stream);
    return result;
}

int __snprintf_chk(char * str, size_t maxlen, int flag, size_t strlen, const char * format, ...){
    printf("snprintf_mylibc = %s\n", format);
    int result;
    va_list args;
    va_start(args, format);
    result = vsprintf(str, format, args);
    va_end(args);
    printf("str = %s\n",str);
    return result;
}

int __sprintf_chk(char * str, int flag, size_t strlen, const char * format, ...){
    printf("sprintf_mylibc = %s\n", format);
    int result;
    va_list args;
    va_start(args, format);
    result = vsprintf(str, format, args);
    va_end(args);
    printf("str = %s\n",str);
    return result;
}

int __fprintf_chk (FILE * stream, int flag, const char * format, ...){
    printf("fprintf_chk_mylibc = %s\n", format);
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
    printf("fprintf_mylibc = %s\n", format);
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

size_t fwrite( const void * ptr, size_t size, size_t count, FILE * stream ){
    size_t result;
    fwrite_ocall(ptr, size, count, size*count, (uint64_t) stream, &result);
    return result;
}

//write
size_t fwrite_unlocked( const void * ptr, size_t size, size_t count, FILE * stream ){
    size_t result;
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

// read
size_t fread(void * ptr, size_t size, size_t count, FILE * stream ){
    size_t result;
    fread_ocall(ptr, size, count,(uint64_t) stream, size*count, &result);
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