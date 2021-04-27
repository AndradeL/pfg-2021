//ocalls
#include "host_funcs.h"

uint64_t stdin_id, stdout_id, stderr_id;
FILE * stdin_fp, * stdout_fp, * stderr_fp;

long unsigned comeco,fim;

void start1_time(){
    comeco = get_time();
}

void end1_time(){
    fim = get_time();
    printf("measure = %lu\n", fim - comeco);
}

void fprintf_ocall(uint64_t stream, char * buffer, int * result){
    //printf("fprintf_ocall!\n%s\n", buffer);
    if(stream == stdin_id)    *result = fprintf(stdin_fp, "%s", buffer);
    
    else if(stream == stdout_id)  *result = fprintf(stdout_fp, "%s", buffer);
    
    else if(stream == stderr_id)  *result = fprintf(stderr_fp, "%s", buffer);
    else    *result = fprintf((FILE *) stream, "%s", buffer);
}

void fwrite_ocall(const void * ptr, size_t size, size_t count, size_t total_bytes, uint64_t stream, size_t * result){
    //printf("fwrite_ocall! fp = %ld\n", stream);
    if(stream == stdin_id)    *result = fwrite(ptr, size, count, stdin_fp);
    
    else if(stream == stdout_id)  *result = fwrite(ptr, size, count, stdout_fp);
    
    else if(stream == stderr_id)  *result = fwrite(ptr, size, count, stderr_fp);
    else    *result = fwrite(ptr, size, count, (FILE *) stream);
}

void fputs_ocall(const char * str, uint64_t file, int * result){
    //printf("fputs_ocall!\n");
    //printf("(fputs) file = %lx %lx\n", (uint64_t) (file), (uint64_t) ((FILE *)(file))->_IO_buf_base);
    if(file == stdin_id)    *result = fputs(str, stdin_fp);
    
    else if(file == stdout_id)  *result = fputs(str, stdout_fp);
    
    else if(file == stderr_id)  *result = fputs(str, stderr_fp);
    
    else {
        *result = fputs(str, (FILE *) file);
    }
}

void fputc_ocall(int c, uint64_t file, int * result){
    //printf("fputc_ocall! c = %d\n", c);
    if(file == stdin_id)    *result = fputc(c, stdin_fp);
    
    else if(file == stdout_id)  *result = fputc(c, stdout_fp);
    
    else if(file == stderr_id)  *result = fputc(c, stderr_fp);
    
    else    *result = fputc(c, (FILE *)file);
}

void fflush_ocall(uint64_t file, int * result){
    //printf("fflush_ocall!\n");
    if(file == stdin_id)    *result = fflush(stdin_fp);
    
    else if(file == stdout_id)  *result = fflush(stdout_fp);
    
    else if(file == stderr_id)  *result = fflush(stderr_fp);

    else{
        *result = fflush((FILE *) file);
    }
}

void fopen_ocall(const char * path, const char * mode, uint64_t * stream){
    //printf("fopen_ocall = %s %s!\n", path, mode);
    FILE * fp = fopen(path, mode);
    if(fp == NULL){
        *stream = 0;
    }
    else{
        *stream = (uint64_t) fp;
    }
}

void fclose_ocall(uint64_t file, int * result){
    //printf("fclose_ocall!\n"); 
    *result = fclose((FILE *)file);  
}

void fgets_ocall(char * string, size_t size, uint64_t file, int * null_chk){
    //printf("fgets_ocall!\n");
    char * buffer;
    buffer = (char *) malloc(size*sizeof(char));
    if(fgets(buffer, size,(FILE *) file) != NULL){
        memcpy(string, buffer, size);
        *null_chk = 0;
    }
    else{
        *null_chk = -1;
    }
    free(buffer);
}

void fread_ocall(void * ptr, size_t size, size_t count, uint64_t stream, size_t totbyte, size_t * result){
    //printf("fread_ocall!\n");
    if(stream == stdin_id)    *result = fread(ptr, size, count,stdin_fp);
    
    else if(stream == stdout_id)  *result = fread(ptr, size, count,stdout_fp);
    
    else if(stream == stderr_id)  *result = fread(ptr, size, count,stderr_fp);
    
    else    *result = fread(ptr, size, count,(FILE *) stream);
}

void fgetc_ocall(uint64_t stream, int *result){
    //printf("fgetc_ocall!\n");
    *result = fgetc((FILE *)stream);
}

void fseeko_ocall(uint64_t stream, int64_t offset, int whence, int * result){
    //printf("fseeko_ocall!\n");
    if(stream == stdin_id)    *result = fseeko(stdin_fp, offset, whence);
    
    else if(stream == stdout_id)  *result = *result = fseeko(stdout_fp, offset, whence);
    
    else if(stream == stderr_id)  *result = *result = fseeko(stderr_fp, offset, whence);
    
    else    *result = fseeko((FILE *)stream, offset, whence);
}

void freopen_ocall(const char *filename, const char * mode, uint64_t * stream){
    //printf("freopen_ocall!\n%s\n", filename);
    FILE * fp = freopen(filename, mode,(FILE *) *stream);
    if(fp == NULL){
        *stream = 0;
    }
    else{
        *stream = (uint64_t) fp;
    }
}

void ftello_ocall(uint64_t stream, int64_t * result){
    //printf("ftello_ocall!\n");
    if(stream == stdin_id)    *result = ftello(stdin_fp);
    
    else if(stream == stdout_id)  *result = ftello(stdout_fp);
    
    else if(stream == stderr_id)  *result = ftello(stderr_fp);
    
    else    *result = ftello((FILE *)stream);
}

void fdopen_ocall(int fd, const char * mode, uint64_t *stream){
    //printf("fdopen_ocall!\n");
    *stream =  (uint64_t) fdopen(fd, mode);
}

void ungetc_ocall(int c, uint64_t stream, int * result){
    //printf("ungetc!\n");
    *result = ungetc(c,(FILE *) stream);
}

void unlink_ocall(const char * pathname, int * result){
    //printf("unlink_ocall!\n");
    *result = unlink(pathname);
}

void remove_ocall(const char * path, int * result){
    //printf("remove_ocall!\n");
    *result = remove(path);
}

void uname_ocall(char * buf, size_t len, int * result){
    //printf("uname_ocall!\n");
    struct utsname uhost;
    *result = uname(&uhost);
    memcpy(buf, &uhost, len);
}

void fileno_ocall(uint64_t stream, int * result){
    //printf("fileno_ocall!\n");
    *result = fileno((FILE *) stream);
}

void opendir_ocall(const char * name, uint64_t * result){
    //printf("opendir_ocall!\n");
    //printf("dir = %s\n", name);
    *result = (uint64_t) opendir(name);
}

void readdir_ocall(uint64_t dirp, uint64_t * result){
    //printf("readdir_ocall!\n");
    *result = (uint64_t) readdir((DIR *) dirp);
}

void closedir_ocall(uint64_t dirp, int * result){
    //printf("closedir_ocall!\n");
    *result = closedir((DIR *) dirp);
}

void mkstemp_ocall(char * template, int * result){
    //printf("mkstemp_ocall!\n");
    //printf("path = %s\n", template);
    *result = mkstemp(template);
}

void close_ocall(int fd, int * result){
    //printf("close_ocall!\n");
    *result = close(fd);
}

void rewind_ocall(uint64_t file){
    //printf("rewind_ocall!\n");
    rewind((FILE*) file);
}

void ctime_ocall(const time_t * timer, char * result){
    //printf("ctime_ocall!\n");
    char * buffer;
    buffer = ctime(timer);
    memcpy(result, buffer, 100);
}

void getcwd_ocall(char * buf, size_t size){
    //printf("getcwd_ocall!\n");
    if(NULL != getcwd(buf, size))   return;
}

void geteuid_ocall(unsigned int *result){
    //printf("geteuid_ocall!\n");
    *result = geteuid();
}
void isatty_ocall(int fd, int * result){
    //printf("isatty_ocall\n");
    *result = isatty(fd);
}

void memcpy_chk_ocall(void * dest, const void * src, size_t len, size_t destlen, int * result){
    //printf("memcpy_chk_ocall!\n");
    //printf("before %s %s\n",(char *) src,(char *) dest);
    char * buffer = (char *)malloc(destlen*sizeof(char));
    //*result = __memcpy_chk(buffer, src, len, destlen);
}

void getlogin_r_ocall(char * buf, size_t bufsize, int * result){
    //printf("getlogin_r_ocall!\n");
    *result = getlogin_r(buf, bufsize);
    //printf("result = %d\n", *result);
}

void ctype_b_loc_ocall(unsigned short *** result){
    //printf("ctype_b_loc!\n");
    int aux;
    *result = (unsigned short **) __ctype_b_loc();
}

void strncpy_chk_ocall(char * s1, const char * s2, size_t n, size_t s1len, char * result){
    //printf("strncpy_chk_ocall!\n");
    __strncpy_chk(s1, s2, n, s1len);
    //printf("result = %s\n", s1);
}

void execl_ocall(const char *file, const char *arg1, const char * arg2, const char * arg3, int * result){
    //printf("execl!\n");
}

void execlp_ocall(const char *file, const char *arg1, const char * arg2, const char * arg3, int * result){
    //printf("execlp!\n");
}

void fstat_ocall(int fd, uint64_t buf, int * result){
    //printf("fstat_ocall!\n");
    *result = fstat(fd, (struct stat *) buf);
}

void getenv_ocall( const char * buf, char * result, int * null_chk){
    //printf("getenv_ocall! ");
    //printf("buf = %s\n", buf);
    char * buffer;
    buffer = malloc(500);
    memset(buffer, 0, 500);
    buffer = getenv(buf);
    if(buffer != NULL){
        memcpy(result, buffer, 500);
        *null_chk = 0;
        //printf("getenv = %s\n", result);
    }  
    else {
        free(buffer);
        *null_chk = -1;
    }
}

void expf_ocall(float tmp, float * result){
    *result = expf(tmp);
}

