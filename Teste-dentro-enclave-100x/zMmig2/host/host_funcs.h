#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <sys/stat.h>
#include <sys/mman.h> 
#include <fcntl.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>

#include <time.h>
#include <math.h>

extern uint64_t stdin_id, stdout_id, stderr_id;
extern FILE * stdin_fp, * stdout_fp, * stderr_fp;

int handleErrors();
RSA * generate_key2();
char * pri_key();
char * pub_key();
unsigned long get_time();