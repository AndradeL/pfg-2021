// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>

// Include the untrusted helloworld header that is generated
// during the build. This file is generated by calling the
// sdk tool oeedger8r against the helloworld.edl file.
#include "host_funcs.h"
#include "helloworld_u.h"
#include <sys/time.h>

void open_std(){
    stdin_fp = fopen("std/stdin.txt", "r");
    stdout_fp = fopen("std/stdout.txt", "w+");
    stderr_fp = fopen("std/stderr.txt", "w+");
}

void close_std(){
    fclose(stdin_fp);
    fclose(stdout_fp);
    fclose(stderr_fp);
}

bool check_simulate_opt(int* argc, char* argv[])
{
    for (int i = 0; i < *argc; i++)
    {
        if (strcmp(argv[i], "--simulate") == 0)
        {
            fprintf(stdout, "Running in simulation mode\n");
            memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return true;
        }
    }
    return false;
}

int main(int argc, char* argv[])
{
    long unsigned start2 = get_time();
    oe_result_t result;
    int ret = 1;
    oe_enclave_t* enclave = NULL;

    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (check_simulate_opt(&argc, argv))
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    // Create the enclave
    result = oe_create_helloworld_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "oe_create_helloworld_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    long unsigned end2 = get_time();

    //printf("@@time_create = %lu\n", end2 - start2);

    open_std();

    //generating RSA keys for enclave
    //RSA * g = generate_key2();
    char * pr_key = pri_key();
	char * public_key = pub_key();

    result = enclave_keys(enclave, public_key, pr_key);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into enclave_keys failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    //call std
    result = std_ecall(enclave, &stdin_id, &stdout_id, &stderr_id);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into std_ecall failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    //call fwi
    int resultado;
    long unsigned start = get_time();

    for (int i=0;i<10;i++)  result = fwi(enclave, &resultado, argc, argv);

    long unsigned end = get_time();

    //printf("%lu\n", end - start);

    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into function_main failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    close_std();

    ret = 0;

exit:
    // Clean up the enclave if we created one
    if (enclave){
        long unsigned start1 = get_time();
        oe_terminate_enclave(enclave);
        long unsigned end1 = get_time();
        //printf("@@time_terminate = %lu\n", end1 - start1);
        printf("%lu\n", (end2 - start2) + (end1 - start1) + (end - start));
    }
    
    return ret;
}

unsigned long get_time() {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        unsigned long ret = tv.tv_usec;
        ret /= 1000;
        ret += (tv.tv_sec * 1000);
        return ret;
}