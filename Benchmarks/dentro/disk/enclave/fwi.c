#include "enclave_funcs.h"

#include "helloworld_t.h"

#define BUF_SIZE (8 * 1024 * 1024)

static uint8_t buf[BUF_SIZE];
static FILE *data_file;

void init() {
  data_file = fopen("data.txt", "rb+");
  if (!data_file)
    exit(1);
}

void read() { fread(buf, sizeof(uint8_t), BUF_SIZE, data_file); }

void write() { fwrite(buf, sizeof(uint8_t), BUF_SIZE, data_file); }