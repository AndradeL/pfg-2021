#include "enclave_funcs.h"

#include "helloworld_t.h"

#ifndef NUM
#define NUM 8
#endif

#define BUF_SIZE (NUM * 1024 * 1024)

static uint8_t buf[BUF_SIZE];
static FILE *read_file;
static FILE *write_file;
static size_t size;

void init() {
  size = 0;
  read_file = fopen("data.txt", "rb");
  write_file = fopen("copy.txt", "wb");
  if (!read_file || !write_file)
    exit(1);
}

void t_read() { size = fread(buf, sizeof(uint8_t), BUF_SIZE, read_file); }

void t_write() { fwrite(buf, sizeof(uint8_t), size, write_file); }

void t_close() {
  size = 0;
  if (read_file)
    fclose(read_file);
  if (write_file)
    fclose(write_file);
}