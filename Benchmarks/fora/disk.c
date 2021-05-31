/*
 * Initiates a memory and copy it, measuring the time to copy
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define BUF_SIZE (8 * 1024 * 1024)
#define SEED (120389747)

static uint8_t buf[BUF_SIZE];
static FILE *data_file;

void init() {
  data_file = fopen("data.txt", "rb+");
  if (!data_file)
    exit(1);
}

void read() { printf("%d\n", fread(buf, sizeof(uint8_t), BUF_SIZE, data_file)); }

void write() { printf("%d\n", fwrite(buf, sizeof(uint8_t), BUF_SIZE, data_file)); }

unsigned long get_time() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  unsigned long ret = tv.tv_usec;
  ret += (unsigned long)tv.tv_sec * (unsigned long)1000000;
  return ret;
}

int main(int argc, char *argv[]) {
  unsigned long start_time, end_time;
  FILE *oFile;
  init();

  start_time = get_time();
  read();
  end_time = get_time();

  oFile = fopen("diskr_times.txt", "a");
  fprintf(oFile, "%lu\n", end_time - start_time);
  fclose(oFile);

  start_time = get_time();
  write();
  end_time = get_time();

  oFile = fopen("diskw_times.txt", "a");
  fprintf(oFile, "%lu\n", end_time - start_time);
  fclose(oFile);

  fclose(data_file);
}