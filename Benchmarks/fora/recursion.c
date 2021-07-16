#include <inttypes.h>
#include <stdio.h>
#include <sys/time.h>

#ifndef NUM
#define NUM 40
#endif

uint64_t fibonacci(uint64_t n) {
  if (n > 2)
    return fibonacci(n - 1) + fibonacci(n - 2);
  else
    return n ? 1 : 0;
}

void init() {}
uint64_t kernel() { return fibonacci(NUM); }

unsigned long get_time() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  unsigned long ret = tv.tv_usec;
  ret += (unsigned long)tv.tv_sec * (unsigned long)1000000;
  return ret;
}

int main(int argc, char *argv[]) {
  init();
  unsigned long start_time = get_time();

  uint64_t num = kernel();

  unsigned long end_time = get_time();

  fprintf(stderr, "%lu\n", num);
  FILE *oFile = fopen("rec_times.txt", "a");
  fprintf(oFile, "%lu, ", end_time - start_time);
  fclose(oFile);
}