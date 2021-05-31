#include <inttypes.h>
#include <stdio.h>
#include <sys/time.h>

#define NUM 40

uint64_t fibonacci(uint64_t n) {
  if (n > 2)
    return fibonacci(n - 1) + fibonacci(n - 2);
  else
    return n ? 1 : 0;
}

void init() {}
void kernel() {
  uint64_t f = fibonacci(NUM);
  printf("%lu\n", f);
}

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

  kernel();

  unsigned long end_time = get_time();

  FILE *oFile = fopen("rec_times.txt", "a");
  fprintf(oFile, "%lu\n", end_time - start_time);
}