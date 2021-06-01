#include <inttypes.h>
#include <stdio.h>
#include <sys/time.h>

#define NUM 8

uint64_t fibonacci(uint64_t n) {
  uint64_t a, b, c;
  a = 0;
  b = 1;
  for (size_t i = 0; i < n; i++)
  {
    c = a + b;
    a = b;
    b = c;
  }
  return a;
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

  FILE *oFile = fopen("cpu_times.txt", "a");
  fprintf(oFile, "%lu\n", end_time - start_time);
}