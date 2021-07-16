#include <inttypes.h>
#include <stdio.h>
#include <sys/time.h>

#define NUM 100000

// modified from https://www.cplusplus.com/reference/ctime/clock/
int frequency_of_primes(int n) {
  int i, j;
  int freq = n - 1;
  for (i = 2; i <= n; ++i)
    for (j = i / 2; j > 1; --j)
      if (i % j == 0) {
        --freq;
        break;
      }
  return freq;
}

void init() {}
int kernel() { return frequency_of_primes(NUM); }

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

  int n = kernel();

  unsigned long end_time = get_time();

  printf("%d\n", n);
  FILE *oFile = fopen("cpu_times.txt", "a");
  fprintf(oFile, "%lu, ", end_time - start_time);
  fclose(oFile);
}