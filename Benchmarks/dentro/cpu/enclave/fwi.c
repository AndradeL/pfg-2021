#include "enclave_funcs.h"

#include "helloworld_t.h"

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