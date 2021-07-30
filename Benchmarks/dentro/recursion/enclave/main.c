#include "enclave_funcs.h"

#include "helloworld_t.h"

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