#include "enclave_funcs.h"

#include "helloworld_t.h"

#define NUM 40

uint64_t fibonacci(uint64_t n) {
  if (n > 2)
    return fibonacci(n - 1) + fibonacci(n - 2);
  else
    return n ? 1 : 0;
}

void init() {}
void kernel() { fibonacci(NUM); }