#include "enclave_funcs.h"

#include "helloworld_t.h"

#define NUM_EL (64 * 1024 * 1024)
#define SEED (120389747)

static int vec1[NUM_EL];
static int vec2[NUM_EL];

void init() {
  srand(SEED);
  for (size_t i = 0; i < NUM_EL; i++) {
    vec1[i] = rand();
    vec2[i] = 0;
  }
}

void kernel() {
  for (size_t i = 0; i < NUM_EL; i++)
    vec2[i] = vec1[i];
}

// declared in order to avoid the kernel() code being removed by compiler optimizations
void use_variables() {
    for (size_t i = 0; i < NUM_EL; i++)
    {
        printf("%d\n", vec2[i]);
    }
}