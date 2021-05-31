/*
 * Initiates a memory and copy it, measuring the time to copy
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define NUM_EL (64 * 1024 * 1024)
#define SEED (120389747)

static int vec1[NUM_EL];
static int vec2[NUM_EL];

void init() {
  srand(SEED);
  for (uint i = 0; i < NUM_EL; i++) {
    vec1[i] = rand();
    vec2[i] = 0;
  }
}

void kernel() {
  for (uint i = 0; i < NUM_EL; i++)
    vec2[i] = vec1[i];
}

// declared in order to avoid the kernel() code being removed by compiler optimizations
void use_variables() {
    for (uint i = 0; i < NUM_EL; i++)
    {
        printf("%d\n", vec2[i]);
    }
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

  use_variables();

  FILE *oFile = fopen("mem_times.txt", "a");
  fprintf(oFile, "%lu\n", end_time - start_time);
}