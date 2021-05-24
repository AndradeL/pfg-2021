/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_pweno_h
#define _sf_pweno_h


#include "_defs.h"


typedef struct Pweno *sf_pweno;
/* abstract data type */


typedef enum {FUNC1, DER1, BOTH1} derr;
/* flag values */


sf_pweno sf_pweno_init (int order /* interpolation order */,
              int n     /* data size */);
/*< Initialize interpolation object >*/


void sf_pweno_close (sf_pweno ent);
/*< Free internal storage >*/


float powerpeno (float x, float y, int p /* power order */);
/*< Limiter power-p eno >*/


void sf_pweno_set (sf_pweno ent, float* c /* data [n] */, int p /* power order */);
/*< Set the interpolation undivided difference table. c can be changed or freed afterwards >*/


void sf_pweno_apply (sf_pweno ent, 
		int i     /* grid location */, 
		float x   /* offset from grid */, 
		float *f  /* output data value */, 
		float *f1 /* output derivative */, 
		derr what /* flag of what to compute */);
/*< Apply interpolation >*/

#endif