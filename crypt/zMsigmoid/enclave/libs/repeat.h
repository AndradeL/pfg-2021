/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_repeat_h
#define _sf_repeat_h


#include "_solver.h"


void sf_repeat_init(int m1            /* trace length */, 
		 int m2            /* number of traces */, 
		 sf_operator oper1 /* operator */);
/*< initialize >*/


void sf_repeat_lop (bool adj, bool add, int nx, int ny, float *xx, float *yy);
/*< combined linear operator >*/

#endif
