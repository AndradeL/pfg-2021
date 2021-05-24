/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_triangle2_h
#define _sf_triangle2_h


#include "_bool.h"


void sf_triangle2_init (int nbox1, int nbox2 /* triangle size */, 
			int ndat1, int ndat2 /* data size */,
			int nrep /* repeat smoothing */);
/*< initialize >*/


void sf_triangle2_lop (bool adj, bool add, int nx, int ny, float* x, float* y);
/*< linear operator >*/


void sf_triangle2_close(void);
/*< free allocated storage >*/

#endif