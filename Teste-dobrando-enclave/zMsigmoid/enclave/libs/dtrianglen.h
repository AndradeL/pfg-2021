/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_dtrianglen_h
#define _sf_dtrianglen_h


void sf_dtrianglen_init (int ndim  /* number of dimensions */, 
			 int *nbox /* triangle radius [ndim] */, 
			 int *ndat /* data dimensions [ndim] */);
/*< initialize >*/


void sf_dtrianglen (int ider   /* direction of the derivative */,
		    int nrep   /* how many times to repeat smoothing */,
		    int nderiv /* derivative filter accuracy */,
		    float* data   /* input/output */);
/*< linear operator (derivative with respect to radius) >*/


void sf_dtrianglen_close(void);
/*< free allocated storage >*/

#endif
