/* This file is automatically generated. DO NOT EDIT! */

#ifndef _linear_h
#define _linear_h


void linear_init(int n1 /* trace length */);
/*< initialize >*/


void linear_close (void);
/*< free allocated storage >*/


void linear_coeffs(float* x1, float *a1);
/*< fill coefficients table >*/


float linear_eval(float y);
/*< evaluate a cubic spline >*/

#endif