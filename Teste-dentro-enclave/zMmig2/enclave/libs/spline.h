/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_spline_h
#define _sf_spline_h


#include "banded.h"
#include "tridiagonal.h"


sf_bands sf_spline_init (int nw /* interpolator length */, 
			 int nd /* data length */);
/*< initialize a banded matrix >*/


sf_tris sf_spline4_init (int nd /* data length */);
/*< initialize a tridiagonal matrix for cubic splines >*/


void sf_spline4_post (int n            /* total trace length */, 
		      int n1           /* start point */, 
		      int n2           /* end point */, 
		      const float* inp /* spline coefficients */, 
		      float* out       /* function values */);
/*< cubic spline post-filtering >*/


void sf_spline_post (int nw, int o, int d, int n, 
		     const float *modl, float *datr);
/*< post-filtering to convert spline coefficients to model >*/


void sf_spline2 (sf_bands slv1, sf_bands slv2, 
		 int n1, int n2, float** dat, float* tmp);
/*< 2-D spline pre-filtering >*/


void sf_spline3 (sf_bands slv1, sf_bands slv2, sf_bands slv3, 
		 int n1, int n2, int n3, float*** dat, float* tmp2, float* tmp3);
/*< 3-D spline pre-filtering >*/

#endif
