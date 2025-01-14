/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_stretch4_h
#define _sf_stretch4_h


#include "_bool.h"
#include "c99.h"


typedef struct sf_Map4 *sf_map4;
/* abstract data type */


sf_map4 sf_stretch4_init (int n1, float o1, float d1 /* regular axis */, 
		    int nd                     /* data samples */, 
		    float eps                  /* regularization */);
/*< initialize >*/


void sf_stretch4_define (sf_map4 str, const float* coord /* [nd] */);
/*< set coordinates >*/


void sf_cstretch4_apply (sf_map4 str, 
		      const sf_complex* ord /* [nd] */, 
		      sf_complex* mod       /* [n1] */);
/*< complex transform ordinates to model >*/


void sf_stretch4_apply_adj (bool add,  /* add flag */
			    sf_map4 str, 
			    float* ord /* [nd] */, 
			    float* mod /* [n1] */);
/*< transform model to ordinates by adjoint operation >*/


void sf_stretch4_apply (bool add /* add flag */,
		     sf_map4 str, 
		     float* ord /* [nd] */, 
		     float* mod /* [n1] */);
/*< transform ordinates to model >*/


void sf_cstretch4_invert (sf_map4 str, 
		       sf_complex* ord       /* [nd] */, 
		       const sf_complex* mod /* [n1] */);
/*< convert model to ordinates by spline interpolation >*/


void sf_stretch4_invert (bool add /* add flag */,
		      sf_map4 str, 
		      float* ord /* [nd] */, 
		      float* mod /* [n1] */);
/*< convert model to ordinates by spline interpolation >*/


void sf_stretch4_invert_adj (bool add /* add flag */,
			  sf_map4 str, 
			  float* ord /* [nd] */, 
			  float* mod       /* [n1] */);
/*< convert ordinates to model by adjoint spline interpolation >*/


void sf_stretch4_close (sf_map4 str);
/*< free allocated storage >*/

#endif
