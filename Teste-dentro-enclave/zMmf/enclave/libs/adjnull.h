/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_adjnull_h
#define _sf_adjnull_h


#include "_bool.h"
#include "c99.h"


void sf_adjnull (bool adj /* adjoint flag */, 
		 bool add /* addition flag */, 
		 int nx   /* size of x */, 
		 int ny   /* size of y */, 
		 float* x, 
		 float* y);
/*< Zeros out the output (unless add is true). 
  Useful first step for any linear operator. >*/


void sf_cadjnull (bool adj /* adjoint flag */, 
		  bool add /* addition flag */, 
		  int nx   /* size of x */, 
		  int ny   /* size of y */, 
		  sf_complex* x, 
		  sf_complex* y);
/*< adjnull version for complex data. >*/

#endif
