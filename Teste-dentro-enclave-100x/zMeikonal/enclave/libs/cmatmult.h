/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_cmatmult_h
#define _sf_cmatmult_h


#include "_bool.h"
#include "komplex.h"


void sf_cmatmult_init(sf_complex **bb_in);
/*< initialize matrix >*/


void sf_cmatmult_lop (bool adj, bool add, int nx, int ny, 
		      sf_complex *x, sf_complex *y);
/*< operator >*/

#endif
