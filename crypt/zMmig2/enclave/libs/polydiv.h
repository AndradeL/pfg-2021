/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_polydiv_h
#define _sf_polydiv_h


#include "helix.h"


void sf_polydiv_init( int nd       /* data size */, 
		      sf_filter bb /* filter */);
/*< initialize >*/


void sf_polydiv_lop( bool adj, bool add, 
		     int nx, int ny, float* xx, float*yy);
/*< linear operator >*/


void sf_polydiv_close (void);
/*< free allocated storage >*/

#endif