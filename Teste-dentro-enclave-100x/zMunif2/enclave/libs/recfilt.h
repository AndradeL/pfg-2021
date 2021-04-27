/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_recfilt_h
#define _sf_recfilt_h


#include "_bool.h"


void sf_recfilt_init( int nd    /* data size */, 
		   int nb    /* filter size */, 
		   float* bb /* filter [nb] */);
/*< initialize >*/


void sf_recfilt_lop( bool adj, bool add, int nx, int ny, float* xx, float*yy);
/*< linear operator >*/


void sf_recfilt_close (void);
/*< free allocated storage >*/

#endif
