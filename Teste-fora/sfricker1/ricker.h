/* This file is automatically generated. DO NOT EDIT! */

#ifndef _ricker_h
#define _ricker_h


void ricker_init(int nfft   /* time samples */, 
		 float freq /* frequency */,
		 int order  /* derivative order */);
/*< initialize >*/


void ricker_close(void);
/*< free allocated storage >*/

#endif
