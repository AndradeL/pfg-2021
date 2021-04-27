/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_decart_h
#define _sf_decart_h


#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE
#endif
#include <sys/types.h>
#include <unistd.h>


void sf_line2cart(int dim         /* number of dimensions */, 
		  const int* nn /* box size [dim] */, 
		  int i         /* line coordinate */, 
		  int* ii       /* cartesian coordinates [dim] */);
/*< Convert line to Cartesian >*/


int sf_cart2line(int dim         /* number of dimensions */, 
		 const int* nn /* box size [dim] */, 
		 const int* ii /* cartesian coordinates [dim] */);
/*< Convert Cartesian to line >*/


int sf_first_index (int i          /* dimension [0...dim-1] */, 
		    int j        /* line coordinate */, 
		    int dim        /* number of dimensions */, 
		    const int *n /* box size [dim] */, 
		    const int *s /* step [dim] */);
/*< Find first index for multidimensional transforms >*/


void sf_large_line2cart(int dim         /* number of dimensions */, 
			const off_t* nn /* box size [dim] */, 
			off_t i         /* line coordinate */, 
			off_t* ii       /* cartesian coordinates [dim] */);
/*< Convert line to Cartesian >*/


off_t sf_large_cart2line(int dim         /* number of dimensions */, 
			 const off_t* nn /* box size [dim] */, 
			 const off_t* ii /* cartesian coordinates [dim] */);
/*< Convert Cartesian to line >*/


off_t sf_large_first_index (int i          /* dimension [0...dim-1] */, 
			    off_t j        /* line coordinate */, 
			    int dim        /* number of dimensions */, 
			    const off_t *n /* box size [dim] */, 
			    const off_t *s /* step [dim] */);
/*< Find first index for multidimensional transforms >*/

#endif
