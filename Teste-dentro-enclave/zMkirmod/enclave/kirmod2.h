/* This file is automatically generated. DO NOT EDIT! */

#ifndef _kirmod2_h
#define _kirmod2_h


#include "kirmod.h"


typedef struct Surface *surface;
/* abstract data type */


typedef struct Velocity {
    float v0, gx, gz, x0, z0, vz, n;
} *velocity;


surface kirmod2_init(int ns,  float s0,  float ds  /* source/midpoint axis */,
		     int nh,  float h0,  float dh  /* offset axis */,
		     int nx1, float x01, float dx1 /* reflector axis */,
		     int nc1                       /* number of reflectors */,
                     bool cmp                      /* if CMP instead of shot gather */,
                     bool absoff                   /* use absolute offset */);
/*< Initialize surface locations >*/


void kirmod2_close(surface y);
/*< Free allocated storage >*/


void kirmod2_table (surface y                  /* surface structure */,
		    velocity v                 /* velocity attributes */, 
		    char type                  /* velocity distribution */,
		    bool twod                  /* 2-D or 2.5-D */, 
		    float **curve              /* reflectors */,
		    float **dip                /* reflector dip */);
/*< Compute traveltime/amplitude map >*/


ktable kirmod2_map(surface y, int is, int ih, int ix, int ic);
/*< Extract from traveltime/amplitude map >*/

#endif
