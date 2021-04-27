/* This file is automatically generated. DO NOT EDIT! */

#ifndef _kirmod_h
#define _kirmod_h


typedef struct KTable {
    float t  /* traveltime */;
    float a  /* geometrical spreading */;
    float tx /* traveltime slope (dt/dx) */;
    float ty /* traveltime slope (dt/dy) */;
    float tn /* obliguity (dt/dn) */;
    float an /* angle from the normal */;
    float ar /* 2.5-D factor (1/r dt/dr) */;
} *ktable;


void kirmod_table(char type    /* type of velocity distribution */,
		  bool twod    /* 2-D or 2.5-D/3-D */,
		  float z,
		  float x,
		  float y      /* distance between source and receiver */, 
		  float g      /* absolute gradient */,
		  float gx     /* gx+gz*zx */,
		  float gy     /* gy+gz*zy */,
		  float gz     /* gz-gx*zx */,
		  float v1     /* source velocity function */, 
		  float v2     /* receiver velocity function */,
		  float vn     /* "NMO" velocity */,
		  float n      /* "eta" parameter */,
		  float px     /* x+z*zx */,
		  float py     /* y+z*zy */,
		  float pz     /* z-x*zx */,
		  float dz     /* hypotf(1.0,zx) */,
		  ktable table /* [5] output table */);
/*< Compute traveltime attributes >*/

#endif
