/* Multidimensional convolution and deconvolution by helix transform. 
May 2014 program of the month:
http://ahay.org/blog/2014/05/13/program-of-the-month-sfhelicon/
*/
/*
  Copyright (C) 2004 University of Texas at Austin
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <rsf.h>

#include "regrid.h"

#include <sys/time.h>

unsigned long get_time();

int run(int argc, char **argv);

int main(int argc, char **argv){
    unsigned long start = get_time();
    run(argc,argv);
    unsigned long end = get_time();

    printf("%lu\n", end - start);
    
    return 0;
}

int run(int argc, char* argv[])
{
    //unsigned long start = get_time();
    int i, ia, na, nx, dim, n[SF_MAX_DIM], m[SF_MAX_DIM];
    float a0, *pp, *qq;
    bool adj, inv;
    sf_filter aa;
    char* lagfile;
    sf_file in, out, filt, lag;

    sf_init (argc,argv);
    in = sf_input("rsf/spike.rsf");
    filt = sf_input("filt");
    out = sf_output("rsf/shorz1.rsf");

    dim = sf_filedims (in,n);

    if (!sf_histint(filt,"n1",&na)) sf_error("No n1= in filt");
    aa = sf_allocatehelix (na);

    if (!sf_histfloat(filt,"a0",&a0)) a0=1.;
    sf_floatread (aa->flt,na,filt);
    for( ia=0; ia < na; ia++) {
	aa->flt[ia] /= a0;
    }

    if (NULL != (lagfile = sf_getstring("lag")) 
	/*( lag file with filter lags )*/
	|| 
	NULL != (lagfile = sf_histstring(filt,"lag"))) {
	lag = sf_input(lagfile);

	sf_intread(aa->lag,na,lag);
    } else {
	lag = NULL;
	for( ia=0; ia < na; ia++) {
	    aa->lag[ia] = ia+1;
	}
    }

    sf_fileclose(filt);
    
    if (!sf_getints ("n",m,dim) && (NULL == lag ||
				    !sf_histints (lag,"n",m,dim))) {
	for (i=0; i < dim; i++) {
	    m[i] = n[i];
	}
    }
 
    if (NULL != lag) sf_fileclose(lag);

    regrid (dim, m, n, aa);

    if (!sf_getbool ("adj",&adj)) adj=false;
    /* if y, do adjoint operation */
    if (!sf_getbool ("div",&inv)) inv=false;
    /* if y, do inverse operation (deconvolution) */

    nx = 1;
    for( i=0; i < dim; i++) {
	nx *= n[i];
    }
  
    pp = sf_floatalloc (nx);
    qq = sf_floatalloc (nx);

    if (adj) {
	sf_floatread (qq,nx,in);
    } else {
	sf_floatread (pp,nx,in);
    }

    if (inv) {
	sf_polydiv_init (nx, aa);
	sf_polydiv_lop (adj,false,nx,nx,pp,qq);
	sf_polydiv_close();
    } else {
	sf_helicon_init (aa);
	sf_helicon_lop (adj,false,nx,nx,pp,qq);
    }

    if (adj) {
	sf_floatwrite (pp,nx,out);
    } else {
	sf_floatwrite (qq,nx,out);
    }

    //unsigned long end = get_time();

    //printf("@@Time total = %lu\n", end - start);
    return 0;
}

unsigned long get_time() {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        unsigned long ret = tv.tv_usec;
        ret += (unsigned long)tv.tv_sec * (unsigned long)1000000;
        return ret;
}