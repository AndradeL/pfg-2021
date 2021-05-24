/* Convolution with a Ricker wavelet. 
January 2013 program of the month:
http://ahay.org/blog/2013/01/08/program-of-the-month-sfricker1/
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
#include "ricker.h"

#include <sys/time.h>

unsigned long get_time();

int fwi(int argc, char **argv);

int main(int argc, char **argv){
    unsigned long start = get_time();
    fwi(argc,argv);
    unsigned long end = get_time();

    printf("%lu\n", end - start);
    
    return 0;
}

int fwi(int argc, char* argv[])
{

  //unsigned long start = get_time();
    bool deriv;
    int n1, n2, i2, order;
    int fft_size;
    float d1, freq, *trace=NULL;
    sf_file in=NULL, out=NULL;

    sf_init(argc,argv);
    in  = sf_input ( "rsf/in.rsf");
    out = sf_output("rsf/out.rsf");

    if (!sf_histint(in,"n1",&n1)) sf_error("No n1= in input");
    n2 = sf_leftsize(in,1);

    if (!sf_getfloat("frequency",&freq)) {
      /* peak frequency for Ricker wavelet (in Hz) */
      if (!sf_getfloat("freq",&freq)) freq=0.2;
      /* peak frequency for Ricker wavelet (as fraction of Nyquist) */
    } else {
      if (!sf_histfloat(in,"d1",&d1)) d1=1.;
      freq *= 2.*d1;
    }

    if (!sf_getbool("deriv",&deriv)) deriv=false;
    /* apply a half-order derivative filter */
    order = deriv? 2:0;

    trace = sf_floatalloc(n1);
    fft_size = 2*kiss_fft_next_fast_size((n1+1)/2);
    ricker_init(fft_size, 0.5*freq, order);

    for (i2=0; i2 < n2; i2++) {
	sf_floatread(trace,n1,in);
	sf_freqfilt(n1,trace);
	sf_floatwrite(trace,n1,out);
    }

    sf_fileclose(in);

  //  unsigned long end = get_time();

   // printf("@@Total time = %lu\n", end - start);
    return 0;
}

unsigned long get_time() {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        unsigned long ret = tv.tv_usec;
        ret += (tv.tv_sec * 1000000);
        return ret;
}