/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_getpar_h
#define _sf_getpar_h


#include "_bool.h"
#include "simtab.h"


bool sf_stdin(void);
/*< returns true if there is an input in stdin >*/


void sf_init(int argc,char *argv[]);
/*< initialize parameter table from command-line arguments >*/


void sf_parenv(const char *string);
/*< add parameters from an environmental variable >*/


void sf_parclose (void);
/*< close parameter table and free space >*/


void sf_parout (FILE *file);
/*< write the parameters to a file >*/


char* sf_getprog (void);
/*< returns name of the running program >*/


char* sf_getuser (void);
/*< returns user name >*/


char* sf_gethost (void);
/*< returns host name >*/


char* sf_getcdir (void);
/*< returns current directory >*/


bool sf_getint (const char* key,/*@out@*/ int* par);
/*< get an int parameter from the command line >*/


bool sf_getlargeint (const char* key,/*@out@*/ off_t* par);
/*< get a large int parameter from the command line >*/


bool sf_getints (const char* key,/*@out@*/ int* par,size_t n);
/*< get an int array parameter (comma-separated) from the command line >*/


bool sf_getfloat (const char* key,/*@out@*/ float* par);
/*< get a float parameter from the command line >*/


bool sf_getdouble (const char* key,/*@out@*/ double* par);
/*< get a double parameter from the command line >*/


bool sf_getfloats (const char* key,/*@out@*/ float* par,size_t n);
/*< get a float array parameter from the command line >*/


char* sf_getstring (const char* key);
/*< get a string parameter from the command line >*/


bool sf_getstrings (const char* key,/*@out@*/ char** par,size_t n);
/*< get a string array parameter from the command line >*/


bool sf_getbool (const char* key,/*@out@*/ bool* par);
/*< get a bool parameter from the command line >*/


bool sf_getbools (const char* key,/*@out@*/ bool* par,size_t n);
/*< get a bool array parameter from the command line >*/


sf_simtab sf_getpars (void);
/*< provide access to the parameter table >*/

#endif