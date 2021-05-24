/* This file is automatically generated. DO NOT EDIT! */

#ifndef _sf_timer_h
#define _sf_timer_h


#include "_defs.h"
#include "_bool.h"


typedef struct ExecTimer *sf_timer;
/* abstract data type */


sf_timer sf_timer_init (void);
/*< Initialize timer object. >*/


void sf_timer_close (sf_timer timer);
/*< Destroy timer object. >*/


void sf_timer_start (sf_timer timer);
/*< Start time measurement session. >*/


void sf_timer_stop (sf_timer timer);
/*< Stop time measurement session. >*/


void sf_timer_reset (sf_timer timer);
/*< Reset the timer to 0. Does not change the timer running state. >*/


float sf_timer_get_total_time (sf_timer timer);
/*< Total time in msec for all sessions. after start. >*/


float sf_timer_get_diff_time (sf_timer timer);
/*< Time in msec for the last session. >*/


float sf_timer_get_average_time (sf_timer timer);
/*< Average time in msec. for all runs. >*/

#endif