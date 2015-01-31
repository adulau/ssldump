/**
   r_time.c


   Copyright (C) 1999-2000 RTFM, Inc.
   All Rights Reserved

   This package is a SSLv3/TLS protocol analyzer written by Eric Rescorla
   <ekr@rtfm.com> and licensed by RTFM, Inc.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. All advertising materials mentioning features or use of this software
      must display the following acknowledgement:
   
      This product includes software developed by Eric Rescorla for
      RTFM, Inc.

   4. Neither the name of RTFM, Inc. nor the name of Eric Rescorla may be
      used to endorse or promote products derived from this
      software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY ERIC RESCORLA AND RTFM, INC. ``AS IS'' AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY SUCH DAMAGE.

   $Id: r_time.c,v 1.6 2002/09/09 21:02:58 ekr Exp $


   ekr@rtfm.com  Thu Mar  4 08:43:46 1999
 */


static char *RCSSTRING="$Id: r_time.c,v 1.6 2002/09/09 21:02:58 ekr Exp $";

#include <r_common.h>
#include <r_time.h>

#ifdef _WIN32

#include <windows.h>

int gettimeofday(struct timeval *tv, struct timezone *tzp)
{
	/* JAN1_1970_OFFSET is the number of 100-nanoseconds ticks
	   between midnight jan 1, 1970 and jan 1, 1601.
	*/

	const ULARGE_INTEGER JAN1_1970_OFFSET = {0xd53e8000, 0x019db1de};
	ULARGE_INTEGER currentTimeSinceJan_1_1970;
	FILETIME currentTime;

	GetSystemTimeAsFileTime( &currentTime );
	currentTimeSinceJan_1_1970.LowPart = currentTime.dwLowDateTime;
	currentTimeSinceJan_1_1970.HighPart = currentTime.dwHighDateTime;
	currentTimeSinceJan_1_1970.QuadPart -= JAN1_1970_OFFSET.QuadPart;

	/* At this point, currentTimeSinceJan_1_1970 contains the
	   number of 100-nanosecond 'ticks' since midnight, Jan. 1,
	   1970. This is equivalent to 10 * the number of microseconds
	   elapsed since this time. The BSD man pages for gettimeofday()
	   suggest that we should return the whole number of seconds in
	   the tv_sec field, and the fractional number of seconds in units
	   of microseconds in the tv_usec field.

		sec = time / 10000000, usec = (time % 10000000) / 10;
	 */

	tv->tv_sec = currentTimeSinceJan_1_1970.QuadPart / 10000000;
	tv->tv_usec = (currentTimeSinceJan_1_1970.QuadPart % 10000000) / 10;
	return 0;
}
#endif
/*Note that t1 must be > t0 */
int r_timeval_diff(t1,t0,diff)
  struct timeval *t1;
  struct timeval *t0;
  struct timeval *diff;
  {
    long d;

    if(t0->tv_sec > t1->tv_sec)
      ERETURN(R_BAD_ARGS);

    /*Easy case*/
    if(t0->tv_usec <= t1->tv_usec){
      diff->tv_sec=t1->tv_sec - t0->tv_sec;
      diff->tv_usec=t1->tv_usec - t0->tv_usec;      
      return(0);
    }

    /*Hard case*/
    d=t0->tv_usec - t1->tv_usec;
    if(t1->tv_sec < (t0->tv_sec + 1))
      ERETURN(R_BAD_ARGS);
    diff->tv_sec=t1->tv_sec - (t0->tv_sec + 1);
    diff->tv_usec=1000000 - d;

    return(0);
  }

int r_timeval_add(t1,t2,sum)
  struct timeval *t1;
  struct timeval *t2;
  struct timeval *sum;
  {
    long tv_sec,tv_usec,d;

    tv_sec=t1->tv_sec + t2->tv_sec;

    d=t1->tv_usec + t2->tv_usec;
    if(d>1000000){
      tv_sec++;
      tv_usec=d-1000000;
    }
    else{
      tv_usec=d;
    }

    sum->tv_sec=tv_sec;
    sum->tv_usec=tv_usec;
    
    return(0);
  }

UINT8 r_timeval2int(tv)
  struct timeval *tv;
  {
    UINT8 r=0;
    
    r=(tv->tv_sec);
    r*=1000000;
    r+=tv->tv_usec;
        
    return r;
  }

UINT8 r_gettimeint()
  {
    struct timeval tv;

    gettimeofday(&tv,0);

    return r_timeval2int(&tv);
  }
