/**
   r_macros.h


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

   $Id: r_macros.h,v 1.4 2001/11/20 17:45:18 ekr Exp $


   ekr@rtfm.com  Tue Dec 22 10:37:32 1998
 */


#ifndef _r_macros_h
#define _r_macros_h

#if (R_USE_PROTOTYPES==1)
#define PROTO_LIST(a) a
#else
#define PROTO_LIST(a) ()
#endif

#ifndef __GNUC__
#define __FUNCTION__ "unknown"
#endif

#ifdef R_TRACE_ERRORS
#define REPORT_ERROR_(caller,a) fprintf(stderr,"%s: error %d at %s:%d (function %s)\n", \
	caller,a,__FILE__,__LINE__,__FUNCTION__)
#else
#define REPORT_ERROR_(caller,a)
#endif  

#ifndef ERETURN
#define ERETURN(a) do {int _r=a; if(!_r) _r=-1; REPORT_ERROR_("ERETURN",_r); return(_r);} while(0)
#endif

#ifndef ABORT
#define ABORT(a) do { int _r=a; if(!_r) _r=-1; REPORT_ERROR_("ABORT",_r); _status=_r; goto abort;} while(0)
#endif

#ifndef FREE
#define FREE(a) if(a) free(a)
#endif
#ifndef MIN
#define MIN(a,b) ((a)>(b))?(b):(a)
#endif

#ifndef MAX
#define MAX(a,b) ((b)>(a))?(b):(a)
#endif

#ifdef DEBUG
#define DBG(a) debug a
int debug(int class,char *format,...);
#else
#define DBG(a)
#endif

#ifndef RMALLOC
#define RMALLOC(a) malloc(a)
#endif

#ifndef RCALLOC
#define RCALLOC(a) calloc(1,a)
#endif

#ifndef RFREE
#define RFREE(a) if(a) free(a)
#endif

#ifndef RREALLOC
#define RREALLOC(a,b) realloc(a,b)
#endif

#define UNIMPLEMENTED do { fprintf(stderr,"Function %s unimplemented\n",__FUNCTION__); abort(); } while(0)


#endif 
