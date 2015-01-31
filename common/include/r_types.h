/**
   r_types.h


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

   $Id: r_types.h,v 1.3 2002/09/09 21:02:58 ekr Exp $


   ekr@rtfm.com  Tue Dec 22 10:36:02 1998
 */


#ifndef _r_types_h
#define _r_types_h

#ifndef R_DEFINED_UINT4
#ifndef SIZEOF_UNSIGNED_INT
typedef unsigned int UINT4;
#else
# if (SIZEOF_UNSIGNED_INT==4)
typedef unsigned int UINT4;
# elif (SIZEOF_UNSIGNED_SHORT==4)
typedef unsigned short UINT4;
# elif (SIZEOF_UNSIGNED_LONG==4)
typedef unsigned long UINT4;
# else
# error no type for UINT4
# endif
#endif
#endif

#ifndef R_DEFINED_UINT8
#ifndef SIZEOF_UNSIGNED_LONG
typedef unsigned long UINT8;
#else
# if (SIZEOF_UNSIGNED_INT==8)
typedef unsigned int UINT8;
# elif (SIZEOF_UNSIGNED_SHORT==8)
typedef unsigned short UINT8;
# elif (SIZEOF_UNSIGNED_LONG==8)
typedef unsigned long UINT8;
# elif (SIZEOF_UNSIGNED_LONG_LONG==8)
typedef unsigned long long UINT8;
# elif defined (_WIN32) && defined (_MSC_VER)
typedef unsigned __int64 UINT8;
# else
# error no type for UINT8
# endif
#endif
#endif

#ifndef R_DEFINED_UCHAR
typedef unsigned char UCHAR;
#endif

#endif

