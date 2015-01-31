/**
   ciphersuites.c


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

   $Id: ciphersuites.c,v 1.3 2002/08/17 01:33:17 ekr Exp $


   ekr@rtfm.com  Tue Mar 30 17:19:56 1999
 */


static char *RCSSTRING="$Id: ciphersuites.c,v 1.3 2002/08/17 01:33:17 ekr Exp $";

#include <r_common.h>

#include "sslciphers.h"

static SSL_CipherSuite CipherSuites[]={
     {1,KEX_RSA,SIG_RSA,ENC_NULL,0,0,0,DIG_MD5,16,0},
     {2,KEX_RSA,SIG_RSA,ENC_NULL,0,0,0,DIG_SHA,20,0},
     {3,KEX_RSA,SIG_RSA,ENC_RC4,1,128,40,DIG_MD5,16,1},
     {4,KEX_RSA,SIG_RSA,ENC_RC4,1,128,128,DIG_MD5,16,0},
     {5,KEX_RSA,SIG_RSA,ENC_RC4,1,128,128,DIG_SHA,20,0},
     {6,KEX_RSA,SIG_RSA,ENC_RC2,8,128,40,DIG_SHA,20,1},
     {7,KEX_RSA,SIG_RSA,ENC_IDEA,8,128,128,DIG_SHA,20,0},
     {8,KEX_RSA,SIG_RSA,ENC_DES,8,64,40,DIG_SHA,20,1},
     {9,KEX_RSA,SIG_RSA,ENC_DES,8,64,64,DIG_SHA,20,0},
     {10,KEX_RSA,SIG_RSA,ENC_3DES,8,192,192,DIG_SHA,20,0},
     {11,KEX_DH,SIG_DSS,ENC_DES,8,64,40,DIG_SHA,20,1},
     {12,KEX_DH,SIG_DSS,ENC_DES,8,64,64,DIG_SHA,20,0},
     {13,KEX_DH,SIG_DSS,ENC_3DES,8,192,192,DIG_SHA,20,0},
     {14,KEX_DH,SIG_RSA,ENC_DES,8,64,40,DIG_SHA,20,1},
     {15,KEX_DH,SIG_RSA,ENC_DES,8,64,64,DIG_SHA,20,0},
     {16,KEX_DH,SIG_RSA,ENC_3DES,8,192,192,DIG_SHA,20,0},
     {17,KEX_DH,SIG_DSS,ENC_DES,8,64,40,DIG_SHA,20,1},
     {18,KEX_DH,SIG_DSS,ENC_DES,8,64,64,DIG_SHA,20,0},
     {19,KEX_DH,SIG_DSS,ENC_3DES,8,192,192,DIG_SHA,20,0},
     {20,KEX_DH,SIG_RSA,ENC_DES,8,64,40,DIG_SHA,20,1},
     {21,KEX_DH,SIG_RSA,ENC_DES,8,64,64,DIG_SHA,20,0},
     {22,KEX_DH,SIG_RSA,ENC_3DES,8,192,192,DIG_SHA,20,0},
     {23,KEX_DH,SIG_NONE,ENC_RC4,1,128,40,DIG_MD5,16,1},
     {24,KEX_DH,SIG_NONE,ENC_RC4,1,128,128,DIG_MD5,16,0},     
     {25,KEX_DH,SIG_NONE,ENC_DES,8,64,40,DIG_MD5,16,1},
     {26,KEX_DH,SIG_NONE,ENC_DES,8,64,64,DIG_MD5,16,0},
     {27,KEX_DH,SIG_NONE,ENC_3DES,8,192,192,DIG_MD5,16,0},
     {96,KEX_RSA,SIG_RSA,ENC_RC4,1,128,56,DIG_MD5,16,1},
     {97,KEX_RSA,SIG_RSA,ENC_RC2,1,128,56,DIG_MD5,16,1},
     {98,KEX_RSA,SIG_RSA,ENC_DES,8,64,64,DIG_SHA,20,1},
     {99,KEX_DH,SIG_DSS,ENC_DES,8,64,64,DIG_SHA,16,1},
     {100,KEX_RSA,SIG_RSA,ENC_RC4,1,128,56,DIG_SHA,20,1},
     {101,KEX_DH,SIG_DSS,ENC_RC4,1,128,56,DIG_SHA,20,1},     
     {102,KEX_DH,SIG_DSS,ENC_RC4,1,128,128,DIG_SHA,20,0},
     {-1}
};

int ssl_find_cipher(num,cs)
  int num;
  SSL_CipherSuite **cs;
  {
    SSL_CipherSuite *c;

    for(c=CipherSuites;c->number!=-1;c++){
      if(c->number==num){
	*cs=c;
	return(0);
      }
    }

    ERETURN(R_NOT_FOUND);
  }
  
     
