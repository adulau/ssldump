/**
   ssl_rec.h


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

   $Id: ssl_rec.h,v 1.2 2000/10/17 16:10:02 ekr Exp $


   ekr@rtfm.com  Wed Aug 18 16:16:23 1999
 */


#ifndef _ssl_rec_h
#define _ssl_rec_h

typedef struct ssl_rec_decoder_ ssl_rec_decoder;

int ssl_destroy_rec_decoder PROTO_LIST((ssl_rec_decoder **dp));
int ssl_create_rec_decoder PROTO_LIST((ssl_rec_decoder **dp,
  SSL_CipherSuite *cs,UCHAR *mk,UCHAR *sk,UCHAR *iv));
int ssl_decode_rec_data PROTO_LIST((ssl_obj *ssl,ssl_rec_decoder *d,
  int ct,int version,UCHAR *in,int inl,UCHAR *out,int *outl));
int ssl3_check_mac(ssl_rec_decoder *d, int ct, int ver, UCHAR *data,
  UINT4 datalen, UCHAR *mac);
 
#define IS_AEAD_CIPHER(cs) (cs->enc==0x3b||cs->enc==0x3c)
#endif

