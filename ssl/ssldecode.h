/**
   ssldecode.h


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

   $Id: ssldecode.h,v 1.3 2001/07/20 23:33:16 ekr Exp $


   ekr@rtfm.com  Thu Apr  1 15:02:02 1999
 */


#ifndef _ssldecode_h
#define _ssldecode_h

#define CRDUMP(a,b,c) P_(P_CR) {Data d; d.data=b; d.len=c; exdump(ssl,a,&d); printf("\n");}
#define CRDUMPD(a,b) P_(P_CR) {exdump(ssl,a,b);printf("\n");}

int ssl_decode_ctx_create PROTO_LIST((ssl_decode_ctx **ctx,
  char *keyfile,char *password));
int ssl_decoder_destroy PROTO_LIST((ssl_decoder **dp));
int ssl_decoder_create PROTO_LIST((ssl_decoder **dp,ssl_decode_ctx *ctx));
int ssl_set_client_random PROTO_LIST((ssl_decoder *dp,
  UCHAR *msg,int len));
int ssl_set_server_random PROTO_LIST((ssl_decoder *dp,
  UCHAR *msg,int len));
int ssl_set_client_session_id PROTO_LIST((ssl_decoder *dp,
  UCHAR *msg,int len));
int ssl_process_server_session_id PROTO_LIST((ssl_obj *obj,ssl_decoder *dp,
  UCHAR *msg,int len));
int ssl_process_client_key_exchange PROTO_LIST((struct ssl_obj_ *,
  ssl_decoder *d,UCHAR *msg,int len));
int ssl_process_change_cipher_spec PROTO_LIST((ssl_obj *ssl,
  ssl_decoder *d,int direction));

int ssl_decode_record PROTO_LIST((ssl_obj *ssl,ssl_decoder *dec,int direction,
  int ct,int version,Data *d));


#endif

