/**
   sslprint.h


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

   $Id: sslprint.h,v 1.3 2000/11/03 06:38:06 ekr Exp $


   ekr@rtfm.com  Wed Feb 10 15:34:14 1999
 */


#ifndef _sslprint_h
#define _sslprint_h

#include "ssl_analyze.h"
#include "ssl_h.h"

int ssl_expand_record PROTO_LIST((ssl_obj *ssl,
  segment *q,int direction,UCHAR *data,int len));
int ssl_decode_switch PROTO_LIST((ssl_obj *ssl,
  decoder *dtable,int value,int dir,segment *seg,Data *data));
int ssl_decode_uintX PROTO_LIST((ssl_obj *ssl,char *name,int size,
  UINT4 print,Data *data,UINT4 *x));
int ssl_decode_opaque_array PROTO_LIST((ssl_obj *ssl,char *name,int size,
  UINT4 print,Data *data,Data *x));
int ssl_decode_enum PROTO_LIST((ssl_obj *ssl,char *name,
  int size,decoder *decode,UINT4 p,Data *data,
  UINT4 *x));
int ssl_lookup_enum PROTO_LIST((ssl_obj *ssl,decoder *dtable,
  UINT4 val,char **ptr));
int ssl_print_enum PROTO_LIST((ssl_obj *obj,char *name,
  decoder *decode,UINT4 value));
int print_data PROTO_LIST((ssl_obj *ssl,Data *d));
int process_v2_hello PROTO_LIST((ssl_obj *ssl,segment *seg));
int process_beginning_plaintext PROTO_LIST((ssl_obj *ssl,
  segment *seg,int direction));
int ssl_print_direction_indicator PROTO_LIST((ssl_obj *ssl,int dir));
int ssl_print_timestamp PROTO_LIST((ssl_obj *ssl,struct timeval *ts));
int ssl_print_record_num PROTO_LIST((ssl_obj *ssl));
int ssl_print_cipher_suite PROTO_LIST((ssl_obj *ssl,int version,int p,
  UINT4 val));

int explain PROTO_LIST((ssl_obj *ssl,char *format,...));
int exdump PROTO_LIST((ssl_obj *ssl,char *name,Data *data));


#define SSL_DECODE_UINT8(a,n,b,c,d) if(r=ssl_decode_uintX(a,n,1,b,c,d)) ERETURN(r)
#define SSL_DECODE_UINT16(a,n,b,c,d) if(r=ssl_decode_uintX(a,n,2,b,c,d)) ERETURN(r)
#define SSL_DECODE_UINT24(a,n,b,c,d) if(r=ssl_decode_uintX(a,n,3,b,c,d)) ERETURN(r)
#define SSL_DECODE_UINT32(a,n,b,c,d) if(r=ssl_decode_uintX(a,n,4,b,c,d)) ERETURN(r)
#define SSL_DECODE_OPAQUE_ARRAY(a,n,b,c,d,e) if(r=ssl_decode_opaque_array(a,n,b,c,d,e)) ERETURN(r)
#define SSL_DECODE_ENUM(a,b,c,d,e,f,g) if(r=ssl_decode_enum(a,b,c,d,e,f,g)) ERETURN(r)
#define P_(p)              if((p==SSL_PRINT_ALL) || (p & SSL_print_flags))

#define INDENT  do {int i; for(i=0;i<(ssl->indent_depth + ssl->indent_name_len);i++)  printf("%s",SSL_print_flags & SSL_PRINT_NROFF?" ":" ");} while(0)
#define INDENT_INCR ssl->indent_depth+=2
#define INDENT_POP ssl->indent_depth-=2
#define INDENT_NAME(x) ssl->indent_name_len += strlen(x)
#define INDENT_NAME_POP ssl->indent_name_len=0
#define LINE_LEFT (80-(ssl->indent_name_len + ssl->indent_depth)
#define LF printf("\n")
  
#endif

