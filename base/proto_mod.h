/**
   proto_mod.h


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

   $Id: proto_mod.h,v 1.4 2001/11/26 22:28:16 ekr Exp $


   ekr@rtfm.com  Thu Dec 24 21:10:05 1998
 */


#ifndef _proto_mod_h
#define _proto_mod_h

typedef struct proto_obj_ proto_obj;
typedef struct proto_ctx_ proto_ctx;

#define DIR_I2R    1
#define DIR_R2I	   2

struct proto_mod_vtbl_ {
     int (*parse_flags) PROTO_LIST((char *str));
     int (*parse_flag) PROTO_LIST((int flag));
     int (*create_ctx) PROTO_LIST((void *handle,proto_ctx **ctxp));
     int (*create) PROTO_LIST((void *handle,proto_ctx *ctx,
       tcp_conn *conn,
       proto_obj **objp,
       struct in_addr *i_addr,u_short i_port,
       struct in_addr *r_addr,u_short r_port,struct timeval *time_base));
     int (*destroy) PROTO_LIST((proto_obj **objp));
     int (*data) PROTO_LIST((proto_obj *obj,segment *data,int direction));
     int (*close) PROTO_LIST((proto_obj *obj,packet *p,int direction));
};

struct proto_mod_ {
     void *handle;
     struct proto_mod_vtbl_ *vtbl;
};

struct proto_handler_ {
     proto_obj *obj;
     struct proto_mod_vtbl_ *vtbl;
};

int create_proto_handler PROTO_LIST((proto_mod *mod,proto_ctx *ctx,
  proto_handler **handlerp,
  tcp_conn *conn,struct timeval *first_packet));
int destroy_proto_handler PROTO_LIST((proto_handler **handlerp));

#endif

