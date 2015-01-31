/**
   proto_mod.c


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

   $Id: proto_mod.c,v 1.3 2001/07/20 23:33:14 ekr Exp $


   ekr@rtfm.com  Thu Jan  7 22:35:23 1999
 */


static char *RCSSTRING="$Id: proto_mod.c,v 1.3 2001/07/20 23:33:14 ekr Exp $";

#include "network.h"

int create_proto_handler(mod,ctx,handlerp,conn,first_packet)
  proto_mod *mod;
  proto_ctx *ctx;
  proto_handler **handlerp;
  tcp_conn *conn;
  struct timeval *first_packet;
  {
    int r,_status;
    proto_handler *handler=0;

    if(!(handler=(proto_handler *)calloc(sizeof(proto_handler),1)))
      ABORT(R_NO_MEMORY);
    handler->vtbl=mod->vtbl;
    if(r=mod->vtbl->create(mod->handle,ctx,conn,&handler->obj,
      &conn->i_addr,conn->i_port,&conn->r_addr,conn->r_port,first_packet))
      ABORT(r);

    *handlerp=handler;

    _status=0;
  abort:
    if(_status){
      destroy_proto_handler(&handler);
    }
    return(_status);
  }

int destroy_proto_handler(handlerp)
  proto_handler **handlerp;
  {
    if(!handlerp || !*handlerp)
      return(0);

    (*handlerp)->vtbl->destroy(&(*handlerp)->obj);
    free(*handlerp);
    *handlerp=0;
    return(0);
  }
