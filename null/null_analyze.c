/**
   null_analyze.c


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

   $Id: null_analyze.c,v 1.6 2001/11/26 22:28:16 ekr Exp $


   ekr@rtfm.com  Thu Jan  7 22:58:27 1999
 */


static char *RCSSTRING="$Id: null_analyze.c,v 1.6 2001/11/26 22:28:16 ekr Exp $";

#include <ctype.h>
#include "network.h"
#include "proto_mod.h"
#include "debug.h"

typedef struct null_analyzer_ {
     int num;
} null_analyzer;

static int create_null_analyzer PROTO_LIST((void *handle,
  proto_ctx *ctx,tcp_conn *conn,proto_obj **objp,
  struct in_addr *i_addr,u_short i_port,
  struct in_addr *r_addr,u_short r_port, struct timeval *base_time));

static int create_null_analyzer(handle,ctx,conn,objp,i_addr,i_port,r_addr,r_port,
  base_time)
  void *handle;
  proto_ctx *ctx;
  tcp_conn *conn;
  proto_obj **objp;
  struct in_addr *i_addr;
  u_short i_port;
  struct in_addr *r_addr;
  u_short r_port;
  struct timeval *base_time;
  {
    null_analyzer *obj=0;
    static int ctr;
    
    if(!(obj=(null_analyzer *)calloc(sizeof(null_analyzer),1)))
      ERETURN(R_NO_MEMORY);

    obj->num=ctr++;
    
    DBG((0,"Creating analyzer for connection %d\n",obj->num));
    
    *objp=(proto_obj *)obj;
    return(0);
  }

int destroy_null_analyzer(objp)
  proto_obj **objp;
  {
    null_analyzer *obj;
    
    if(!objp || !*objp)
      return(0);

    obj=(null_analyzer *)*objp;
    DBG((0,"Destroying analyzer for connection %d\n",obj->num));
    
    free(*objp);
    *objp=0;

    return(0);
  }

int data_null_analyzer(_obj,seg,direction)
  proto_obj *_obj;
  segment *seg;
  int direction;
  {
#ifdef DEBUG    
    null_analyzer *obj=(null_analyzer *)_obj;
#endif    
    DBG((0,"Processing data for connection %d dir %d\n",obj->num,
      direction));

    for(;seg;seg=seg->next){
      int i;
	
      for(i=0;i<MIN(seg->len,20);i++){
	if(!isascii(seg->data[i]))
	  break;
      }
      if(i<20)
	xdump("NSEGMENT",seg->data,seg->len);
      else{
	printf("NSEGMENT: ");
	fwrite(seg->data,1,seg->len,stdout);
      }
      printf("====\n");
    }
    
    return(0);
  }

int fin_null_analyzer(_obj,p,direction)
  proto_obj *_obj;
  packet *p;
  int direction;
  {
#ifdef DEBUG    
    null_analyzer *obj=(null_analyzer *)_obj;
#endif    
    DBG((0,"Received FIN on connection %d\n",obj->num));
    return(0);
  }




static struct proto_mod_vtbl_ null_vtbl ={
     0,
     0,
     0,
     create_null_analyzer,
     destroy_null_analyzer,
     data_null_analyzer,
     fin_null_analyzer,
};

struct proto_mod_ null_mod = {
     0,
     &null_vtbl
};
