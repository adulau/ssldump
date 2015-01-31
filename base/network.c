/**
   network.c


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

   $Id: network.c,v 1.10 2002/09/09 21:02:58 ekr Exp $


   ekr@rtfm.com  Tue Dec 29 09:52:54 1998
 */


static char *RCSSTRING="$Id: network.c,v 1.10 2002/09/09 21:02:58 ekr Exp $";

#include <sys/types.h>
#include <r_common.h>
#include "network.h"
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include "tcppack.h"

#ifdef STDC_HEADERS
#include <string.h>
#endif

UINT4 NET_print_flags;

struct network_handler_ {
     proto_mod *mod;
     proto_ctx *ctx;
};

int network_handler_create(mod,handlerp)
  proto_mod *mod;
  n_handler **handlerp;
  {
    int r,_status;
    n_handler *handler=0;
    
    if(!(handler=(n_handler *)malloc(sizeof(n_handler))))
      ABORT(R_NO_MEMORY);
    if(mod->vtbl->create_ctx){
      if(r=mod->vtbl->create_ctx(mod->handle,&handler->ctx))
	ABORT(r);
    }
    handler->mod=mod;
    *handlerp=handler;
    _status=0;
  abort:
    if(_status){
      network_handler_destroy(&handler);
    }
    return(_status);
  }

int network_handler_destroy(handlerp)
  n_handler **handlerp;
  {
    if(!handlerp || !*handlerp)
      return(0);

    free(*handlerp);
    *handlerp=0;
    return(0);
  }

int network_process_packet(handler,timestamp,data,length)
  n_handler *handler;
  struct timeval *timestamp;
  UCHAR *data;
  int length;
  {
    int r;
    int hlen;
    packet p;
    u_short off;
    
    /*We can pretty much ignore all the options*/
    memcpy(&p.ts,timestamp,sizeof(struct timeval));
    p.base=data;
    p._len=length;
    p.data=data;
    p.len=length;
    p.ip=(struct ip *)data;

    /*Handle, or rather mishandle, fragmentation*/
    off=ntohs(p.ip->ip_off);
    
    if((off & 0x1fff) ||  /*Later fragment*/
       (off & 0x2000)){	  /*More fragments*/
/*      fprintf(stderr,"Fragmented packet! rejecting\n"); */
      return(0);
    }

    hlen=p.ip->ip_hl * 4;
    p.data += hlen;
    p.len =ntohs(p.ip->ip_len)-hlen;
    
    
    switch(p.ip->ip_p){
      case IPPROTO_TCP:
	if(r=process_tcp_packet(handler->mod,handler->ctx,&p))
	  ERETURN(r);
	break;
    }
    return(0);
  }

int packet_copy(in,out)
  packet *in;
  packet **out;
  {
    int _status;
    
    packet *p=0;
    
    if(!(p=(packet *)calloc(sizeof(packet),1)))
      ABORT(R_NO_MEMORY);

    memcpy(&p->ts,&in->ts,sizeof(struct timeval));
    if(!(p->base=(UCHAR *)malloc(in->_len)))
      ABORT(R_NO_MEMORY);
    memcpy(p->base,in->base,p->_len=in->_len);

    p->data=p->base + (in->data - in->base);
    p->len=in->len;

    p->ip=(struct ip *)(p->base + ((UCHAR *)in->ip - in->base));
    p->tcp=(struct tcphdr *)(p->base + ((UCHAR *)in->tcp - in->base));

    *out=p;
    
    _status=0;
  abort:
    if(_status){
      packet_destroy(p);
    }
    return(_status);
  }

int packet_destroy(p)
  packet *p;
  {
    if(!p)
      return(0);

    FREE(p->base);
    return(0);
  }
    
int timestamp_diff(t1,t0,diff)
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

      

int lookuphostname(addr,namep)
  struct in_addr *addr;
  char **namep;
  {
    struct hostent *ne=0;

    if(!(NET_print_flags & NET_PRINT_NO_RESOLVE)){
      ne=gethostbyaddr((char *)addr,4,AF_INET);
    }

    if(!ne){
      *namep=strdup((char *)inet_ntoa(*addr));
    }
    else{
      *namep=strdup(ne->h_name);
    }

    return(0);
  }
        
    
    
  
