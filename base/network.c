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
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY SUCH
   DAMAGE.

   $Id: network.c,v 1.10 2002/09/09 21:02:58 ekr Exp $


   ekr@rtfm.com  Tue Dec 29 09:52:54 1998
 */

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

int network_handler_create(proto_mod *mod, n_handler **handlerp) {
  int r, _status;
  n_handler *handler = 0;

  if(!(handler = (n_handler *)malloc(sizeof(n_handler))))
    ABORT(R_NO_MEMORY);
  if(mod->vtbl->create_ctx) {
    if((r = mod->vtbl->create_ctx(mod->handle, &handler->ctx)))
      ABORT(r);
  }
  handler->mod = mod;
  *handlerp = handler;
  _status = 0;
abort:
  if(_status) {
    network_handler_destroy(mod, &handler);
  }
  return (_status);
}

int network_handler_destroy(proto_mod *mod, n_handler **handlerp) {
  n_handler *handler = 0;
  if(!handlerp || !*handlerp)
    return (0);

  handler = *handlerp;

  mod->vtbl->destroy_ctx(mod->handle, &handler->ctx);
  free(*handlerp);
  *handlerp = 0;
  return (0);
}

int network_process_packet(n_handler *handler,
                           struct timeval *timestamp,
                           UCHAR *data,
                           int length,
                           int af) {
  int r;
  int hlen;
  packet p;
  u_short off;
  int proto;

  /*We can pretty much ignore all the options*/
  memcpy(&p.ts, timestamp, sizeof(struct timeval));
  p.base = data;
  p._len = length;
  p.data = data;
  p.len = length;
  p.af = af;

  if(p.len < 20) {
    if(!(NET_print_flags & NET_PRINT_JSON))
      printf(
          "Malformed packet, packet too small to contain IP header, skipping "
          "...\n");
    return (0);
  }

  memset(&p.i_addr.so_st, 0x0, sizeof(struct sockaddr_storage));
  memset(&p.r_addr.so_st, 0x0, sizeof(struct sockaddr_storage));

  if(af == AF_INET) {
    p.l3_hdr.ip = (struct ip *)data;
    memcpy(&p.i_addr.so_in.sin_addr, &p.l3_hdr.ip->ip_src,
           sizeof(struct in_addr));
    p.i_addr.so_in.sin_family = AF_INET;
    memcpy(&p.r_addr.so_in.sin_addr, &p.l3_hdr.ip->ip_dst,
           sizeof(struct in_addr));
    p.r_addr.so_in.sin_family = AF_INET;

    /*Handle, or rather mishandle, fragmentation*/
    off = ntohs(p.l3_hdr.ip->ip_off);

    if((off & 0x1fff) || /*Later fragment*/
       (off & 0x2000)) { /*More fragments*/
      /*      fprintf(stderr,"Fragmented packet! rejecting\n"); */
      return (0);
    }

    hlen = p.l3_hdr.ip->ip_hl * 4;
    p.data += hlen;
    p.len = ntohs(p.l3_hdr.ip->ip_len);

    if(p.len > length) {
      if(!(NET_print_flags & NET_PRINT_JSON))
        printf(
            "Malformed packet, size from IP header is larger than size "
            "reported by libpcap, skipping ...\n");
      return (0);
    }

    if(p.len == 0) {
      DBG((0,
           "ip length reported as 0, presumed to be because of 'TCP "
           "segmentation offload' (TSO)\n"));
      p.len = p._len;
    }
    p.len -= hlen;

    proto = p.l3_hdr.ip->ip_p;
  } else {
    p.l3_hdr.ip6 = (struct ip6_hdr *)data;
    memcpy(&p.i_addr.so_in6.sin6_addr, &p.l3_hdr.ip6->ip6_src,
           sizeof(struct in6_addr));
    p.i_addr.so_in6.sin6_family = AF_INET6;
    memcpy(&p.r_addr.so_in6.sin6_addr, &p.l3_hdr.ip6->ip6_dst,
           sizeof(struct in6_addr));
    p.r_addr.so_in6.sin6_family = AF_INET6;
    // Skip packets with header extensions
    if(p.l3_hdr.ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
      return 0;
    }

    hlen = 40;  // Fixed header size with no extension
    p.data += hlen;
    p.len = ntohs(p.l3_hdr.ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
    if(p.len > length) {
      if(!(NET_print_flags & NET_PRINT_JSON))
        printf(
            "Malformed packet, size from IP header is larger than size "
            "reported by libpcap, skipping ...\n");
      return (0);
    }

    if(p.len == 0) {
      DBG((0,
           "ip length reported as 0, presumed to be because of 'TCP "
           "segmentation offload' (TSO)\n"));
      p.len = p._len;
    }

    proto = p.l3_hdr.ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  }

  switch(proto) {
    case IPPROTO_TCP:
      if((r = process_tcp_packet(handler->mod, handler->ctx, &p)))
        ERETURN(r);
      break;
  }

  return (0);
}

int packet_copy(packet *in, packet **out) {
  int _status;

  packet *p = 0;

  if(!(p = (packet *)calloc(1, sizeof(packet))))
    ABORT(R_NO_MEMORY);

  memcpy(&p->ts, &in->ts, sizeof(struct timeval));
  if(!(p->base = (UCHAR *)malloc(in->_len)))
    ABORT(R_NO_MEMORY);
  memcpy(p->base, in->base, p->_len = in->_len);

  p->data = p->base + (in->data - in->base);
  p->len = in->len;

  p->ip = (struct ip *)(p->base + ((UCHAR *)in->ip - in->base));
  p->tcp = (struct tcphdr *)(p->base + ((UCHAR *)in->tcp - in->base));

  *out = p;

  _status = 0;
abort:
  if(_status) {
    packet_destroy(p);
  }
  return (_status);
}

int packet_destroy(packet *p) {
  if(!p)
    return (0);

  FREE(p->base);
  FREE(p);
  return (0);
}

int timestamp_diff(struct timeval *t1,
                   struct timeval *t0,
                   struct timeval *diff) {
  long d;

  if(t0->tv_sec > t1->tv_sec)
    ERETURN(R_BAD_ARGS);

  /*Easy case*/
  if(t0->tv_usec <= t1->tv_usec) {
    diff->tv_sec = t1->tv_sec - t0->tv_sec;
    diff->tv_usec = t1->tv_usec - t0->tv_usec;
    return (0);
  }

  /*Hard case*/
  d = t0->tv_usec - t1->tv_usec;
  if(t1->tv_sec < (t0->tv_sec + 1))
    ERETURN(R_BAD_ARGS);
  diff->tv_sec = t1->tv_sec - (t0->tv_sec + 1);
  diff->tv_usec = 1000000 - d;

  return (0);
}

int lookuphostname(struct sockaddr_storage *so_st, char **namep) {
  int r = 1;
  *namep = calloc(1, NI_MAXHOST);
  void *addr = NULL;

  if(!(NET_print_flags & NET_PRINT_NO_RESOLVE)) {
    r = getnameinfo((struct sockaddr *)so_st, sizeof(struct sockaddr_storage),
                    *namep, NI_MAXHOST, NULL, 0, 0);
  }

  if(r) {
    if(so_st->ss_family == AF_INET) {
      addr = &((struct sockaddr_in *)so_st)->sin_addr;
    } else {
      addr = &((struct sockaddr_in6 *)so_st)->sin6_addr;
    }
    inet_ntop(so_st->ss_family, addr, *namep, INET6_ADDRSTRLEN);
  }

  return (0);
}

int addrtotext(struct sockaddr_storage *so_st, char **namep) {
  *namep = calloc(1, NI_MAXHOST);
  void *addr = NULL;

  if(so_st->ss_family == AF_INET) {
    addr = &((struct sockaddr_in *)so_st)->sin_addr;
  } else {
    addr = &((struct sockaddr_in6 *)so_st)->sin6_addr;
  }
  inet_ntop(so_st->ss_family, addr, *namep, INET6_ADDRSTRLEN);

  return (0);
}
