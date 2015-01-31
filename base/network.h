/**
   network.h


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

   $Id: network.h,v 1.3 2001/09/14 22:29:14 ekr Exp $


   ekr@rtfm.com  Tue Dec 29 09:53:50 1998
 */


#ifndef _network_h
#define _network_h

#include <stdlib.h>
#include <string.h>

#include <r_common.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <r_time.h>
#include <r_data.h>

typedef struct network_handler_ n_handler;
typedef struct proto_mod_ proto_mod;
typedef struct proto_handler_ proto_handler;
typedef struct packet_ packet;

int network_handler_create PROTO_LIST((proto_mod *mod,
  n_handler **handlerp));
int network_handler_destroy PROTO_LIST((n_handler **handlerp));
int network_process_packet PROTO_LIST((n_handler *handler,
  struct timeval *timestamp,UCHAR *data,int length));
int packet_copy PROTO_LIST((packet *in,packet **out));
int packet_destroy PROTO_LIST((packet *p));
int timestamp_diff PROTO_LIST(( struct timeval *t1,struct timeval *t0,
  struct timeval *diff));
int lookuphostname PROTO_LIST((struct in_addr *addr,char **name));

struct packet_ {
     struct timeval ts;
     UCHAR *base;	/*The base of the packet*/
     int _len;
     UCHAR *data;	/*The data ptr appropriate to this layer*/
     int len;		/*The length of the data segment*/
     
     /*These just save us the effort of doing casts to the data
       segments*/
     struct ip *ip;	/*The IP header*/
     struct tcphdr *tcp; /*The TCP header*/
};

#include "tcpconn.h"
#include "proto_mod.h"

extern UINT4 NET_print_flags;

#define NET_PRINT_TCP_HDR   1
#define NET_PRINT_TYPESET   2
#define NET_PRINT_ACKS	    4
#define NET_PRINT_NO_RESOLVE  8
#endif

