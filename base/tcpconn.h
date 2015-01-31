/**
   tcpconn.h


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

   $Id: tcpconn.h,v 1.4 2001/07/20 23:33:15 ekr Exp $


   ekr@rtfm.com  Tue Dec 29 13:00:52 1998
 */


#ifndef _tcpconn_h
#define _tcpconn_h

typedef struct segment_ {
     u_char *data;
     u_int len;
     tcp_seq s_seq;
     packet *p;
     struct segment_ *next;
} segment;

typedef struct stream_data_ {
     tcp_seq seq;
     tcp_seq ack;
     short close;
     segment *oo_queue;
} stream_data;

typedef struct tcp_conn_ {
     int conn_number;
     int state;
#define TCP_STATE_SYN1	1
#define TCP_STATE_SYN2	2
#define TCP_STATE_ACK	3
#define TCP_STATE_ESTABLISHED	4
#define TCP_STATE_FIN1	5
#define TCP_STATE_CLOSED 6
     /*The address which sent the first SYN*/
     struct in_addr i_addr;   
     u_short i_port;

     /*The address which sent the second SYN*/
     struct in_addr r_addr;   
     u_short r_port;

     stream_data i2r;   /*The stream from initiator to responder*/
     stream_data r2i;   /*The stream from responder to initiator*/
     
     struct timeval start_time;
     proto_handler *analyzer;    /*The analyzer to call with new data*/
     struct conn_struct_ *backptr;
} tcp_conn;

int tcp_find_conn PROTO_LIST((tcp_conn **connp,
  int *directionp,
  struct in_addr *src_addr, u_short src_port,
  struct in_addr *dst_addr, u_short dst_port));

int tcp_create_conn PROTO_LIST((tcp_conn **connp,
  struct in_addr *initiator_addr, u_short initiator_port,
  struct in_addr *responder_addr, u_short responder_port));

int tcp_destroy_conn PROTO_LIST((tcp_conn *conn));
int free_tcp_segment_queue PROTO_LIST((segment *seg));
int copy_tcp_segment_queue PROTO_LIST((segment **out,segment *in));
    
#endif

