/**
   tcpconn.c


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

   $Id: tcpconn.c,v 1.7 2002/08/17 01:33:16 ekr Exp $


   ekr@rtfm.com  Tue Dec 29 15:13:03 1998
 */

static char *RCSSTRING="$Id: tcpconn.c,v 1.7 2002/08/17 01:33:16 ekr Exp $";

#include "network.h"
#include "tcpconn.h"


typedef struct conn_struct_ {
     tcp_conn conn;
     struct conn_struct_ *next;
     struct conn_struct_ *prev;
} conn_struct;

int conn_number=1;

static conn_struct *first_conn=0;

static int zero_conn PROTO_LIST((tcp_conn *conn));

static int zero_conn(conn)
  tcp_conn *conn;
  {
    memset(conn,0,sizeof(tcp_conn));
    return(0);
  }

int tcp_find_conn(connp,directionp,saddr,sport,daddr,dport)
  tcp_conn **connp;
  int *directionp;
  struct in_addr *saddr;
  u_short sport;
  struct in_addr *daddr;
  u_short dport;
  {
    conn_struct *conn;

    for(conn=first_conn;conn;conn=conn->next){

      if(sport == conn->conn.i_port && dport==conn->conn.r_port){
	if(!memcmp(saddr,&conn->conn.i_addr,sizeof(struct in_addr))
	  && !memcmp(daddr,&conn->conn.r_addr,sizeof(struct in_addr)))
	{
	  *directionp=DIR_I2R;
	  *connp=&(conn->conn);
	  return(0);
	}
      }

      if(dport == conn->conn.i_port && sport==conn->conn.r_port){
	if(!memcmp(saddr,&conn->conn.r_addr,sizeof(struct in_addr))
	  && !memcmp(daddr,&conn->conn.i_addr,sizeof(struct in_addr)))
	{
	  *directionp=DIR_R2I;
	  *connp=&(conn->conn);
	  return(0);
	}
      }
    }

    return(R_NOT_FOUND);
  }

int tcp_create_conn(connp,i_addr,i_port,r_addr,r_port)
  tcp_conn **connp;
  struct in_addr *i_addr;
  u_short i_port;
  struct in_addr *r_addr;
  u_short r_port;
  {
    conn_struct *conn=0;

    if(!(conn=(conn_struct *)malloc(sizeof(conn_struct))))
      return(R_NO_MEMORY);
    
    conn->prev=0;

    zero_conn(&conn->conn);
    conn->conn.backptr=conn;
    conn->conn.conn_number=conn_number++;
    
    memcpy(&conn->conn.i_addr,i_addr,sizeof(struct in_addr));
    conn->conn.i_port=i_port;
    memcpy(&conn->conn.r_addr,r_addr,sizeof(struct in_addr));
    conn->conn.r_port=r_port;
    *connp=&(conn->conn);

    /* Insert at the head of the list */
    conn->next=first_conn;
    if(first_conn)
      first_conn->prev=conn;
    first_conn=conn;

    
    return(0);
  }

int tcp_destroy_conn(conn)
  tcp_conn *conn;
  {
    conn_struct *c=conn->backptr;

    /* Detach from the list */
    if(c->next){
      c->next->prev=c->prev;
    }
    if(c->prev){
      c->prev->next=c->next;
    }
    else {
      first_conn=c->next;
    }
    
    destroy_proto_handler(&conn->analyzer);
    free_tcp_segment_queue(conn->i2r.oo_queue);
    free_tcp_segment_queue(conn->r2i.oo_queue);
    zero_conn(conn);

    return(0);
  }
    
int free_tcp_segment_queue(seg)
  segment *seg;
  {
    segment *tmp;

    while(seg){
      tmp=seg->next;
      packet_destroy(seg->p);
      free(seg);
      seg=tmp;
    }

    return(0);
  }

int copy_tcp_segment_queue(out,in)
  segment **out;
  segment *in;
  {
    int r,_status;
    segment *base=0;
    
    for(;in;in=in->next){
      if(!(*out=(segment *)calloc(sizeof(segment),1)))
	ABORT(R_NO_MEMORY);
      if(!base) base=*out;

      if(r=packet_copy(in->p,&(*out)->p))
	ABORT(r);
      out=&(*out)->next;  /* Move the pointer we're assigning to */
    }

    _status=0;
  abort:
    if(_status){
      free_tcp_segment_queue(base);
    }
    return(_status);
  }
