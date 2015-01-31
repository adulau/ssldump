/**
   tcppack.c


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

   $Id: tcppack.c,v 1.11 2002/09/09 21:02:58 ekr Exp $


   ekr@rtfm.com  Tue Dec 29 12:43:39 1998
 */


static char *RCSSTRING="$Id: tcppack.c,v 1.11 2002/09/09 21:02:58 ekr Exp $";

#include "network.h"
#ifndef _WIN32
# include <sys/socket.h>
# include <arpa/inet.h>
# ifndef LINUX
#  include <netinet/tcp_seq.h>
# else
#  define SEQ_LT(x,y) ((int)((x)-(y))<0)
# endif
#else
# include <winsock2.h>
# define SEQ_LT(x,y) ((int)((x)-(y))<0)
#endif
#include <ctype.h>
#include "debug.h"
#include "tcpconn.h"
#include "tcppack.h"


static int process_data_segment PROTO_LIST((tcp_conn *conn,
  proto_mod *handler,packet *p,stream_data *stream,int direction));
static int new_connection PROTO_LIST((proto_mod *handler,proto_ctx *ctx,
  packet *p,tcp_conn **connp));
static int print_tcp_packet PROTO_LIST((packet *p));
int STRIM PROTO_LIST((UINT4 _seq,segment *s));

int process_tcp_packet(handler,ctx,p)
  proto_mod *handler;
  proto_ctx *ctx;
  packet *p;
  {
    int r,_status;
    int direction;
    stream_data *stream;
    tcp_conn *conn;
    
    p->tcp=(struct tcphdr *)p->data;

    print_tcp_packet(p);

    if(r=tcp_find_conn(&conn,&direction,&p->ip->ip_src,
      ntohs(p->tcp->th_sport),&p->ip->ip_dst,ntohs(p->tcp->th_dport))){
      if(r!=R_NOT_FOUND)
	ABORT(r);

      /*Note that we MUST receive the 3-way handshake in the
	proper order. This shouldn't be a problem, though,
        except for simultaneous connects*/
      if((p->tcp->th_flags & (TH_SYN|TH_ACK))!=TH_SYN){
	DBG((0,"TCP: rejecting packet from unknown connection\n"));
	return(0);
      }
      
      DBG((0,"SYN1\n"));
      if(r=new_connection(handler,ctx,p,&conn))
	ABORT(r);
      conn->i2r.seq=ntohl(p->tcp->th_seq)+1;
      return(0);
    }

    stream=direction==DIR_R2I?&conn->r2i:&conn->i2r;
    
    switch(conn->state){
      case TCP_STATE_SYN1:
	if(direction != DIR_R2I)
	  break;
	if((p->tcp->th_flags & (TH_SYN|TH_ACK))!=(TH_SYN|TH_ACK))
 	  break;
	conn->r2i.seq=ntohl(p->tcp->th_seq)+1;
	conn->r2i.ack=ntohl(p->tcp->th_ack)+1;
	conn->state=TCP_STATE_SYN2;
	DBG((0,"SYN2\n"));	
	break;
      case TCP_STATE_SYN2:
        {
          char *sn=0,*dn=0;
	if(direction != DIR_I2R)
	  break;
	DBG((0,"ACK\n"));
	conn->i2r.ack=ntohl(p->tcp->th_ack)+1;
        lookuphostname(&conn->i_addr,&sn);
        lookuphostname(&conn->r_addr,&dn);
        if(NET_print_flags & NET_PRINT_TYPESET)
          printf("\\fC");
        printf("New TCP connection #%d: %s(%d) <-> %s(%d)\n",
          conn->conn_number,
          sn,conn->i_port,
          dn,conn->r_port);
        if(NET_print_flags & NET_PRINT_TYPESET)
          printf("\\fR");
        
	conn->state=TCP_STATE_ESTABLISHED;
        free(sn);
        free(dn);
        }
      case TCP_STATE_ESTABLISHED:
      case TCP_STATE_FIN1:
	{
	  UINT4 length;
	  
	  if(p->tcp->th_flags & TH_SYN)
	    break;
	  length=p->len - (p->tcp->th_off * 4);
	  if(r=process_data_segment(conn,handler,p,stream,direction))
	    ABORT(r);
	}
	break;
      default:
	break;
    }

    if(conn->state==TCP_STATE_CLOSED)
      tcp_destroy_conn(conn);
      
    
    _status=0;
  abort:
    
    return(_status);
  }

static int new_connection(handler,ctx,p,connp)
  proto_mod *handler;
  proto_ctx *ctx;
  packet *p;
  tcp_conn **connp;
  {
    int r,_status;
    tcp_conn *conn=0;

    if(r=tcp_create_conn(&conn,&p->ip->ip_src,ntohs(p->tcp->th_sport),
      &p->ip->ip_dst,ntohs(p->tcp->th_dport)))
      ABORT(r);

    conn->state=TCP_STATE_SYN1;
    memcpy(&conn->start_time,&p->ts,sizeof(struct timeval));
    if(r=create_proto_handler(handler,ctx,&conn->analyzer,conn,&p->ts))
      ABORT(r);
    
    *connp=conn;
    _status=0;
  abort:
    return(_status);
  }

/*#define STRIM(_seq,s) { \
    int l;\
    int off;\
    l=(s)->s_seq - _seq; \
    off=(s)->p->tcp->th_off*4; \
    if(l>((s)->p->len-off)) ERETURN(R_BAD_DATA);\
    (s)->data=(s)->p->data + off  + (l) ; \
    (s)->len=(s)->p->len - off + (l); \
    (s)->s_seq += (l); \
    if((s)->next) { \
      if((s)->s_seq >= (s)->next->s_seq) {\
        l=(s)->next->s_seq - (s)->s_seq; \
	if((s)->len){\
	  (s)->len-=(l+1); \
	  (s)->s_seq-=(l+1);\
	}\
      }\
    }\
  }
*/

static int process_data_segment(conn,handler,p,stream,direction)
  tcp_conn *conn;
  proto_mod *handler;
  packet *p;
  stream_data *stream;
  int direction;
  {
    int r,_status;
    tcp_seq seq,right_edge;
    segment _seg;
    segment *seg,*nseg=0;
    long l;

    l=p->len - p->tcp->th_off * 4;
    
    if(stream->close){
      DBG((0,"Rejecting packet received after FIN"));
      return(0);
    }

    /*The idea here is to pass all available segments
      to the analyzer at once. Since we want to preserve
      the segment packet data, we pass the data as a linked list of
      segments*/
    seq=ntohl(p->tcp->th_seq);

    /*Add ACK processing logic here <TODO>*/
    if(p->tcp->th_flags & TH_ACK){
      long acknum,acked;

	
      acknum=ntohl(p->tcp->th_ack);
      acked=acknum-stream->ack;
      
      if(acked && !l){
        /*
	if(r=timestamp_diff(&p->ts,&conn->start_time,&dt))
	  ERETURN(r);
          	printf("%d%c%4.4d ",dt.tv_sec,'.',dt.tv_usec/100);
	if(direction == DIR_R2I)
	  printf("S>C ");
	else
	  printf("C>S ");

          printf("ACK (%d)\n",acked); */
      }
      
      stream->ack=acknum;
    }
    
    
    DBG((0,"Stream Seq %u ",stream->seq));

    /* Check to see if this packet has been processed already */
    right_edge=seq + (p->len - (p->tcp->th_off)*4);
    if(!(p->tcp->th_flags & (TH_RST)) && SEQ_LT(right_edge,stream->seq))
      return(0);
    
    if(SEQ_LT(stream->seq,seq)){
      /* Out of order segment */
      tcp_seq left_edge;

      for(seg=0;seg;seg=seg?seg->next:stream->oo_queue){
	if(seg->next->s_seq > seq)
	  break;
      }

      if(!(nseg=(segment *)calloc(sizeof(segment),1)))
	ABORT(R_NO_MEMORY);
      if(r=packet_copy(p,&nseg->p))
	ABORT(r);
      nseg->s_seq=seq;
      
      /*Insert this segment into the reassembly queue*/
      if(seg){
	nseg->next=seg->next;
	seg->next=nseg;
      }
      else{
	nseg->next=stream->oo_queue;	
	stream->oo_queue=nseg;
      }

      left_edge=seg?seg->s_seq:stream->seq;
      STRIM(left_edge,nseg);
    }
    else{
      /*First segment -- just thread the unallocated data on the
       list so we can pass to the analyzer*/
      _seg.next=0;
      _seg.p=p;
      _seg.s_seq=seq;

      /*Now split the queue. Assemble as many packets as possible
	and pass them to the analyzer. But process anything with a
        RST in it immediately and ignore any data that might be in it
      */
      if(_seg.p->tcp->th_flags & (TH_RST)){
        stream->close=_seg.p->tcp->th_flags & (TH_RST);
	seg=&_seg;

        conn->state=TCP_STATE_CLOSED;
      }
      else{
        STRIM(stream->seq,&_seg);
        
        if(_seg.p->tcp->th_flags & (TH_FIN)){
          stream->close=_seg.p->tcp->th_flags & (TH_FIN);
	  seg=&_seg;
        }
        else {
          for(seg=&_seg;seg->next;seg=seg->next){
            if(seg->p->tcp->th_flags & (TH_FIN)){   
              stream->close=_seg.p->tcp->th_flags & (TH_FIN);
              break;
            }
            if(seg->len + seg->s_seq != seg->next->s_seq)
              break;
          }
        }
        
        /*Note that this logic is broken because it doesn't
          do the CLOSE_WAIT/FIN_WAIT stuff, but it's probably
          close enough, since this is a higher level protocol analyzer,
          not a TCP analyzer*/
        if(seg->p->tcp->th_flags & (TH_FIN) ){
          if(conn->state == TCP_STATE_ESTABLISHED)
            conn->state=TCP_STATE_FIN1;
          else
	  conn->state=TCP_STATE_CLOSED;
        }
        
        stream->oo_queue=seg->next;
        seg->next=0;
        stream->seq=seg->s_seq + seg->len;

        if(r=conn->analyzer->vtbl->data(conn->analyzer->obj,&_seg,direction))
          ABORT(r);
      }

      if(stream->close){
	if(r=conn->analyzer->vtbl->close(conn->analyzer->obj,p,direction))
	  ABORT(r);
      }
      
      free_tcp_segment_queue(_seg.next);
    }

    _status=0;
  abort:
    return(_status);
  }

static int print_tcp_packet(p)
  packet *p;
  {
    char *src=0,*dst=0;
    
    if(!(NET_print_flags & NET_PRINT_TCP_HDR))
      return(0);

    lookuphostname(&p->ip->ip_src,&src);
    lookuphostname(&p->ip->ip_dst,&dst);
    
    printf("TCP: %s(%d) -> %s(%d) ",
      src,
      ntohs(p->tcp->th_sport),
      dst,
      ntohs(p->tcp->th_dport));

    printf("Seq %u.(%d) ",
      ntohl(p->tcp->th_seq),
      p->len - p->tcp->th_off *4);

    if(p->tcp->th_flags & TH_ACK)
      printf("ACK %u ",ntohl(p->tcp->th_ack));

    if(p->tcp->th_flags & TH_FIN)
      printf("FIN ");
    if(p->tcp->th_flags & TH_SYN)
      printf("SYN ");
    if(p->tcp->th_flags & TH_RST)
      printf("RST ");
    if(p->tcp->th_flags & TH_PUSH)
      printf("PUSH ");
    if(p->tcp->th_flags & TH_URG)
      printf("URG ");

    printf("\n");

    free(src);
    free(dst);
    return(0);
  }

int STRIM(_seq,s)
  UINT4 _seq;
  segment *s;
  {
    int l;
    int off;

    /* Test: this shouldn't damage things at all
    s->p->data-=4; 
    s->p->len+=4;
    s->s_seq-=4;
    */
    
    l=_seq - (s)->s_seq; /* number of bytes to trim
                            from the left of s */ 
    off=(s)->p->tcp->th_off*4; 
    if(l>((s)->p->len-off)) ERETURN(R_BAD_DATA);

    /* Now remove the leading l bytes */
    (s)->data=(s)->p->data + off  + (l) ; 
    (s)->len=(s)->p->len - (off + l); 
    (s)->s_seq += (l);

    /* Now trim to the right if necessary */
    if((s)->next) { 
      if((s)->s_seq >= (s)->next->s_seq) {
        l=(s)->s_seq - (s)->next->s_seq;
        
	if((s)->len){
	  (s)->len-=(l+1); 
	}
      }
    }
    
    return(0);
  }

