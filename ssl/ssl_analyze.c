/**
   ssl_analyze.c


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

   $Id: ssl_analyze.c,v 1.8 2002/01/21 18:46:13 ekr Exp $


   ekr@rtfm.com  Fri Jan  8 14:07:05 1999
 */


static char *RCSSTRING="$Id: ssl_analyze.c,v 1.8 2002/01/21 18:46:13 ekr Exp $";

#include "network.h"
#include "debug.h"
#include "sslprint.h"
#include "ssl_h.h"
#include "ssl_analyze.h"

/*UINT4 SSL_print_flags=P_HL| P_ND;*/
UINT4 SSL_print_flags = 1 | P_HT | P_HL;

static int parse_ssl_flags PROTO_LIST((char *str));
static int create_ssl_ctx PROTO_LIST((void *handle,proto_ctx **ctxp));
static int create_ssl_analyzer PROTO_LIST((void *handle,
  proto_ctx *ctx,tcp_conn *conn,proto_obj **objp,
  struct in_addr *i_addr,u_short i_port,
  struct in_addr *r_addr,u_short r_port, struct timeval *base_time));
static int destroy_ssl_analyzer PROTO_LIST((proto_obj **objp));
static int read_ssl_record PROTO_LIST((ssl_obj *obj,r_queue *q,segment *seg,
  int offset,segment **lastp,int *offsetp));
static int read_data PROTO_LIST((r_queue *q,segment *seg,int offset,
  segment **lastp,int *offsetp));
static int data_ssl_analyzer PROTO_LIST((proto_obj *_obj,segment *seg,
  int direction));
int close_ssl_analyzer PROTO_LIST((proto_obj *_obj,packet *p,int direction));

static int create_r_queue PROTO_LIST((r_queue **qp));

static int free_r_queue PROTO_LIST((r_queue *q));
static int print_ssl_record PROTO_LIST((ssl_obj *obj,int direction,
  segment *q,UCHAR *data,int len));
char *SSL_keyfile=0;
char *SSL_password=0;

#define NEGATE 0x800000

typedef struct {
     int ch;
     char *name;
     UINT4 flag;
} flag_struct;

flag_struct flags[]={
     {
          't',
          "ts",
          SSL_PRINT_TIMESTAMP,
     },
     {
          'e',
	  "tsa",
	  SSL_PRINT_TIMESTAMP|SSL_PRINT_TIMESTAMP_ABSOLUTE
     },
     {
          'x',
          "x",
          SSL_PRINT_HEXDUMP
     },
     {
          'X',
          "X",
          SSL_PRINT_HEX_ONLY
     },
     {
          'r',
          "rh",
          SSL_PRINT_RECORD_HEADER
     },
     {
          0,
          "ht",
          SSL_PRINT_HANDSHAKE_TYPE
     },
     {
          0,
          "H",
          SSL_PRINT_HIGHLIGHTS
     },
     {
          'A',
          "all",
          SSL_PRINT_ALL_FIELDS
     },
     {
          0,
          "d",
          SSL_PRINT_DECODE
     },
     {
          0,
          "nroff",
          SSL_PRINT_NROFF
     },
     {
          'N',
	  "asn",
	  SSL_PRINT_DECODE_ASN1
     },
     {
          0,
	  "crypto",
	  SSL_PRINT_CRYPTO
     },
     {
          'd',
          "appdata",
          SSL_PRINT_APP_DATA
     },
     {    'q',
          "quiet",
          P_HL | NEGATE
     },
     {0}
};

int parse_ssl_flag(flag)
  int flag;
  {
    flag_struct *fl;
    
    for(fl=flags;fl->name;fl++){
      if(fl->ch==flag){
        if(fl->flag & NEGATE){
          SSL_print_flags &= ~(fl->flag);
        }
        else
          SSL_print_flags |= fl->flag;
        break;
      }
    }

    return(0);
  }
     
static int parse_ssl_flags(str)
  char *str;
  {
    char *x,*y;
    flag_struct *fl;
    int bang;
    
    y=str;
    
    while(x=strtok(y,",")){
      y=0;
      
      if(*x=='!'){
	bang=1;
	x++;
      }
      else
	bang=0;
      for(fl=flags;fl->name;fl++){
        if(!strcmp(x,fl->name)){
          if(!bang) SSL_print_flags |= fl->flag;
          else SSL_print_flags &= ~fl->flag;
          break;
        }
      }
      if(!fl->name){
        fprintf(stderr,"SSL: Bad flag %s\n",x);
      }
    }

    return(0);
  }
            
static int create_ssl_ctx(handle,ctxp)
  void *handle;
  proto_ctx **ctxp;
  {
    ssl_decode_ctx *ctx=0;
    int r,_status;
    
    if(r=ssl_decode_ctx_create(&ctx,SSL_keyfile,SSL_password))
      ABORT(r);

    *ctxp=(proto_ctx *)ctx;
    _status=0;
  abort:
    return(_status);
  }

static int create_ssl_analyzer(handle,ctx,conn,objp,i_addr,i_port,r_addr,r_port,base_time)
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
    int r,_status;
    ssl_obj *obj=0;
    
    if(!(obj=(ssl_obj *)calloc(sizeof(ssl_obj),1)))
      ABORT(R_NO_MEMORY);
    
    obj->ssl_ctx=(ssl_decode_ctx *)ctx;
    obj->conn=conn;
    
    if(r=create_r_queue(&obj->r2i_queue))
      ABORT(r);
    if(r=create_r_queue(&obj->i2r_queue))
      ABORT(r);

    lookuphostname(i_addr,&obj->client_name);
    obj->client_port=i_port;
    lookuphostname(r_addr,&obj->server_name);    
    obj->server_port=r_port;
    
    obj->i_state=SSL_ST_SENT_NOTHING;
    obj->r_state=SSL_ST_HANDSHAKE;
    
    memcpy(&obj->time_start,base_time,sizeof(struct timeval));
    memcpy(&obj->time_last,base_time,sizeof(struct timeval));    

    if(r=ssl_decoder_create(&obj->decoder,obj->ssl_ctx))
      ABORT(r);
    
    *objp=(proto_obj *)obj;

    _status=0;
  abort:
    if(_status){
      destroy_ssl_analyzer((proto_obj **)&obj);
    }
    return(_status);
  }

static int destroy_ssl_analyzer(objp)
  proto_obj **objp;
  {
    ssl_obj *obj;
    
    if(!objp || !*objp)
      return(0);

    obj=(ssl_obj *)*objp;
    DBG((0,"Destroying SSL analyzer"));

    free_r_queue(obj->i2r_queue);
    free_r_queue(obj->r2i_queue);
    ssl_decoder_destroy(&obj->decoder);
    free(obj->client_name);
    free(obj->server_name);    
    free(*objp);
    *objp=0;

    return(0);
  }


static int free_r_queue(q)
  r_queue *q;
  {
    FREE(q->data);
    if(q->q) free_tcp_segment_queue(q->q);
    free(q);
    return(0);
  }

static int create_r_queue(qp)
  r_queue **qp;
  {
    r_queue *q=0;
    int _status;

    if(!(q=(r_queue *)calloc(sizeof(r_queue),1)))
      ABORT(R_NO_MEMORY);

    if(!(q->data=(UCHAR *)malloc(SSL_HEADER_SIZE)))
      ABORT(R_NO_MEMORY);
    q->ptr=q->data;
    q->_allocated=SSL_HEADER_SIZE;
    q->len=0;
    
    q->state=SSL_READ_NONE;
    *qp=q;
    _status=0;
  abort:
    if(_status){
      free_r_queue(q);
    }
    return(_status);
  }

static int read_ssl_record(obj,q,seg,offset,lastp,offsetp)
  ssl_obj *obj;
  r_queue *q;
  segment *seg;
  int offset;
  segment **lastp;
  int *offsetp;
  
  {
    segment *last=seg;
    int rec_len,r,_status;

    switch(q->state){
      case SSL_READ_NONE:
	q->read_left=SSL_HEADER_SIZE;
	if(r=read_data(q,seg,offset,&last,&offset))
	  ABORT(r);
        
        q->state=SSL_READ_HEADER;
        switch(q->data[0]){
          case 20:
          case 21:
          case 22:
          case 23:
            break;
          default:
            printf("Unknown SSL content type %d\n",q->data[0] & 255);
            ABORT(R_INTERNAL);
        }
        
	rec_len=COMBINE(q->data[3],q->data[4]);

	/*Expand the buffer*/
	if(q->_allocated<(rec_len+SSL_HEADER_SIZE)){
	  if(!(q->data=realloc(q->data,rec_len+5)))
	    ABORT(R_NO_MEMORY);
	  q->_allocated=rec_len+SSL_HEADER_SIZE;
	};

	q->ptr=q->data+SSL_HEADER_SIZE;
	q->read_left=rec_len;
	
      case SSL_READ_HEADER:
	if(r=read_data(q,last,offset,&last,&offset))
	  ABORT(r);
	break;
      default:
	ABORT(R_INTERNAL);
    }

    q->state=SSL_READ_NONE;
    /*Whew. If we get here, we've managed to read a whole record*/
    *lastp=last;
    *offsetp=offset;

    _status=0;
  abort:
    return(_status);
  }
	
  
static int read_data(q,seg,offset,lastp,offsetp)
  r_queue *q;	
  segment *seg;
  int offset;
  segment **lastp;
  int *offsetp;
  {
    int tocpy=0,r,_status;
#ifdef DEBUG
    int bread=0;
#endif
    
    DBG((0,"read_data %d bytes requested",q->read_left));
    
    for(;seg;seg=seg->next,offset=0){
      int left;

      left=seg->len-offset;

      tocpy=MIN(q->read_left,left);
      memcpy(q->ptr,seg->data+offset,tocpy);
      q->read_left-=tocpy;
      q->ptr+=tocpy;
      q->len+=tocpy;
#ifdef DEBUG
      bread+=tocpy;
#endif
      if(!q->read_left)
	break;
    };
    
    if(q->read_left){
      if(r=copy_tcp_segment_queue(&q->q,seg))
	ABORT(r);
      return(SSL_NO_DATA);
    }

    if(seg && tocpy==(seg->len - offset)){
      *lastp=0;
      *offsetp=0;
    }
    else{
      *lastp=seg;
      if(seg) *offsetp=tocpy+offset;
    }

    if(q->read_left<0) abort();
    
    DBG((0,"read_data %d bytes read",bread));
    
    _status=0;
  abort:
    return(_status);
  }
      
static int data_ssl_analyzer(_obj,seg,direction)
  proto_obj *_obj;
  segment *seg;
  int direction;
  {
    int _status,r;
    r_queue *q;
    segment *last,*q_next,*assembled;
    ssl_obj *ssl=(ssl_obj *)_obj;
    int offset=0;
    
    q=direction==DIR_R2I?ssl->r2i_queue:ssl->i2r_queue;

    /* Handle SSLv2 backwards compat client hello
       This is sloppy because we'll assume that it's
       all in one TCP segment -- an assumption we make
       nowhere else in the code
     */
    if(direction==DIR_I2R && ssl->i_state==SSL_ST_SENT_NOTHING){
      r=process_v2_hello(ssl,seg);

      if(r==SSL_NO_DATA)
        return(0);
      
      if(r==0)
        return(0);
    }

    if(ssl->i_state==SSL_ST_SENT_NOTHING){
        
        r=process_beginning_plaintext(ssl,seg,direction);
        if(r==SSL_NO_DATA)
          return(0);
      
        if(r==0)
          return(0);
    }
        
    while(!(r=read_ssl_record(ssl,q,seg,offset,&last,&offset))){
      if(ssl->i_state==SSL_ST_SENT_NOTHING)
        ssl->i_state=SSL_ST_HANDSHAKE;
      if(last){
	q_next=last->next;
	last->next=0;
      }
      if(q->q_last){
	q->q_last->next=seg;
	assembled=q->q;
      }
      else
	assembled=seg;

      ssl->direction=direction;
      
      if(r=print_ssl_record(ssl,direction,assembled,q->data,q->len))
	ABORT(r);
      
      /*Now reset things, so we can read another record*/
      if(q){
	if(q->q_last) q->q_last->next=0;
	if(last)
	  last->next=q_next;
	free_tcp_segment_queue(q->q);
	q->q=0;q->q_last=0;q->offset=0;q->len=0;q->ptr=q->data;
	q->state=SSL_READ_NONE;
      }

      seg=last;
    }

    if(r!=SSL_NO_DATA)
      ABORT(r);

    _status=0;
  abort:
    return(_status);
  }

static int print_ssl_header(obj,direction,q,data,len)
  ssl_obj *obj;
  int direction;
  segment *q;
  UCHAR *data;
  int len;
  {
    int ct=0;
    int r;
    segment *s;
    struct timeval dt;

    ssl_print_record_num(obj);

    if(SSL_print_flags & SSL_PRINT_TIMESTAMP){
      for(s=q;s;s=s->next) ct++;

      for(s=q;s;s=s->next){
        ssl_print_timestamp(obj,&s->p->ts);

	if(s->next)
	  printf(", ");
      }
    }

    ssl_print_direction_indicator(obj,direction);
    
    return(0);
  }

static int print_ssl_record(obj,direction,q,data,len)
  ssl_obj *obj;
  int direction;
  segment *q;
  UCHAR *data;
  int len;
  {
    int r;
    
    if(r=print_ssl_header(obj,direction,q,data,len))
      ERETURN(r);
    
    ssl_expand_record(obj,q,direction,data,len);
    if(SSL_print_flags & SSL_PRINT_HEXDUMP){
      Data d;

      INIT_DATA(d,data,len);
      exdump(obj,"Packet data",&d);
      printf("\n\n");
    }
    
    return(0);
  }

int close_ssl_analyzer(_obj,p,dir)
  proto_obj *_obj;
  packet *p;
  int dir;
  {
    ssl_obj *ssl=(ssl_obj *)_obj;
    char *what;
    
    if(p->tcp->th_flags & TH_RST)
      what="RST";
    else
      what="FIN";

    explain(ssl,"%d    ",ssl->conn->conn_number);
    ssl_print_timestamp(ssl,&p->ts);
    ssl_print_direction_indicator(ssl,dir);
    explain(ssl,"  TCP %s",what);
    printf("\n");
    
    return(0);
  }


static struct proto_mod_vtbl_ ssl_vtbl ={
     parse_ssl_flags,
     parse_ssl_flag,
     create_ssl_ctx,
     create_ssl_analyzer,
     destroy_ssl_analyzer,
     data_ssl_analyzer,
     close_ssl_analyzer,
};

struct proto_mod_ ssl_mod = {
     0,
     &ssl_vtbl
};
    

    
    
