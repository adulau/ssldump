/**
   ssl.h


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

   $Id: ssl_h.h,v 1.6 2002/08/17 01:33:17 ekr Exp $


   ekr@rtfm.com  Fri Jan  8 14:09:37 1999
 */


#ifndef _ssl_h
#define _ssl_h

#include "sslciphers.h"

typedef struct ssl_decode_ctx_ ssl_decode_ctx;
typedef struct ssl_decoder_ ssl_decoder;


typedef struct d_queue_ {
     short state;	/*What state we're in*/
#define SSL_READ_NONE	1
#define SSL_READ_HEADER 2		   
     int read_left;	/*How many more bytes to read in this state*/
     int len;		/*The length of the total record, including header*/
     UCHAR *data;	/*The data for this record*/
     UCHAR *ptr;	/*The data ptr*/
     int _allocated;	/*The number of data bytes allocated for this record*/
     segment *q;	/*The segments that match this record*/
     segment *q_last;	/*The last segment*/
     int offset;	/*How far into the first segment this record starts*/
} r_queue;

typedef struct ssl_obj_ {
     tcp_conn *conn;
     int r_state;
     int i_state;
     int version;
     int cipher_suite;

     char *client_name;
     int client_port;
     char *server_name;
     int server_port;

     struct SSL_CipherSuite_ *cs;
     r_queue *i2r_queue;
     r_queue *r2i_queue;
     struct timeval time_start;
     struct timeval time_last;
     ssl_decode_ctx *ssl_ctx;
     ssl_decoder *decoder;

     int process_ciphertext;

     /*Printing bookkeeping*/
     #define REC_PLAINTEXT                1
     #define REC_DECRYPTED_CIPHERTEXT     2
     #define REC_CIPHERTEXT               3
     int record_encryption;

     int direction; /* The direction we're currently working in*/     
     int record_count;
     int indent_depth;
     int indent_name_len;
} ssl_obj;

typedef struct decoder_ {
     int type;
     char *name;
     int (*print) PROTO_LIST((ssl_obj *,int direction,segment *seg,Data *data));
} decoder;

#define SSL_NO_DATA	1
#define SSL_BAD_CONTENT_TYPE 2
#define SSL_BAD_PMS	     3
#define SSL_CANT_DO_CIPHER   4
#define SSL_NO_DECRYPT       5
#define SSL_BAD_MAC          6
#define SSL_BAD_DATA         7

/*SSL defines*/
#define COMBINE(a,b) ((a<<8) | b)
#define SSL_HEADER_SIZE 5

#define SSLV3_VERSION	       0x300
#define TLSV1_VERSION	       0x301

/*State defines*/
#define SSL_ST_SENT_NOTHING             0
#define SSL_ST_HANDSHAKE                1
#define SSL_ST_SENT_CHANGE_CIPHER_SPEC  2

#include "ssldecode.h"


#endif

