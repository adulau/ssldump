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
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY SUCH
   DAMAGE.

   $Id: tcpconn.c,v 1.7 2002/08/17 01:33:16 ekr Exp $


   ekr@rtfm.com  Tue Dec 29 15:13:03 1998
 */

#include "network.h"
#include "tcpconn.h"

int conn_number = 1;

conn_struct *first_conn = 0;
char *state_map[] = {
    "UNKNOWN",         "TCP_STATE_SYN1",        "TCP_STATE_SYN2",
    "TCP_STATE_ACK",   "TCP_STATE_ESTABLISHED", "TCP_STATE_FIN1",
    "TCP_STATE_CLOSED"};

extern struct timeval last_packet_seen_time;
extern int conn_ttl;

static int zero_conn PROTO_LIST((tcp_conn * conn));

static int zero_conn(tcp_conn *conn) {
  memset(conn, 0, sizeof(tcp_conn));
  return 0;
}

int tcp_find_conn(tcp_conn **connp,
                  int *directionp,
                  struct sockaddr_storage *saddr,
                  u_short sport,
                  struct sockaddr_storage *daddr,
                  u_short dport) {
  conn_struct *conn;

  for(conn = first_conn; conn; conn = conn->next) {
    if(sport == conn->conn.i_port && dport == conn->conn.r_port) {
      if(!memcmp(saddr, &conn->conn.i_addr, sizeof(struct sockaddr_storage)) &&
         !memcmp(daddr, &conn->conn.r_addr, sizeof(struct sockaddr_storage))) {
        *directionp = DIR_I2R;
        *connp = &(conn->conn);
        return 0;
      }
    }

    if(dport == conn->conn.i_port && sport == conn->conn.r_port) {
      if(!memcmp(saddr, &conn->conn.r_addr, sizeof(struct sockaddr_storage)) &&
         !memcmp(daddr, &conn->conn.i_addr, sizeof(struct sockaddr_storage))) {
        *directionp = DIR_R2I;
        *connp = &(conn->conn);
        return 0;
      }
    }
  }

  return R_NOT_FOUND;
}

int tcp_create_conn(tcp_conn **connp,
                    struct sockaddr_storage *i_addr,
                    u_short i_port,
                    struct sockaddr_storage *r_addr,
                    u_short r_port) {
  conn_struct *conn = 0;

  if(!(conn = (conn_struct *)malloc(sizeof(conn_struct))))
    return R_NO_MEMORY;

  conn->prev = 0;

  zero_conn(&conn->conn);
  conn->conn.backptr = conn;
  conn->conn.conn_number = conn_number++;

  memcpy(&conn->conn.i_addr, i_addr, sizeof(struct sockaddr_storage));
  conn->conn.i_port = i_port;
  memcpy(&conn->conn.r_addr, r_addr, sizeof(struct sockaddr_storage));
  conn->conn.r_port = r_port;
  *connp = &(conn->conn);

  /* Insert at the head of the list */
  conn->next = first_conn;
  if(first_conn)
    first_conn->prev = conn;
  first_conn = conn;

  return 0;
}

int tcp_destroy_conn(tcp_conn *conn) {
  conn_struct *c = conn->backptr;

  /* Detach from the list */
  if(c->next) {
    c->next->prev = c->prev;
  }
  if(c->prev) {
    c->prev->next = c->next;
  } else {
    first_conn = c->next;
  }

  destroy_proto_handler(&conn->analyzer);
  free_tcp_segment_queue(conn->i2r.oo_queue);
  free_tcp_segment_queue(conn->r2i.oo_queue);
  free(conn->i_name);
  free(conn->r_name);
  free(conn->i_num);
  free(conn->r_num);
  zero_conn(conn);
  free(conn->backptr);
  free(conn);

  return 0;
}

int clean_old_conn(void) {
  conn_struct *conn;
  tcp_conn *tcpconn;
  struct timeval dt;
  int i = 0;

  if(!last_packet_seen_time.tv_sec)
    return 0;  // Still processing first block of packets

  conn = first_conn;
  while(conn) {
    tcpconn = &conn->conn;
    conn = conn->next;
    if(timestamp_diff(&last_packet_seen_time, &tcpconn->last_seen_time, &dt))
      continue;
    if(dt.tv_sec > conn_ttl) {
      i++;
      tcp_destroy_conn(tcpconn);
    }
  }
  return i;
}

void list_all_conn(void) {
  conn_struct *conn;
  tcp_conn *tcpconn;
  struct timeval dt;
  long freshness;

  fprintf(stderr,
          "<connection #> <initiator:port> -> <responder:port> <state> "
          "<freshness (in s)>\n");
  conn = first_conn;
  while(conn) {
    tcpconn = &conn->conn;
    conn = conn->next;
    freshness =
        (timestamp_diff(&last_packet_seen_time, &tcpconn->last_seen_time, &dt))
            ? 0
            : dt.tv_sec;
    fprintf(stderr, "Connection #%d %s:%d -> %s:%d %s %ld\n",
            tcpconn->conn_number, tcpconn->i_name, tcpconn->i_port,
            tcpconn->r_name, tcpconn->r_port, state_map[tcpconn->state],
            freshness);
  }
}

int destroy_all_conn(void) {
  int i = 0;
  while(first_conn) {
    i++;
    tcp_destroy_conn(&first_conn->conn);
  }
  return i;
}

int free_tcp_segment_queue(segment *seg) {
  segment *tmp;

  while(seg) {
    tmp = seg->next;
    packet_destroy(seg->p);
    free(seg);
    seg = tmp;
  }

  return 0;
}

int copy_tcp_segment_queue(segment **out, segment *in) {
  int r, _status;
  segment *base = 0;

  for(; in; in = in->next) {
    if(!(*out = (segment *)calloc(1, sizeof(segment))))
      ABORT(R_NO_MEMORY);
    if(!base)
      base = *out;

    if((r = packet_copy(in->p, &(*out)->p)))
      ABORT(r);
    out = &(*out)->next; /* Move the pointer we're assigning to */
  }

  _status = 0;
abort:
  if(_status) {
    free_tcp_segment_queue(base);
  }
  return _status;
}
