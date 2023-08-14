/**
   sslprint.c


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

   $Id: sslprint.c,v 1.8 2002/08/17 01:33:17 ekr Exp $


   ekr@rtfm.com  Tue Jan 12 18:06:39 1999
 */

#include <json.h>
#include <ctype.h>
#include <stdarg.h>
#include "network.h"
#include "ssl_h.h"
#include "sslprint.h"
#include "ssl.enums.h"
#include "ssldecode.h"

extern decoder ContentType_decoder[];
extern decoder HandshakeType_decoder[];

#define BYTES_NEEDED(x) \
  (x <= 255) ? 1 : ((x <= (1 << 16)) ? 2 : (x <= (1 << 24) ? 3 : 4))

int process_beginning_plaintext(ssl_obj *ssl, segment *seg, int direction) {
  Data d;
  if(seg->len == 0)
    return (SSL_NO_DATA);

  d.data = seg->data;
  d.len = seg->len;

  /* this looks like SSL data. Ignore it*/
  if(d.data[0] == 0x16)
    return (SSL_BAD_CONTENT_TYPE);

  if(logger)
    logger->vtbl->data(ssl->logger_obj, d.data, d.len, direction);

  P_(P_AD) {
    ssl_print_timestamp(ssl, &seg->p->ts);

    ssl_print_direction_indicator(ssl, direction);

    print_data(ssl, &d);
    LF;
  }

  return (0);
}

int process_v2_hello(ssl_obj *ssl, segment *seg) {
  int r;
  int rec_len;
  int _status;
  UINT4 cs_len;
  UINT4 sid_len;
  UINT4 chall_len;
  UINT4 ver;
  Data d;
  Data chall;
  UCHAR random[32];

  if(seg->len == 0)
    ABORT(SSL_NO_DATA);

  d.data = seg->data;
  d.len = seg->len;

  /* First check the message length. */
  if(d.len < 4)
    ABORT(SSL_BAD_CONTENT_TYPE);
  rec_len = ((d.data[0] & 0x7f) << 8) | (d.data[1]);
  d.data += 2;
  d.len -= 2;

  if(d.len != rec_len) /* Whatever this is it isn't valid SSLv2*/
    ABORT(SSL_BAD_CONTENT_TYPE);

  /* If msg_type==1 then we've got a v2 message (or trash)*/
  if(*d.data++ != 1)
    ABORT(SSL_BAD_CONTENT_TYPE);
  d.len--;

  SSL_DECODE_UINT16_ABORT(ssl, "Version number", P_DC, &d, &ver);
  /* We can't handle real v2 clients*/
  if(ver <= 2) {
    explain(ssl, "Version 2 Client.\n");
    ABORT(SSL_BAD_DATA);
  }

  ssl->cur_json_st = json_object_new_object();
  ssl_print_record_num(ssl);
  ssl_print_timestamp(ssl, &seg->p->ts);
  ssl_print_direction_indicator(ssl, DIR_I2R);
  explain(ssl, " SSLv2 compatible client hello\n");
  json_object_object_add(ssl->cur_json_st, "msg_type",
                         json_object_new_string("Handshake"));
  json_object_object_add(ssl->cur_json_st, "handshake_type",
                         json_object_new_string("ClientHello_v2_compat"));

  INDENT_INCR;

  P_(P_HL) {
    explain(ssl, "Version %d.%d ", (ver >> 8) & 0xff, ver & 0xff);
    LF;
  }
  SSL_DECODE_UINT16_ABORT(ssl, "cipher_spec_length", P_DC, &d, &cs_len);
  SSL_DECODE_UINT16_ABORT(ssl, "session_id_length", P_DC, &d, &sid_len);
  SSL_DECODE_UINT16_ABORT(ssl, "challenge_length", P_DC, &d, &chall_len);

  if(cs_len % 3) {
    fprintf(stderr, "Bad cipher spec length %d\n", cs_len);
    ABORT(SSL_BAD_DATA);
  }
  P_(P_HL) { explain(ssl, "cipher suites\n"); }

  for(; cs_len; cs_len -= 3) {
    UINT4 val;

    SSL_DECODE_UINT24_ABORT(ssl, 0, 0, &d, &val);
    ssl_print_cipher_suite(ssl, ver, P_HL, val);
    P_(P_HL) { explain(ssl, "\n"); }
  }

  if(sid_len != 0) {
    fprintf(stderr, "Session ID field should be zero length\n");
    ABORT(SSL_BAD_DATA);
  }

  if(chall_len < 16 || chall_len > 32) {
    fprintf(stderr, "Invalid challenge length %d\n", chall_len);
    ABORT(SSL_BAD_DATA);
  }

  SSL_DECODE_OPAQUE_ARRAY_ABORT(ssl, 0, chall_len, 0, &d, &chall);
  P_(P_DC) { exdump(ssl, "Challenge", &chall); }

  memset(random, 0, 32);
  memcpy(random + (32 - chall_len), chall.data, chall_len);

  ssl_set_client_random(ssl->decoder, random, 32);
  ssl->i_state = SSL_ST_HANDSHAKE;

  P_(SSL_PRINT_HEXDUMP) {
    Data d;

    INIT_DATA(d, seg->data, seg->len);
    exdump(ssl, "Packet data", &d);
    LF;
    LF;
  }

  INDENT_POP;

  _status = 0;

abort:
  if(ssl->cur_json_st) {
    if(SSL_print_flags & SSL_PRINT_JSON)
      printf("%s\n", json_object_to_json_string(ssl->cur_json_st));
    json_object_put(ssl->cur_json_st);
    ssl->cur_json_st = NULL;
  }

  return (_status);
}

int ssl_decode_switch(ssl_obj *ssl,
                      decoder *dtable,
                      int value,
                      int dir,
                      segment *seg,
                      Data *data) {
  while(dtable && dtable->type != -1 && dtable->name != NULL) {
    if(dtable->type == value) {
      INDENT_INCR;
      explain(ssl, "%s", dtable->name);
      if(dtable->print) {
        INDENT_INCR;
        dtable->print(ssl, dir, seg, data);
        INDENT_POP;
      }
      INDENT_POP;
      return (0);
    }
    dtable++;
  }

  ERETURN(R_NOT_FOUND);
}

int ssl_expand_record(ssl_obj *ssl,
                      segment *q,
                      int direction,
                      UCHAR *data,
                      int len) {
  int r;
  Data d;
  UINT4 ct, vermaj, vermin, length;
  int version;
  char verstr[8];
  char enumstr[20];
  struct json_object *jobj;
  jobj = ssl->cur_json_st;

  d.data = data;
  d.len = len;

  /*This should be mapped to an enum*/
  SSL_DECODE_UINT8(ssl, 0, 0, &d, &ct);
  SSL_DECODE_UINT8(ssl, 0, 0, &d, &vermaj);
  SSL_DECODE_UINT8(ssl, 0, 0, &d, &vermin);
  SSL_DECODE_UINT16(ssl, 0, 0, &d, &length);

  if(d.len != length) {
    explain(ssl, "  Short record: %u bytes available (expecting: %u)\n", length,
            d.len);
    return (0);
  }
  version = ssl->version ? ssl->version : (vermaj * 256 + vermin);

  P_(P_RH) {
    explain(ssl, " V%d.%d(%d)", (version >> 8) & 0xff, version & 0xff, length);
    json_object_object_add(jobj, "record_len", json_object_new_int(length));
    snprintf(verstr, 8, "%d.%d", (version >> 8) & 0xff, version & 0xff);
    json_object_object_add(jobj, "record_ver", json_object_new_string(verstr));
  }

  r = ssl_decode_record(ssl, ssl->decoder, direction, ct, version, &d);
  if(r == SSL_BAD_MAC) {
    explain(ssl, "  bad MAC\n");
    return (0);
  }

  if(r) {
    if(!(SSL_print_flags & SSL_PRINT_JSON))
      if((r = ssl_print_enum(ssl, 0, ContentType_decoder, ct))) {
        printf("  unknown record type: %d\n", ct);
        ERETURN(r);
      }
    if((r = ssl_get_enum_str(ssl, enumstr, ContentType_decoder, ct))) {
      strncpy(enumstr, "Unknown", 20);
    }

    json_object_object_add(jobj, "msg_type", json_object_new_string(enumstr));

    if(!(SSL_print_flags & SSL_PRINT_JSON))
      LF;
  } else {
    // try to save unencrypted data to logger
    // we must save record with type "application_data" (this is unencrypted
    // data)
    if(ct == 23) {
      if(logger) {
        logger->vtbl->data(ssl->logger_obj, d.data, d.len, direction);
      }
      if(ssl->version == TLSV13_VERSION) {
        ct = d.data[--d.len];  // In TLS 1.3 ct is stored in the end for
                               // encrypted records
      }
    }
    if((r = ssl_decode_switch(ssl, ContentType_decoder, ct, direction, q,
                              &d))) {
      if(!(SSL_print_flags & SSL_PRINT_JSON))
        printf("  unknown record type: %d\n", ct);
      ERETURN(r);
    }
  }

  return (0);
}

int ssl_decode_uintX(ssl_obj *ssl,
                     char *name,
                     int size,
                     UINT4 p,
                     Data *data,
                     UINT4 *x) {
  UINT4 v = 0;
  UINT4 _x;

  if(!x)
    x = &_x;

  if(size > data->len) {
    fprintf(stderr, "Short read: %d bytes available (expecting %d)\n",
            data->len, size);
    ERETURN(R_EOD);
  }

  while(size--) {
    v <<= 8;
    v |= *(data->data)++;
    data->len--;
  }

  P_(p) { explain(ssl, "%s = %d\n", name, *x); }
  *x = v;
  return (0);
}

int ssl_decode_opaque_array(ssl_obj *ssl,
                            char *name,
                            int size,
                            UINT4 p,
                            Data *data,
                            Data *x) {
  UINT4 len;
  char n[1000];
  int r;
  Data _x;

  if(!x)
    x = &_x;

  sprintf(n, "%s (length)", name ? name : "<unknown>");
  if(size < 0) {
    size *= -1;
    if((r = ssl_decode_uintX(ssl, n, BYTES_NEEDED(size), P_DC, data, &len)))
      ERETURN(r);
  } else {
    len = size;
  }

  if(len > data->len) {
    fprintf(stderr, "Not enough data. Found %d bytes (expecting %d)\n",
            data->len, size);
    ERETURN(R_EOD);
  }

  x->data = data->data;
  x->len = len;
  data->data += len;
  data->len -= len;

  P_(p) { exdump(ssl, name, x); }

  return (0);
}

int ssl_lookup_enum(ssl_obj *ssl, decoder *dtable, UINT4 val, char **ptr) {
  while(dtable && dtable->type != -1) {
    if(dtable->type == val) {
      *ptr = dtable->name;
      return (0);
    }
    dtable++;
  }

  return (R_NOT_FOUND);
}

int ssl_decode_enum(ssl_obj *ssl,
                    char *name,
                    int size,
                    decoder *dtable,
                    UINT4 p,
                    Data *data,
                    UINT4 *x) {
  int r;
  UINT4 _x;

  if(!x)
    x = &_x;

  if((r = ssl_decode_uintX(ssl, name, size, 0, data, x)))
    ERETURN(r);

  P_(p) {
    if(!(SSL_print_flags & SSL_PRINT_JSON))
      if((r = ssl_print_enum(ssl, name, dtable, *x)))
        ERETURN(r);
  }

  return (0);
}

int ssl_print_enum(ssl_obj *ssl, char *name, decoder *dtable, UINT4 value) {
  if(name)
    explain(ssl, "%s ", name);
  INDENT;

  while(dtable && dtable->type != -1) {
    if(dtable->type == value) {
      INDENT_INCR;
      explain(ssl, "%s", dtable->name);
      INDENT_POP;
      return (0);
    }
    dtable++;
  }
  LF;
  return (R_NOT_FOUND);
}

int ssl_get_enum_str(ssl_obj *ssl, char *outstr, decoder *dtable, UINT4 value) {
  while(dtable && dtable->type != -1) {
    if(dtable->type == value) {
      strncpy(outstr, dtable->name, 20);
      return (0);
    }
    dtable++;
  }
  return (R_NOT_FOUND);
}

int explain(ssl_obj *ssl, char *format, ...) {
  va_list ap;
  if(!(SSL_print_flags & SSL_PRINT_JSON)) {
    va_start(ap, format);

    P_(P_NR) {
      if(ssl->record_encryption == REC_DECRYPTED_CIPHERTEXT)
        printf("\\f(CI");
      else
        printf("\\fC");
    }
    INDENT;

    vprintf(format, ap);
    va_end(ap);
  }
  return (0);
}

int exdump(ssl_obj *ssl, char *name, Data *data) {
  int i;
  if(!(SSL_print_flags & SSL_PRINT_JSON)) {
    if(name) {
      explain(ssl, "%s[%d]=\n", name, data->len);
      INDENT_INCR;
    }
    P_(P_NR) { printf("\\f(CB"); }
    for(i = 0; i < data->len; i++) {
      if(!i)
        INDENT;

      if((data->len > 8) && i && !(i % 16)) {
        LF;
        INDENT;
      }
      printf("%.2x ", data->data[i] & 255);
    }
    P_(P_NR) { printf("\\fR"); }
    if(name)
      INDENT_POP;
    LF;
  }
  return (0);
}

int exstr(ssl_obj *ssl, char *outstr, Data *data) {
  int i;

  char *ptr = outstr;
  for(i = 0; i < data->len; i++) {
    sprintf(ptr, "%.2x", data->data[i] & 255);
    ptr += 2;
    if(i < data->len - 1) {
      sprintf(ptr, ":");
      ++ptr;
    }
  }

  return (0);
}

int combodump(ssl_obj *ssl, char *name, Data *data) {
  UCHAR *ptr = data->data;
  int len = data->len;

  if(name) {
    explain(ssl, "%s[%d]=\n", name, data->len);
    INDENT_INCR;
  }
  while(len) {
    int i;
    int bytes = MIN(len, 16);

    INDENT;

    P_(P_NR) {
      if(ssl->record_encryption == REC_DECRYPTED_CIPHERTEXT)
        printf("\\f[CBI]");
      else
        printf("\\f(CB");
    }

    for(i = 0; i < bytes; i++)
      printf("%.2x ", ptr[i] & 255);
    /* Fill */
    for(i = 0; i < (16 - bytes); i++)
      printf("   ");
    printf("   ");

    P_(P_NR) {
      if(ssl->record_encryption == REC_DECRYPTED_CIPHERTEXT)
        printf("\\f[CI]");
      else
        printf("\\f(C");
    }

    for(i = 0; i < bytes; i++) {
      if(isprint(ptr[i]))
        printf("%c", ptr[i]);
      else
        printf(".");
    }
    LF;

    len -= bytes;
    ptr += bytes;
  }
  P_(P_NR) { printf("\\fR"); }
  if(name)
    INDENT_POP;
  return (0);
}

int print_data(ssl_obj *ssl, Data *d) {
  int i, bit8 = 0;

  LF;
  for(i = 0; i < d->len; i++) {
    if(d->data[i] == 0 ||
       (!isprint(d->data[i]) && !strchr("\r\n\t", d->data[i]))) {
      bit8 = 1;
      break;
    }
  }

  if(bit8) {
    INDENT;
    printf("---------------------------------------------------------------\n");
    P_(P_HO) { exdump(ssl, 0, d); }
    else {
      combodump(ssl, 0, d);
    }
    INDENT;
    printf("---------------------------------------------------------------\n");

  } else {
    int nl = 1;
    INDENT;
    printf("---------------------------------------------------------------\n");
    if(SSL_print_flags & SSL_PRINT_NROFF) {
      if(ssl->process_ciphertext & ssl->direction)
        printf("\\f[CI]");
      else
        printf("\\f(C");
    }

    INDENT;
    for(i = 0; i < d->len; i++) {
      /* Escape leading . */
      if(nl == 1 && (SSL_print_flags & SSL_PRINT_NROFF) && (d->data[i] == '.'))
        printf("\\&");
      nl = 0;

      putchar(d->data[i]);
      if(d->data[i] == '\n') {
        nl = 1;
        INDENT;
      }
    }
    printf("---------------------------------------------------------------\n");
    if(SSL_print_flags & SSL_PRINT_NROFF) {
      printf("\\f(R");
    }
  }

  return (0);
}
int ssl_print_direction_indicator(ssl_obj *ssl, int dir) {
  struct json_object *jobj;
#if 0    
    if(dir==DIR_I2R){
      explain(ssl,"%s(%d) > %s>%d",
        ssl->client_name,ssl->client_port,ssl->server_name,ssl->server_port);
    }
    else{
      explain(ssl,"%s(%d) > %s>%d",
        ssl->client_name,ssl->client_port,ssl->server_name,ssl->server_port);
    }
#else

  jobj = ssl->cur_json_st;

  if(dir == DIR_I2R) {
    explain(ssl, "C>S");
    if(jobj) {
      json_object_object_add(jobj, "src_name",
                             json_object_new_string(ssl->client_name));
      json_object_object_add(jobj, "src_ip",
                             json_object_new_string(ssl->client_ip));
      json_object_object_add(jobj, "src_port",
                             json_object_new_int(ssl->client_port));
      json_object_object_add(jobj, "dst_name",
                             json_object_new_string(ssl->server_name));
      json_object_object_add(jobj, "dst_ip",
                             json_object_new_string(ssl->server_ip));
      json_object_object_add(jobj, "dst_port",
                             json_object_new_int(ssl->server_port));
    }
  } else {
    explain(ssl, "S>C");
    if(jobj) {
      json_object_object_add(jobj, "src_name",
                             json_object_new_string(ssl->server_name));
      json_object_object_add(jobj, "src_ip",
                             json_object_new_string(ssl->server_ip));
      json_object_object_add(jobj, "src_port",
                             json_object_new_int(ssl->server_port));
      json_object_object_add(jobj, "dst_name",
                             json_object_new_string(ssl->client_name));
      json_object_object_add(jobj, "dst_ip",
                             json_object_new_string(ssl->client_ip));
      json_object_object_add(jobj, "dst_port",
                             json_object_new_int(ssl->client_port));
    }
  }
#endif

  return (0);
}

int ssl_print_timestamp(ssl_obj *ssl, struct timeval *ts) {
  struct timeval dt;
  int r;

  char ts_str[40];
  struct json_object *jobj;
  jobj = ssl->cur_json_st;

  if(jobj) {
    snprintf(ts_str, 40, "%lld%c%4.4lld", (long long)ts->tv_sec, '.',
             (long long)ts->tv_usec / 100);
    json_object *j_ts_str = json_object_new_string(ts_str);
    json_object_object_add(jobj, "timestamp", j_ts_str);
  }
  if(SSL_print_flags & SSL_PRINT_TIMESTAMP_ABSOLUTE) {
    if(!(SSL_print_flags & SSL_PRINT_JSON))
      explain(ssl, "%lld%c%4.4lld ", (long long)ts->tv_sec, '.',
              (long long)ts->tv_usec / 100);
  } else {
    if((r = timestamp_diff(ts, &ssl->time_start, &dt)))
      ERETURN(r);
    if(!(SSL_print_flags & SSL_PRINT_JSON))
      explain(ssl, "%lld%c%4.4lld ", (long long)dt.tv_sec, '.',
              (long long)dt.tv_usec / 100);
  }

  if((r = timestamp_diff(ts, &ssl->time_last, &dt))) {
    ERETURN(r);
  }
  if(!(SSL_print_flags & SSL_PRINT_JSON))
    explain(ssl, "(%lld%c%4.4lld)  ", (long long)dt.tv_sec, '.',
            (long long)dt.tv_usec / 100);

  memcpy(&ssl->time_last, ts, sizeof(struct timeval));

  return (0);
}

int ssl_print_record_num(ssl_obj *ssl) {
  struct json_object *jobj;
  jobj = ssl->cur_json_st;

  ssl->record_count++;
  if(!(SSL_print_flags & SSL_PRINT_JSON)) {
    if(SSL_print_flags & SSL_PRINT_NROFF) {
      printf("\\fI%d %d\\fR %s", ssl->conn->conn_number, ssl->record_count,
             ssl->record_count < 10 ? " " : "");
    } else {
      printf("%d %d %s", ssl->conn->conn_number, ssl->record_count,
             ssl->record_count < 10 ? " " : "");
    }
  }
  json_object_object_add(jobj, "connection_number",
                         json_object_new_int(ssl->conn->conn_number));
  json_object_object_add(jobj, "record_count",
                         json_object_new_int(ssl->record_count));

  return (0);
}

int ssl_print_cipher_suite(ssl_obj *ssl, int version, int p, UINT4 val) {
  char *str;
  char *prefix = version <= 0x300 ? "SSL_" : "TLS_";
  int r;

  P_(p) {
    if((r = ssl_lookup_enum(ssl, cipher_suite_decoder, val, &str))) {
      explain(ssl, "Unknown value 0x%x", val);
      return (0);
    }

    /* Now the tricky bit. If the cipher suite begins with TLS_
       and the version is SSLv3 then we replace it with SSL_*/
    if(!strncmp(str, "TLS_", 4)) {
      explain(ssl, "%s%s", prefix, str + 4);
    } else {
      explain(ssl, "%s", str);
    }
  }
  return (0);
}
