/**
   ssl_analyze.h


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

   $Id: ssl_analyze.h,v 1.3 2000/11/09 18:52:24 ekr Exp $


   ekr@rtfm.com  Tue Jan 12 08:45:44 1999
 */


#ifndef _ssl_analyze_h
#define _ssl_analyze_h

extern proto_mod ssl_mod;

/*The type of data this is*/
#define P_RH  (1<<3)
#define P_HT  (1<<4)
#define P_HL  (1<<5)
#define P_ND  (1<<6)
#define P_DC  (1<<7)
#define P_NR  (1<<8)
#define P_ASN (1<<9)
#define P_CR  (1<<10)
#define P_AD  (1<<11)
#define P_TSA (1<<12)
#define P_QT  (1<<13)
#define P_HO  (1<<14)

#define SSL_PRINT_TIMESTAMP       (1)     /*Timestamp records*/
#define SSL_PRINT_HEXDUMP         (1<<2)  /*Print the whole record in hex*/
#define SSL_PRINT_RECORD_HEADER   P_RH    /*Print the record header*/
#define SSL_PRINT_HANDSHAKE_TYPE  P_HT  /*Print the handshake type*/
#define SSL_PRINT_HIGHLIGHTS      (P_HT | P_HL)
#define SSL_PRINT_ALL_FIELDS      (P_RH | P_HT | P_HL | P_ND)
#define SSL_PRINT_DECODE          (P_DC)  /*Print fields as decoded*/
#define SSL_PRINT_NROFF           (P_NR)
#define SSL_PRINT_DECODE_ASN1	  (P_ASN)
#define SSL_PRINT_CRYPTO	  (P_CR)
#define SSL_PRINT_APP_DATA        (P_AD)
#define SSL_PRINT_TIMESTAMP_ABSOLUTE  (P_TSA)
#define SSL_PRINT_QUIET               (P_QT)
#define SSL_PRINT_HEX_ONLY            (P_HO)
#define SSL_PRINT_ALL      0xfffffff

extern UINT4 SSL_print_flags;
extern char *SSL_keyfile;
extern char *SSL_password;

#endif

