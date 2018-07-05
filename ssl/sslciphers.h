/**
   sslciphers.h


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

   $Id: sslciphers.h,v 1.3 2002/08/17 01:33:17 ekr Exp $


   ekr@rtfm.com  Tue Mar 30 18:11:55 1999
 */


#ifndef _sslciphers_h
#define _sslciphers_h
typedef struct SSL_CipherSuite_ {
     int number;
     int kex;
     int sig;
     int enc;
     int block;
     int bits;
     int eff_bits;
     int dig;
     int dig_len;
     int export;
} SSL_CipherSuite;

#define KEX_RSA		0x10
#define KEX_DH		0x11

#define SIG_RSA		0x20
#define SIG_DSS		0x21
#define SIG_NONE	0x22

#define ENC_DES		0x30
#define ENC_3DES	0x31
#define ENC_RC4		0x32
#define ENC_RC2		0x33
#define ENC_IDEA	0x34
#define ENC_AES128	0x35
#define ENC_AES256	0x36
#define ENC_CAMELLIA128	0x37
#define ENC_CAMELLIA256	0x38
#define ENC_SEED	0x39
#define ENC_NULL	0x3a
#define ENC_AES128_GCM  0x3b
#define ENC_AES256_GCM  0x3c

#define DIG_MD5		0x40
#define DIG_SHA		0x41
#define DIG_SHA224	0x42  /* Not sure why EKR didn't follow RFC for */
#define DIG_SHA256	0x43  /* these values, but whatever, just adding on */
#define DIG_SHA384	0x44
#define DIG_SHA512	0x45

int ssl_find_cipher PROTO_LIST((int num,SSL_CipherSuite **cs));


#endif

