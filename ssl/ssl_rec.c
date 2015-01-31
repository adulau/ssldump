/**
   ssl_rec.c


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

   $Id: ssl_rec.c,v 1.3 2000/11/03 06:38:06 ekr Exp $


   ekr@rtfm.com  Wed Aug 18 15:46:57 1999
 */


static char *RCSSTRING="$Id: ssl_rec.c,v 1.3 2000/11/03 06:38:06 ekr Exp $";

#include "network.h"
#include "ssl_h.h"
#include "sslprint.h"
#include "ssl.enums.h"
#ifdef OPENSSL
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#endif
#include "ssldecode.h"
#include "ssl_rec.h"

struct ssl_rec_decoder_ {
     SSL_CipherSuite *cs;
     Data *mac_key;
#ifdef OPENSSL     
     EVP_CIPHER_CTX *evp;
#endif     
     UINT4 seq;
};


static char *digests[]={
     "MD5",
     "SHA1"
};

static char *ciphers[]={
     "DES",
     "DES3",
     "RC4",
     "RC2",
     "IDEA"
};


static int tls_check_mac PROTO_LIST((ssl_rec_decoder *d,int ct,
  int ver,UCHAR *data,UINT4 datalen,UCHAR *mac));
static int fmt_seq PROTO_LIST((UINT4 num,UCHAR *buf));

int ssl_create_rec_decoder(dp,cs,mk,sk,iv)
  ssl_rec_decoder **dp;
  SSL_CipherSuite *cs;
  UCHAR *mk;
  UCHAR *sk;
  UCHAR *iv;
  {
    int r,_status;
    ssl_rec_decoder *dec=0;
#ifdef OPENSSL
    const EVP_CIPHER *ciph=0;

    /* Find the SSLeay cipher */
    if(cs->enc!=ENC_NULL){
      ciph=(EVP_CIPHER *)EVP_get_cipherbyname(ciphers[cs->enc-0x30]);
    }

    if(!(dec=(ssl_rec_decoder *)calloc(sizeof(ssl_rec_decoder),1)))
      ABORT(R_NO_MEMORY);

    dec->cs=cs;
    if(r=r_data_create(&dec->mac_key,mk,cs->dig_len))
      ABORT(r);
    if(!(dec->evp=(EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX))))
      ABORT(R_NO_MEMORY);
    EVP_CIPHER_CTX_init(dec->evp);
    EVP_CipherInit(dec->evp,ciph,sk,iv,0);
#endif
    
    *dp=dec;
    _status=0;
  abort:
    if(_status){
      ssl_destroy_rec_decoder(&dec);
    }
    return(_status);
  }

int ssl_destroy_rec_decoder(dp)
  ssl_rec_decoder **dp;
  {
    ssl_rec_decoder *d;
    
    if(!dp || !*dp)
      return(0);
    d=*dp;

    r_data_destroy(&d->mac_key);
#ifdef OPENSSL    
    if(d->evp){
      EVP_CIPHER_CTX_cleanup(d->evp);
      free(d->evp);
    }
    free(*dp);
#endif    

    *dp=0;
    return(0);
  }
    
int ssl_decode_rec_data(ssl,d,ct,version,in,inl,out,outl)
  ssl_obj *ssl;
  ssl_rec_decoder *d;
  int ct;
  int version;
  UCHAR *in;
  int inl;
  UCHAR *out;
  int *outl;
  {
#ifdef OPENSSL
    int pad;
    int r;
    UCHAR *mac;
    
    CRDUMP("Ciphertext",in,inl);
    /* First decrypt*/
    EVP_Cipher(d->evp,out,in,inl);

    CRDUMP("Plaintext",out,inl);    
    *outl=inl;
    
    /* Now strip off the padding*/
    if(d->cs->block!=1){
      pad=out[inl-1];
      *outl-=(pad+1);
    }

    /* And the MAC */
    *outl-=d->cs->dig_len;
    mac=out+(*outl);
    CRDUMP("Record data",out,*outl);

    /* Now check the MAC */
    if(ssl->version==0x300){
      if(r=ssl3_check_mac(d,ct,version,out,*outl,mac))
        ERETURN(r);
    }
    else{
      if(r=tls_check_mac(d,ct,version,out,*outl,mac))
        ERETURN(r);
    }
    
#endif    
    return(0);
  }
    

#define MSB(a) ((a>>8)&0xff)
#define LSB(a) (a&0xff)
#ifdef OPENSSL

/* This should go to 2^128, but we're never really going to see
   more than 2^64, so we cheat*/
static int fmt_seq(num,buf)
  UINT4 num;
  UCHAR *buf;
  {
    UINT4 netnum;
    
    memset(buf,0,8);
    netnum=htonl(num);
    memcpy(buf+4,&netnum,4);

    return(0);
  }
  
static int tls_check_mac(d,ct,ver,data,datalen,mac)
  ssl_rec_decoder *d;
  int ct;
  int ver;
  UCHAR *data;
  UINT4 datalen;
  UCHAR *mac;
  {
    HMAC_CTX hm;
    const EVP_MD *md;
    UINT4 l;
    UCHAR buf[20];
    
    md=EVP_get_digestbyname(digests[d->cs->dig-0x40]);
    HMAC_Init(&hm,d->mac_key->data,d->mac_key->len,md);

    fmt_seq(d->seq,buf);
    d->seq++;
    HMAC_Update(&hm,buf,8);
    buf[0]=ct;
    HMAC_Update(&hm,buf,1);

    buf[0]=MSB(ver);
    buf[1]=LSB(ver);
    HMAC_Update(&hm,buf,2);

    buf[0]=MSB(datalen);
    buf[1]=LSB(datalen);
    HMAC_Update(&hm,buf,2);

    HMAC_Update(&hm,data,datalen);
    
    HMAC_Final(&hm,buf,&l);
    if(memcmp(mac,buf,l))
      ERETURN(SSL_BAD_MAC);

    HMAC_cleanup(&hm);
    return(0);
  }

int ssl3_check_mac(d,ct,ver,data,datalen,mac)
  ssl_rec_decoder *d;
  int ct;
  int ver;
  UCHAR *data;
  UINT4 datalen;
  UCHAR *mac;
  {
    EVP_MD_CTX mc;
    const EVP_MD *md;
    UINT4 l;
    UCHAR buf[64],dgst[20];
    int pad_ct;

    pad_ct=(d->cs->dig==DIG_SHA)?40:48;
    
    md=EVP_get_digestbyname(digests[d->cs->dig-0x40]);
    EVP_DigestInit(&mc,md);

    EVP_DigestUpdate(&mc,d->mac_key->data,d->mac_key->len);

    memset(buf,0x36,pad_ct);
    EVP_DigestUpdate(&mc,buf,pad_ct);

    fmt_seq(d->seq,buf);
    d->seq++;
    EVP_DigestUpdate(&mc,buf,8);

    buf[0]=ct;
    EVP_DigestUpdate(&mc,buf,1);
    
    buf[0]=MSB(datalen);
    buf[1]=LSB(datalen);
    EVP_DigestUpdate(&mc,buf,2);    

    EVP_DigestUpdate(&mc,data,datalen);

    EVP_DigestFinal(&mc,dgst,&l);
    
    EVP_DigestInit(&mc,md);

    EVP_DigestUpdate(&mc,d->mac_key->data,d->mac_key->len);
    
    memset(buf,0x5c,pad_ct);
    EVP_DigestUpdate(&mc,buf,pad_ct);

    EVP_DigestUpdate(&mc,dgst,l);

    EVP_DigestFinal(&mc,dgst,&l);

    if(memcmp(mac,dgst,l))
      ERETURN(SSL_BAD_MAC);

    return(0);
  }
    
#endif   
