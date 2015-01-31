/**
   ssldecode.c


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

   $Id: ssldecode.c,v 1.9 2002/08/17 01:33:17 ekr Exp $


   ekr@rtfm.com  Thu Apr  1 09:54:53 1999
 */

#include "network.h"
#include "ssl_h.h"
#include "sslprint.h"
#include "ssl.enums.h"
#ifdef OPENSSL
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#endif
#include "ssldecode.h"
#include "ssl_rec.h"
#include "r_assoc.h"
static char *RCSSTRING="$Id: ssldecode.c,v 1.9 2002/08/17 01:33:17 ekr Exp $";

#define PRF(ssl,secret,usage,rnd1,rnd2,out) (ssl->version==SSLV3_VERSION)? \
        ssl3_prf(ssl,secret,usage,rnd1,rnd2,out): \
        tls_prf(ssl,secret,usage,rnd1,rnd2,out)


static char *ssl_password;

extern UINT4 SSL_print_flags;

struct ssl_decode_ctx_ {
#ifdef OPENSSL     
     SSL_CTX *ssl_ctx;
     SSL *ssl;
     r_assoc *session_cache;
#else
     char dummy;       /* Some compilers (Win32) don't like empty
                           structs */
#endif     
};

struct ssl_decoder_ {
     ssl_decode_ctx *ctx;
     Data *session_id;
     SSL_CipherSuite *cs;
     Data *client_random;
     Data *server_random;
     int ephemeral_rsa;
     Data *PMS;
     Data *MS;
     ssl_rec_decoder *c_to_s;
     ssl_rec_decoder *s_to_c;     
     ssl_rec_decoder *c_to_s_n;
     ssl_rec_decoder *s_to_c_n;
};


#ifdef OPENSSL
static int tls_P_hash PROTO_LIST((ssl_obj *ssl,Data *secret,Data *seed,
  const EVP_MD *md,Data *out));
static int tls_prf PROTO_LIST((ssl_obj *ssl,Data *secret,char *usage,
  Data *rnd1,Data *rnd2,Data *out));
static int ssl3_prf PROTO_LIST((ssl_obj *ssl,Data *secret,char *usage,
  Data *rnd1,Data *rnd2,Data *out));
static int ssl3_generate_export_iv PROTO_LIST((ssl_obj *ssl,
  Data *rnd1,Data *rnd2,Data *out));
static int ssl_generate_keying_material PROTO_LIST((ssl_obj *ssl,
  ssl_decoder *d));
#endif

static int ssl_create_session_lookup_key PROTO_LIST((ssl_obj *ssl,
  UCHAR *id,UINT4 idlen,UCHAR **keyp,UINT4 *keyl));
int ssl_save_session PROTO_LIST((ssl_obj *ssl,ssl_decoder *d));
int ssl_restore_session PROTO_LIST((ssl_obj *ssl,ssl_decoder *d));

/*The password code is not thread safe*/
static int password_cb(char *buf,int num,int rwflag,void *userdata)
  {
    if(num<strlen(ssl_password)+1)
      return(0);

    strcpy(buf,ssl_password);
    return(strlen(ssl_password));
  }

int ssl_decode_ctx_create(dp,keyfile,pass)
  ssl_decode_ctx **dp;
  char *keyfile;
  char *pass;
  {
#ifdef OPENSSL    
    ssl_decode_ctx *d=0;
    int r,_status;
    
    SSLeay_add_all_algorithms();
    if(!(d=(ssl_decode_ctx *)malloc(sizeof(ssl_decode_ctx))))
      ABORT(R_NO_MEMORY);
    if(!(d->ssl_ctx=SSL_CTX_new(SSLv23_server_method())))
      ABORT(R_NO_MEMORY);
    if(keyfile){
      if(pass){
        ssl_password=pass;
        SSL_CTX_set_default_passwd_cb(d->ssl_ctx,password_cb);
      }
#if 0      
      if(SSL_CTX_use_certificate_file(d->ssl_ctx,keyfile,SSL_FILETYPE_PEM)!=1){
        fprintf(stderr,"Problem loading certificate file\n");
        ABORT(R_INTERNAL);
      }
#endif      
      if(SSL_CTX_use_PrivateKey_file(d->ssl_ctx,keyfile,SSL_FILETYPE_PEM)!=1){
        fprintf(stderr,"Problem loading private key\n");
        ABORT(R_INTERNAL);
      }
    }
    if(!(d->ssl=SSL_new(d->ssl_ctx)))
      ABORT(R_NO_MEMORY);
    
    if(r_assoc_create(&d->session_cache))
      ABORT(R_NO_MEMORY);

    X509V3_add_standard_extensions();

    *dp=d;
    _status=0;
  abort:
    return(_status);
#else
    return(0);
#endif
  }

int ssl_decoder_create(dp,ctx)
  ssl_decoder **dp;
  ssl_decode_ctx *ctx;
  {
    int _status;
    
    ssl_decoder *d=0;

#ifdef OPENSSL
    if(!(d=(ssl_decoder *)calloc(sizeof(ssl_decoder),1)))
      ABORT(R_NO_MEMORY);
    d->ctx=ctx;
    
    *dp=d;
    _status=0;
  abort:
    if(_status)
      ssl_decoder_destroy(&d);
    return(_status);
#else
    return 0;
#endif
  }

int ssl_decoder_destroy(dp)
  ssl_decoder **dp;
  {
#ifdef OPENSSL    
    ssl_decoder *d;

    if(!dp || !*dp)
      return(0);
    d=*dp;
    r_data_destroy(&d->client_random);
    r_data_destroy(&d->server_random);
    r_data_destroy(&d->session_id);
    r_data_destroy(&d->PMS);
    r_data_destroy(&d->MS);
    ssl_destroy_rec_decoder(&d->c_to_s);
    ssl_destroy_rec_decoder(&d->c_to_s_n);
    ssl_destroy_rec_decoder(&d->s_to_c);
    ssl_destroy_rec_decoder(&d->s_to_c_n);
    free(d);
    *dp=0;
#endif
    return(0);
  }

int ssl_set_client_random(d,msg,len)
  ssl_decoder *d;
  UCHAR *msg;
  int len;
  {
#ifdef OPENSSL    
    int r;
    
    if(r=r_data_create(&d->client_random,msg,len))
      ERETURN(r);
#endif
    return(0);
  }
      
int ssl_set_server_random(d,msg,len)
  ssl_decoder *d;
  UCHAR *msg;
  int len;
  {
#ifdef OPENSSL    
    int r;
    
    if(r=r_data_create(&d->server_random,msg,len))
      ERETURN(r);
#endif    
    return(0);
  }

int ssl_set_client_session_id(d,msg,len)
  ssl_decoder *d;
  UCHAR *msg;
  int len;
  {
#ifdef OPENSSL    
    int r;
    
    if(r=r_data_create(&d->session_id,msg,len))
      ERETURN(r);
#endif
    return(0);
  }

int ssl_process_server_session_id(ssl,d,msg,len)
  ssl_obj *ssl;
  ssl_decoder *d;
  UCHAR *msg;
  int len;
  {
#ifdef OPENSSL    
    int r,_status;
    Data idd;
    int restored=0;
    
    INIT_DATA(idd,msg,len);
    
    /* First check to see if the client tried to restore */
    if(d->session_id){
      /* Now check to see if we restored */
      if(r_data_compare(&idd,d->session_id))
        goto abort;

      /* Now try to look up the session. We may not be able
         to find it if, for instance, the original session
         was initiated with something other than static RSA */
      if(r=ssl_restore_session(ssl,d))
        ABORT(r);

      restored=1;
    }
    
    _status=0;
  abort:
    if(!restored){
      /* Copy over the session ID */
      r_data_zfree(d->session_id);
      r_data_create(&d->session_id,msg,len);
    }
    return(_status);
#else
    return(0);
#endif      
  }
  
int ssl_process_change_cipher_spec(ssl,d,direction)
  ssl_obj *ssl;
  ssl_decoder *d;
  int direction;
  {
#ifdef OPENSSL    
    if(direction==DIR_I2R){
      d->c_to_s=d->c_to_s_n;
      d->c_to_s_n=0;
      if(d->c_to_s) ssl->process_ciphertext |= direction;
    }
    else{
      d->s_to_c=d->s_to_c_n;
      d->s_to_c_n=0;
      if(d->s_to_c) ssl->process_ciphertext |= direction;      
    }

#endif    
    return(0);
  }
int ssl_decode_record(ssl,dec,direction,ct,version,d)
  ssl_obj *ssl;
  ssl_decoder *dec;
  int direction;
  int ct;
  int version;
  Data *d;
  {
    ssl_rec_decoder *rd;
    UCHAR *out;
    int outl;
    int r,_status;
    UINT4 state;

    if(dec)
      rd=(direction==DIR_I2R)?dec->c_to_s:dec->s_to_c;
    else
      rd=0;
    state=(direction==DIR_I2R)?ssl->i_state:ssl->r_state;

    if(!rd){
      if(state & SSL_ST_SENT_CHANGE_CIPHER_SPEC){
        ssl->record_encryption=REC_CIPHERTEXT;
        return(SSL_NO_DECRYPT);
      }
      else {
        ssl->record_encryption=REC_PLAINTEXT;
        return(0);
      }
    }

    ssl->record_encryption=REC_CIPHERTEXT;        
#ifdef OPENSSL    
    if(!(out=(UCHAR *)malloc(d->len)))
      ABORT(R_NO_MEMORY);

    if(r=ssl_decode_rec_data(ssl,rd,ct,version,d->data,d->len,out,&outl)){
      ABORT(r);
    }
    
    memcpy(d->data,out,outl);
    d->len=outl;

    ssl->record_encryption=REC_DECRYPTED_CIPHERTEXT;
    
    _status=0;
  abort:
    FREE(out);
    return(_status);
#else
    return(0);                                                  
#endif    
  }


static int ssl_create_session_lookup_key(ssl,id,idlen,keyp,keyl)
  ssl_obj *ssl;
  UCHAR *id;
  UINT4 idlen;
  UCHAR **keyp;
  UINT4 *keyl;
  {
    UCHAR *key=0;
    UINT4 l;
    int r,_status;

    l=idlen+strlen(ssl->server_name)+idlen+15; /* HOST + PORT + id */
    
    if(!(key=(UCHAR *)malloc(l)))
      ABORT(R_NO_MEMORY);
    *keyp=key;
    
    memcpy(key,id,idlen);
    *keyl=idlen;
    key+=idlen;
    
    sprintf(key,"%s:%d",ssl->server_name,ssl->server_port);
    *keyl+=strlen(key);

    _status=0;
  abort:
    return(_status);
  }
  
/* Look up the session id in the session cache and generate
   the appropriate keying material */
int ssl_restore_session(ssl,d)
  ssl_obj *ssl;
  ssl_decoder *d;
  {
    UCHAR *lookup_key=0;
    void *msv;
    Data *msd;
    int lookup_key_len;
    int r,_status;
#ifdef OPENSSL    
    if(r=ssl_create_session_lookup_key(ssl,
      d->session_id->data,d->session_id->len,&lookup_key,
      &lookup_key_len))
      ABORT(r);
    if(r=r_assoc_fetch(d->ctx->session_cache,lookup_key,lookup_key_len,
      &msv))
      ABORT(r);
    msd=(Data *)msv;
    if(r=r_data_create(&d->MS,msd->data,msd->len))
      ABORT(r);
    CRDUMPD("Restored MS",d->MS);

    switch(ssl->version){
      case SSLV3_VERSION:
	if(r=ssl_generate_keying_material(ssl,d))
          ABORT(r);
	break;
      case TLSV1_VERSION:
	if(r=ssl_generate_keying_material(ssl,d))
	  ABORT(r);
	break;
      default:
	ABORT(SSL_CANT_DO_CIPHER);	
    }
    
    _status=0;
  abort:
    FREE(lookup_key);
    return(_status);
#else
    return(0);
#endif    
  }

/* Look up the session id in the session cache and generate
   the appropriate keying material */
int ssl_save_session(ssl,d)
  ssl_obj *ssl;
  ssl_decoder *d;
  {
#ifdef OPENSSL    
    UCHAR *lookup_key=0;
    void *msv;
    Data *msd=0;
    int lookup_key_len;
    int r,_status;
    
    if(r=ssl_create_session_lookup_key(ssl,d->session_id->data,
      d->session_id->len,&lookup_key,
      &lookup_key_len))
      ABORT(r);
    if(r=r_data_create(&msd,d->MS->data,d->MS->len))
      ABORT(r);
    if(r=r_assoc_insert(d->ctx->session_cache,lookup_key,lookup_key_len,
      (void *)msd,0,(int (*)(void *))r_data_zfree,
      R_ASSOC_NEW | R_ASSOC_REPLACE))
      ABORT(r);
    
    _status=0;
  abort:
    if(_status){
      r_data_zfree(msd);
    }
    FREE(lookup_key);
    return(_status);
#else
    return(0);
#endif
  }

/* This only works with RSA because the other cipher suites
   offer PFS. Yuck. */
int ssl_process_client_key_exchange(ssl,d,msg,len)
  ssl_obj *ssl;
  ssl_decoder *d;
  UCHAR *msg;
  int len;
  {
#ifdef OPENSSL
    int r,_status;
    int i;

    EVP_PKEY *pk;
    
    if(ssl->cs->kex!=KEX_RSA)
      return(-1);

    if(d->ephemeral_rsa)
      return(-1);

    pk=SSL_get_privatekey(d->ctx->ssl);
    if(!pk)
      return(-1);

    if(pk->type!=EVP_PKEY_RSA)
      return(-1);
 
    if(r=r_data_alloc(&d->PMS,BN_num_bytes(pk->pkey.rsa->n)))
      ABORT(r);

    i=RSA_private_decrypt(len,msg,d->PMS->data,
      pk->pkey.rsa,RSA_PKCS1_PADDING);

    if(i!=48)
      ABORT(SSL_BAD_PMS);

    d->PMS->len=48;
      
    CRDUMPD("PMS",d->PMS);

    /* Remove the master secret if it was there
       to force keying material regeneration in
       case we're renegotiating */
    r_data_destroy(&d->MS);
    
    switch(ssl->version){
      case SSLV3_VERSION:
	if(r=ssl_generate_keying_material(ssl,d))
          ABORT(r);
	break;
      case TLSV1_VERSION:
	if(r=ssl_generate_keying_material(ssl,d))
	  ABORT(r);
	break;
      default:
	ABORT(SSL_CANT_DO_CIPHER);	
    }

         
    /* Now store the data in the session cache */
    if(r=ssl_save_session(ssl,d))
      ABORT(r);
      
    _status=0;
  abort:
    return(_status);
#else
    return 0;
#endif    
    
  }

#ifdef OPENSSL
static int tls_P_hash(ssl,secret,seed,md,out)
  ssl_obj *ssl;
  Data *secret;
  Data *seed;
  const EVP_MD *md;
  Data *out;
  {
    UCHAR *ptr=out->data;
    int left=out->len;
    int tocpy;
    UCHAR *A;
    UCHAR _A[20],tmp[20];
    unsigned int A_l,tmp_l;
    HMAC_CTX hm;

    CRDUMPD("P_hash secret",secret);
    CRDUMPD("P_hash seed",seed);
    
    A=seed->data;
    A_l=seed->len;

    while(left){
      HMAC_Init(&hm,secret->data,secret->len,md);
      HMAC_Update(&hm,A,A_l);
      HMAC_Final(&hm,_A,&A_l);
      A=_A;

      HMAC_Init(&hm,secret->data,secret->len,md);
      HMAC_Update(&hm,A,A_l);
      HMAC_Update(&hm,seed->data,seed->len);
      HMAC_Final(&hm,tmp,&tmp_l);

      tocpy=MIN(left,tmp_l);
      memcpy(ptr,tmp,tocpy);
      ptr+=tocpy;
      left-=tocpy;
    }

    HMAC_cleanup(&hm);

    CRDUMPD("P_hash out",out);
    
    return (0);
  }    


static int tls_prf(ssl,secret,usage,rnd1,rnd2,out)
  ssl_obj *ssl;
  Data *secret;
  char *usage;
  Data *rnd1;
  Data *rnd2;
  Data *out;
  {
    int r,_status;
    Data *md5_out=0,*sha_out=0;
    Data *seed;
    UCHAR *ptr;
    Data *S1=0,*S2=0;
    int i,S_l;

    if(r=r_data_alloc(&md5_out,MAX(out->len,16)))
      ABORT(r);
    if(r=r_data_alloc(&sha_out,MAX(out->len,20)))
      ABORT(r);
    if(r=r_data_alloc(&seed,strlen(usage)+rnd1->len+rnd2->len))
      ABORT(r);
    ptr=seed->data;
    memcpy(ptr,usage,strlen(usage)); ptr+=strlen(usage);
    memcpy(ptr,rnd1->data,rnd1->len); ptr+=rnd1->len;
    memcpy(ptr,rnd2->data,rnd2->len); ptr+=rnd2->len;    

    S_l=secret->len/2 + secret->len%2;
    
    if(r=r_data_alloc(&S1,S_l))
      ABORT(r);
    if(r=r_data_alloc(&S2,S_l))
      ABORT(r);
    
    memcpy(S1->data,secret->data,S_l);
    memcpy(S2->data,secret->data + (secret->len - S_l),S_l);
    
    if(r=tls_P_hash
      (ssl,S1,seed,EVP_get_digestbyname("MD5"),md5_out))
      ABORT(r);
    if(r=tls_P_hash(ssl,S2,seed,EVP_get_digestbyname("SHA1"),sha_out))
      ABORT(r);


    for(i=0;i<out->len;i++)
      out->data[i]=md5_out->data[i] ^ sha_out->data[i];

    CRDUMPD("PRF out",out);
    _status=0;
  abort:
    r_data_destroy(&md5_out);
    r_data_destroy(&sha_out);
    r_data_destroy(&seed);
    r_data_destroy(&S1);
    r_data_destroy(&S2);
    return(_status);

  }

static int ssl3_generate_export_iv(ssl,r1,r2,out)
  ssl_obj *ssl;
  Data *r1;
  Data *r2;
  Data *out;
  {
    MD5_CTX md5;
    UCHAR tmp[16];
    
    MD5_Init(&md5);
    MD5_Update(&md5,r1->data,r1->len);
    MD5_Update(&md5,r2->data,r2->len);
    MD5_Final(tmp,&md5);

    memcpy(out->data,tmp,out->len);

    return(0);
  }

static int ssl3_prf(ssl,secret,usage,r1,r2,out)
  ssl_obj *ssl;
  Data *secret;
  char *usage;
  Data *r1;
  Data *r2;
  Data *out;
  {
    MD5_CTX md5;
    SHA_CTX sha;
    Data *rnd1,*rnd2;
    int off;
    int i=0,j;
    UCHAR buf[20];

    rnd1=r1; rnd2=r2;

    CRDUMPD("Secret",secret);
    CRDUMPD("RND1",rnd1);
    CRDUMPD("RND2",rnd2);
    
    MD5_Init(&md5);
    memset(&sha,0,sizeof(sha));
    SHA1_Init(&sha);

    for(off=0;off<out->len;off+=16){
      char outbuf[16];
      int tocpy;
      i++;
      
      /* A, BB, CCC,  ... */
      for(j=0;j<i;j++){
        buf[j]=64+i;
      }
      
      SHA1_Update(&sha,buf,i);
      CRDUMP("BUF",buf,i);
      if(secret) SHA1_Update(&sha,secret->data,secret->len);
      CRDUMPD("secret",secret);

      if(!strcmp(usage,"client write key") || !strcmp(usage,"server write key")){
        SHA1_Update(&sha,rnd2->data,rnd2->len);
        CRDUMPD("rnd2",rnd2);
        SHA1_Update(&sha,rnd1->data,rnd1->len);
        CRDUMPD("rnd1",rnd1);
      }
      else{
        SHA1_Update(&sha,rnd1->data,rnd1->len);
        CRDUMPD("rnd1",rnd1);      
        SHA1_Update(&sha,rnd2->data,rnd2->len);
        CRDUMPD("rnd2",rnd2);
      }
      
      SHA1_Final(buf,&sha);
      CRDUMP("SHA out",buf,20);
      
      SHA1_Init(&sha);
      
      MD5_Update(&md5,secret->data,secret->len);
      MD5_Update(&md5,buf,20);
      MD5_Final(outbuf,&md5);
      tocpy=MIN(out->len-off,16);
      memcpy(out->data+off,outbuf,tocpy);
      CRDUMP("MD5 out",outbuf,16);
      
      MD5_Init(&md5);
    }

    return(0);
  }
  
static int ssl_generate_keying_material(ssl,d)
  ssl_obj *ssl;
  ssl_decoder *d;
  {
    Data *key_block=0;
    UCHAR _iv_c[8],_iv_s[8];
    UCHAR _key_c[16],_key_s[16];
    int needed;
    int r,_status;
    UCHAR *ptr,*c_wk,*s_wk,*c_mk,*s_mk,*c_iv,*s_iv;

    if(!d->MS){
      if(r=r_data_alloc(&d->MS,48))
        ABORT(r);
    
      if(r=PRF(ssl,d->PMS,"master secret",d->client_random,d->server_random,
        d->MS))
        ABORT(r);

      CRDUMPD("MS",d->MS);
    }

    /* Compute the key block. First figure out how much data
         we need*/
    needed=ssl->cs->dig_len*2;
    needed+=ssl->cs->bits / 4;
    if(ssl->cs->block>1) needed+=ssl->cs->block*2;

      
    if(r=r_data_alloc(&key_block,needed))
      ABORT(r);
    if(r=PRF(ssl,d->MS,"key expansion",d->server_random,d->client_random,
      key_block))
      ABORT(r);
    
    ptr=key_block->data;
    c_mk=ptr; ptr+=ssl->cs->dig_len;
    s_mk=ptr; ptr+=ssl->cs->dig_len;

    c_wk=ptr; ptr+=ssl->cs->eff_bits/8;
    s_wk=ptr; ptr+=ssl->cs->eff_bits/8;

    if(ssl->cs->block>1){
      c_iv=ptr; ptr+=ssl->cs->block;
      s_iv=ptr; ptr+=ssl->cs->block;
    }
    
    if(ssl->cs->export){
      Data iv_c,iv_s;
      Data c_iv_d,s_iv_d;
      Data key_c,key_s;
      Data k;

      if(ssl->cs->block>1){
        ATTACH_DATA(iv_c,_iv_c);
        ATTACH_DATA(iv_s,_iv_s);
        
        if(ssl->version==SSLV3_VERSION){
          if(r=ssl3_generate_export_iv(ssl,d->client_random,
            d->server_random,&iv_c))
            ABORT(r);
          if(r=ssl3_generate_export_iv(ssl,d->server_random,
            d->client_random,&iv_s))
            ABORT(r);
        }
        else{
          UCHAR _iv_block[16];
          Data iv_block;
          Data key_null;
          UCHAR _key_null;

          INIT_DATA(key_null,&_key_null,0);

          /* We only have room for 8 bit IVs, but that's
             all we should need. This is a sanity check */
          if(ssl->cs->block>8)
            ABORT(R_INTERNAL);
          
          ATTACH_DATA(iv_block,_iv_block);

          if(r=PRF(ssl,&key_null,"IV block",d->client_random,
            d->server_random,&iv_block))
            ABORT(r);

          memcpy(_iv_c,iv_block.data,8);
          memcpy(_iv_s,iv_block.data+8,8);
        }

        c_iv=_iv_c;
        s_iv=_iv_s;
      }
      
      if(ssl->version==SSLV3_VERSION){
        MD5_CTX md5;

        MD5_Init(&md5);
        MD5_Update(&md5,c_wk,ssl->cs->eff_bits/8);
        MD5_Update(&md5,d->client_random->data,d->client_random->len);
        MD5_Update(&md5,d->server_random->data,d->server_random->len);        
        MD5_Final(_key_c,&md5);
        c_wk=_key_c;

        MD5_Init(&md5);
        MD5_Update(&md5,s_wk,ssl->cs->eff_bits/8);
        MD5_Update(&md5,d->server_random->data,d->server_random->len);
        MD5_Update(&md5,d->client_random->data,d->client_random->len);
        MD5_Final(_key_s,&md5);
        s_wk=_key_s;
      }
      else{
        ATTACH_DATA(key_c,_key_c);
        ATTACH_DATA(key_s,_key_s);
        INIT_DATA(k,c_wk,ssl->cs->eff_bits/8);
        if(r=PRF(ssl,&k,"client write key",d->client_random,d->server_random,
          &key_c))
          ABORT(r);
        c_wk=_key_c;
        INIT_DATA(k,s_wk,ssl->cs->eff_bits/8);
        if(r=PRF(ssl,&k,"server write key",d->client_random,d->server_random,
          &key_s))
          ABORT(r);
        s_wk=_key_s;
      }
    }

    CRDUMP("Client MAC key",c_mk,ssl->cs->dig_len);
    CRDUMP("Server MAC key",s_mk,ssl->cs->dig_len);    
    CRDUMP("Client Write key",c_wk,ssl->cs->bits/8);
    CRDUMP("Server Write key",s_wk,ssl->cs->bits/8);    

    if(ssl->cs->block>1){
      CRDUMP("Client Write IV",c_iv,ssl->cs->block);
      CRDUMP("Server Write IV",s_iv,ssl->cs->block);
    }

    if(r=ssl_create_rec_decoder(&d->c_to_s_n,
      ssl->cs,c_mk,c_wk,c_iv))
      ABORT(r);
    if(r=ssl_create_rec_decoder(&d->s_to_c_n,
      ssl->cs,s_mk,s_wk,s_iv))
      ABORT(r);

    
    _status=0;
  abort:
    if(key_block){
      r_data_zfree(key_block);
      free(key_block);
    }
    return(_status);
  }

#endif
