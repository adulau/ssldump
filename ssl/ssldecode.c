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
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY SUCH
   DAMAGE.

   $Id: ssldecode.c,v 1.9 2002/08/17 01:33:17 ekr Exp $


   ekr@rtfm.com  Thu Apr  1 09:54:53 1999
 */

#include "network.h"
#include "ssl_h.h"
#include "sslprint.h"
#include "ssl.enums.h"
#ifdef OPENSSL
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/x509v3.h>
#endif
#include "ssldecode.h"
#include "ssl_rec.h"
#include "r_assoc.h"

#define PRF(ssl, secret, usage, rnd1, rnd2, out)              \
  (ssl->version == SSLV3_VERSION)                             \
      ? ssl3_prf(ssl, secret, usage, rnd1, rnd2, out)         \
      : ((ssl->version == TLSV12_VERSION)                     \
             ? tls12_prf(ssl, secret, usage, rnd1, rnd2, out) \
             : tls_prf(ssl, secret, usage, rnd1, rnd2, out))

static char *ssl_password;

extern char *digests[];
extern UINT4 SSL_print_flags;

struct ssl_decode_ctx_ {
#ifdef OPENSSL
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  r_assoc *session_cache;
  FILE *ssl_key_log_file;
#else
  char dummy; /* Some compilers (Win32) don't like empty
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
  Data *SHTS;  // Server Handshake traffic secret
  Data *CHTS;  // Client Handshake traffic secret
  Data *STS;   // Server traffic Secret
  Data *CTS;   // Client traffic secret
  Data *handshake_messages;
  Data *session_hash;
  ssl_rec_decoder *c_to_s;
  ssl_rec_decoder *s_to_c;
  ssl_rec_decoder *c_to_s_n;
  ssl_rec_decoder *s_to_c_n;
};

#ifdef OPENSSL
static int tls_P_hash PROTO_LIST(
    (ssl_obj * ssl, Data *secret, Data *seed, const EVP_MD *md, Data *out));
static int tls12_prf PROTO_LIST((ssl_obj * ssl,
                                 Data *secret,
                                 char *usage,
                                 Data *rnd1,
                                 Data *rnd2,
                                 Data *out));
static int tls_prf PROTO_LIST((ssl_obj * ssl,
                               Data *secret,
                               char *usage,
                               Data *rnd1,
                               Data *rnd2,
                               Data *out));
static int ssl3_prf PROTO_LIST((ssl_obj * ssl,
                                Data *secret,
                                char *usage,
                                Data *rnd1,
                                Data *rnd2,
                                Data *out));
static int ssl3_generate_export_iv
    PROTO_LIST((ssl_obj * ssl, Data *rnd1, Data *rnd2, Data *out));
static int ssl_generate_keying_material PROTO_LIST((ssl_obj * ssl,
                                                    ssl_decoder *d));
static int ssl_generate_session_hash PROTO_LIST((ssl_obj * ssl,
                                                 ssl_decoder *d));
static int ssl_read_key_log_file PROTO_LIST((ssl_obj * obj, ssl_decoder *d));
#endif

static int ssl_create_session_lookup_key PROTO_LIST(
    (ssl_obj * ssl, UCHAR *id, UINT4 idlen, UCHAR **keyp, UINT4 *keyl));
int ssl_save_session PROTO_LIST((ssl_obj * ssl, ssl_decoder *d));
int ssl_restore_session PROTO_LIST((ssl_obj * ssl, ssl_decoder *d));

/*The password code is not thread safe*/
static int password_cb(char *buf, int num, int rwflag, void *userdata) {
  if(num < strlen(ssl_password) + 1)
    return (0);

  strcpy(buf, ssl_password);
  return (strlen(ssl_password));
}

int ssl_decode_ctx_create(ssl_decode_ctx **dp,
                          char *keyfile,
                          char *pass,
                          char *keylogfile) {
#ifdef OPENSSL
  ssl_decode_ctx *d = 0;
  int _status;

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  if(!(d = (ssl_decode_ctx *)malloc(sizeof(ssl_decode_ctx))))
    ABORT(R_NO_MEMORY);
  if(!(d->ssl_ctx = SSL_CTX_new(SSLv23_server_method())))
    ABORT(R_NO_MEMORY);
  if(keyfile) {
    if(pass) {
      ssl_password = pass;
      SSL_CTX_set_default_passwd_cb(d->ssl_ctx, password_cb);
    }
#if 0      
      if(SSL_CTX_use_certificate_file(d->ssl_ctx,keyfile,SSL_FILETYPE_PEM)!=1){
        fprintf(stderr,"Problem loading certificate file\n");
        ABORT(R_INTERNAL);
      }
#endif
    if(SSL_CTX_use_PrivateKey_file(d->ssl_ctx, keyfile, SSL_FILETYPE_PEM) !=
       1) {
      fprintf(stderr, "Problem loading private key\n");
      ABORT(R_INTERNAL);
    }
  }
  if(!(d->ssl = SSL_new(d->ssl_ctx)))
    ABORT(R_NO_MEMORY);

  if(r_assoc_create(&d->session_cache))
    ABORT(R_NO_MEMORY);

  if(keylogfile) {
    if(!(d->ssl_key_log_file = fopen(keylogfile, "r"))) {
      fprintf(stderr, "Failed to open ssl key log file");
      ABORT(R_INTERNAL);
    }
  } else {
    d->ssl_key_log_file = NULL;
  }

  X509V3_add_standard_extensions();

  *dp = d;
  _status = 0;
abort:
  return (_status);
#else
  return (0);
#endif
}

int ssl_decode_ctx_destroy(ssl_decode_ctx **dp) {
#ifdef OPENSSL
  ssl_decode_ctx *d = *dp;
  if(!d)
    return 0;
  if(d->ssl_key_log_file) {
    fclose(d->ssl_key_log_file);
  }

  r_assoc *x = d->session_cache;
  r_assoc_destroy(&d->session_cache);

  SSL_CTX_free(d->ssl_ctx);
  SSL_free(d->ssl);
  free(d);
#endif
  return (0);
}

int ssl_decoder_create(ssl_decoder **dp, ssl_decode_ctx *ctx) {
  int _status;

  ssl_decoder *d = 0;

#ifdef OPENSSL
  if(!(d = (ssl_decoder *)calloc(1, sizeof(ssl_decoder))))
    ABORT(R_NO_MEMORY);
  d->ctx = ctx;

  *dp = d;
  _status = 0;
abort:
  if(_status)
    ssl_decoder_destroy(&d);
  return (_status);
#else
  return 0;
#endif
}

int ssl_decoder_destroy(ssl_decoder **dp) {
#ifdef OPENSSL
  ssl_decoder *d;

  if(!dp || !*dp)
    return (0);
  d = *dp;
  r_data_destroy(&d->client_random);
  r_data_destroy(&d->server_random);
  r_data_destroy(&d->session_id);
  r_data_destroy(&d->PMS);
  r_data_destroy(&d->MS);
  r_data_destroy(&d->handshake_messages);
  r_data_destroy(&d->session_hash);
  ssl_destroy_rec_decoder(&d->c_to_s);
  ssl_destroy_rec_decoder(&d->c_to_s_n);
  ssl_destroy_rec_decoder(&d->s_to_c);
  ssl_destroy_rec_decoder(&d->s_to_c_n);
  free(d);
  *dp = 0;
#endif
  return (0);
}

int ssl_set_client_random(ssl_decoder *d, UCHAR *msg, int len) {
#ifdef OPENSSL
  int r;

  r_data_destroy(&d->client_random);
  if((r = r_data_create(&d->client_random, msg, len)))
    ERETURN(r);
#endif
  return (0);
}

int ssl_set_server_random(ssl_decoder *d, UCHAR *msg, int len) {
#ifdef OPENSSL
  int r;

  r_data_destroy(&d->server_random);
  if((r = r_data_create(&d->server_random, msg, len)))
    ERETURN(r);
#endif
  return (0);
}

int ssl_set_client_session_id(ssl_decoder *d, UCHAR *msg, int len) {
#ifdef OPENSSL
  int r;

  if(len > 0) {
    r_data_destroy(&d->session_id);
    if((r = r_data_create(&d->session_id, msg, len)))
      ERETURN(r);
  }
#endif
  return (0);
}

int ssl_process_server_session_id(ssl_obj *ssl,
                                  ssl_decoder *d,
                                  UCHAR *msg,
                                  int len) {
#ifdef OPENSSL
  int r, _status;
  Data idd;
  int restored = 0;

  INIT_DATA(idd, msg, len);

  if(ssl->version == TLSV13_VERSION) {
    // No need to save/restore session in tls1.3 since the only way of
    // decrypting is through log file
  } else {
    /* First check to see if the client tried to restore */
    if(d->session_id) {
      /* Now check to see if we restored */
      if((r = r_data_compare(&idd, d->session_id)))
        ABORT(r);

      /* Now try to look up the session. We may not be able
         to find it if, for instance, the original session
         was initiated with something other than static RSA */
      if((r = ssl_restore_session(ssl, d)))
        ABORT(r);

      restored = 1;
    }
  }

  _status = 0;
abort:
  if(!restored) {
    /* Copy over the session ID */
    r_data_destroy(&d->session_id);
    r_data_create(&d->session_id, msg, len);
  }
  return (_status);
#else
  return (0);
#endif
}

int ssl_process_client_session_id(ssl_obj *ssl,
                                  ssl_decoder *d,
                                  UCHAR *msg,
                                  int len) {
#ifdef OPENSSL
  int _status;

  /* First check if the client set session id */
  // todo: check that session_id in decoder and msg are the same (and if not
  // then take from msg?)
  if(d->session_id) {
    /* Remove the master secret */
    // todo: better save and destroy only when successfully read key log
    r_data_destroy(&d->MS);

    if(d->ctx->ssl_key_log_file && (ssl_read_key_log_file(ssl, d) == 0) &&
       d->MS) {
      // we found master secret for session in keylog
      // try to save session
      _status = ssl_save_session(ssl, d);
    } else {
      // just return error
      _status = -1;
    }
  } else {
    _status = -1;
  }
  return (_status);
#else
  return (0);
#endif
}

int ssl_process_handshake_finished(ssl_obj *ssl, ssl_decoder *dec, Data *data) {
  if(ssl->version == TLSV13_VERSION) {
    if(ssl->direction ==
       DIR_I2R) {  // Change from handshake decoder to data traffic decoder
      dec->c_to_s = dec->c_to_s_n;
      dec->c_to_s_n = 0;
    } else {
      dec->s_to_c = dec->s_to_c_n;
      dec->s_to_c_n = 0;
    }
  }
  return 0;
}

int ssl_process_change_cipher_spec(ssl_obj *ssl,
                                   ssl_decoder *d,
                                   int direction) {
#ifdef OPENSSL
  if(ssl->version != TLSV13_VERSION) {
    if(direction == DIR_I2R) {
      d->c_to_s = d->c_to_s_n;
      d->c_to_s_n = 0;
      if(d->c_to_s)
        ssl->process_ciphertext |= direction;
    } else {
      d->s_to_c = d->s_to_c_n;
      d->s_to_c_n = 0;
      if(d->s_to_c)
        ssl->process_ciphertext |= direction;
    }
  }
#endif
  return (0);
}
int ssl_decode_record(ssl_obj *ssl,
                      ssl_decoder *dec,
                      int direction,
                      int ct,
                      int version,
                      Data *d) {
  ssl_rec_decoder *rd;
  UCHAR *out;
  int outl;
  int r, _status;
  UINT4 state;

  if(dec)
    rd = (direction == DIR_I2R) ? dec->c_to_s : dec->s_to_c;
  else
    rd = 0;
  state = (direction == DIR_I2R) ? ssl->i_state : ssl->r_state;

  if(ssl->version == TLSV13_VERSION &&
     ct != 23) {  // Only type 23 is encrypted in tls1.3
    ssl->record_encryption = REC_PLAINTEXT;
    return 0;
  } else if(!rd) {
    if(state & SSL_ST_SENT_CHANGE_CIPHER_SPEC) {
      ssl->record_encryption = REC_CIPHERTEXT;
      return (SSL_NO_DECRYPT);
    } else {
      ssl->record_encryption = REC_PLAINTEXT;
      return (0);
    }
  }

  ssl->record_encryption = REC_CIPHERTEXT;
#ifdef OPENSSL
  if(!(out = (UCHAR *)malloc(d->len)))
    ABORT(R_NO_MEMORY);

  if(ssl->version == TLSV13_VERSION) {
    r = tls13_decode_rec_data(ssl, rd, ct, version, d->data, d->len, out,
                              &outl);
  } else {
    r = ssl_decode_rec_data(ssl, rd, ct, version, d->data, d->len, out, &outl);
  }
  if(r) {
    ABORT(r);
  }

  memcpy(d->data, out, outl);
  d->len = outl;

  ssl->record_encryption = REC_DECRYPTED_CIPHERTEXT;

  _status = 0;
abort:
  FREE(out);
  return (_status);
#else
  return (0);
#endif
}

int ssl_update_handshake_messages(ssl_obj *ssl, Data *data) {
#ifdef OPENSSL
  Data *hms;
  UCHAR *d;
  int l, r;

  hms = ssl->decoder->handshake_messages;
  d = data->data - 4;
  l = data->len + 4;

  if(hms) {
    if(!(hms->data = realloc(hms->data, l + hms->len)))
      ERETURN(R_NO_MEMORY);

    memcpy(hms->data + hms->len, d, l);
    hms->len += l;
  } else {
    if((r = r_data_create(&hms, d, l)))
      ERETURN(r);
    ssl->decoder->handshake_messages = hms;
  }
#endif
  return (0);
}

static int ssl_create_session_lookup_key(ssl_obj *ssl,
                                         UCHAR *id,
                                         UINT4 idlen,
                                         UCHAR **keyp,
                                         UINT4 *keyl) {
  UCHAR *key = 0;
  UINT4 l;
  int _status;

  l = idlen + strlen(ssl->server_name) + idlen + 15; /* HOST + PORT + id */

  if(!(key = (UCHAR *)malloc(l)))
    ABORT(R_NO_MEMORY);
  *keyp = key;

  memcpy(key, id, idlen);
  *keyl = idlen;
  key += idlen;

  snprintf((char *)key, l, "%s:%d", ssl->server_name, ssl->server_port);
  *keyl += strlen((char *)key);

  _status = 0;
abort:
  return (_status);
}

/* Look up the session id in the session cache and generate
   the appropriate keying material */
int ssl_restore_session(ssl_obj *ssl, ssl_decoder *d) {
  UCHAR *lookup_key = 0;
  void *msv;
  Data *msd;
  int lookup_key_len;
  int r, _status;
#ifdef OPENSSL
  if((r = ssl_create_session_lookup_key(ssl, d->session_id->data,
                                        d->session_id->len, &lookup_key,
                                        (UINT4 *)&lookup_key_len)))
    ABORT(r);
  if((r = r_assoc_fetch(d->ctx->session_cache, (char *)lookup_key,
                        lookup_key_len, &msv)))
    ABORT(r);
  msd = (Data *)msv;
  if((r = r_data_create(&d->MS, msd->data, msd->len)))
    ABORT(r);
  CRDUMPD("Restored MS", d->MS);

  switch(ssl->version) {
    case SSLV3_VERSION:
    case TLSV1_VERSION:
    case TLSV11_VERSION:
    case TLSV12_VERSION:
      if((r = ssl_generate_keying_material(ssl, d)))
        ABORT(r);
      break;
    default:
      ABORT(SSL_CANT_DO_CIPHER);
  }

  _status = 0;
abort:
  FREE(lookup_key);
  return (_status);
#else
  return (0);
#endif
}

/* Look up the session id in the session cache and generate
   the appropriate keying material */
int ssl_save_session(ssl_obj *ssl, ssl_decoder *d) {
#ifdef OPENSSL
  UCHAR *lookup_key = 0;
  Data *msd = 0;
  int lookup_key_len;
  int r, _status;

  if((r = ssl_create_session_lookup_key(ssl, d->session_id->data,
                                        d->session_id->len, &lookup_key,
                                        (UINT4 *)&lookup_key_len)))
    ABORT(r);
  if((r = r_data_create(&msd, d->MS->data, d->MS->len)))
    ABORT(r);
  if((r = r_assoc_insert(d->ctx->session_cache, (char *)lookup_key,
                         lookup_key_len, (void *)msd, 0,
                         (int (*)(void *))r_data_zfree,
                         R_ASSOC_NEW | R_ASSOC_REPLACE)))
    ABORT(r);

  _status = 0;
abort:
  if(_status) {
    r_data_zfree(msd);
  }
  FREE(lookup_key);
  return (_status);
#else
  return (0);
#endif
}

/* This only works with RSA because the other cipher suites
   offer PFS. Yuck. */
int ssl_process_client_key_exchange(ssl_obj *ssl,
                                    ssl_decoder *d,
                                    UCHAR *msg,
                                    int len) {
#ifdef OPENSSL
  int r, _status;
  int i;
  EVP_PKEY *pk;
  const BIGNUM *n;

  /* Remove the master secret if it was there
     to force keying material regeneration in
     case we're renegotiating */
  r_data_destroy(&d->MS);

  if(!d->ctx->ssl_key_log_file || ssl_read_key_log_file(ssl, d) || !d->MS) {
    if(ssl->cs->kex != KEX_RSA)
      return (-1);

    if(d->ephemeral_rsa)
      return (-1);

    pk = SSL_get_privatekey(d->ctx->ssl);
    if(!pk)
      return (-1);

    if(EVP_PKEY_id(pk) != EVP_PKEY_RSA)
      return (-1);

    RSA_get0_key(EVP_PKEY_get0_RSA(pk), &n, NULL, NULL);
    if((r = r_data_alloc(&d->PMS, BN_num_bytes(n))))
      ABORT(r);

    i = RSA_private_decrypt(len, msg, d->PMS->data, EVP_PKEY_get0_RSA(pk),
                            RSA_PKCS1_PADDING);

    if(i != 48)
      ABORT(SSL_BAD_PMS);

    d->PMS->len = 48;

    CRDUMPD("PMS", d->PMS);
  }

  switch(ssl->version) {
    case SSLV3_VERSION:
    case TLSV1_VERSION:
    case TLSV11_VERSION:
    case TLSV12_VERSION:
      if((r = ssl_generate_keying_material(ssl, d)))
        ABORT(r);
      break;
    default:
      ABORT(SSL_CANT_DO_CIPHER);
  }

  /* Now store the data in the session cache */
  if((r = ssl_save_session(ssl, d)))
    ABORT(r);

  _status = 0;
abort:
  return (_status);
#else
  return 0;
#endif
}

#ifdef OPENSSL
static int tls_P_hash(ssl_obj *ssl,
                      Data *secret,
                      Data *seed,
                      const EVP_MD *md,
                      Data *out) {
  UCHAR *ptr = out->data;
  int left = out->len;
  int tocpy;
  UCHAR *A;
  UCHAR _A[128], tmp[128];
  unsigned int A_l, tmp_l;
  HMAC_CTX *hm = HMAC_CTX_new();

  CRDUMPD("P_hash secret", secret);
  CRDUMPD("P_hash seed", seed);

  A = seed->data;
  A_l = seed->len;

  while(left) {
    HMAC_Init_ex(hm, secret->data, secret->len, md, NULL);
    HMAC_Update(hm, A, A_l);
    HMAC_Final(hm, _A, &A_l);
    A = _A;

    HMAC_Init_ex(hm, secret->data, secret->len, md, NULL);
    HMAC_Update(hm, A, A_l);
    HMAC_Update(hm, seed->data, seed->len);
    HMAC_Final(hm, tmp, &tmp_l);

    tocpy = MIN(left, tmp_l);
    memcpy(ptr, tmp, tocpy);
    ptr += tocpy;
    left -= tocpy;
  }

  HMAC_CTX_free(hm);
  CRDUMPD("P_hash out", out);

  return (0);
}

static int tls_prf(ssl_obj *ssl,
                   Data *secret,
                   char *usage,
                   Data *rnd1,
                   Data *rnd2,
                   Data *out) {
  int r, _status;
  Data *md5_out = 0, *sha_out = 0;
  Data *seed;
  UCHAR *ptr;
  Data *S1 = 0, *S2 = 0;
  int i, S_l;

  if((r = r_data_alloc(&md5_out, MAX(out->len, 16))))
    ABORT(r);
  if((r = r_data_alloc(&sha_out, MAX(out->len, 20))))
    ABORT(r);
  if((r = r_data_alloc(&seed, strlen(usage) + rnd1->len + rnd2->len)))
    ABORT(r);
  ptr = seed->data;
  memcpy(ptr, usage, strlen(usage));
  ptr += strlen(usage);
  memcpy(ptr, rnd1->data, rnd1->len);
  ptr += rnd1->len;
  memcpy(ptr, rnd2->data, rnd2->len);
  ptr += rnd2->len;

  S_l = secret->len / 2 + secret->len % 2;

  if((r = r_data_alloc(&S1, S_l)))
    ABORT(r);
  if((r = r_data_alloc(&S2, S_l)))
    ABORT(r);

  memcpy(S1->data, secret->data, S_l);
  memcpy(S2->data, secret->data + (secret->len - S_l), S_l);

  if((r = tls_P_hash(ssl, S1, seed, EVP_get_digestbyname("MD5"), md5_out)))
    ABORT(r);
  if((r = tls_P_hash(ssl, S2, seed, EVP_get_digestbyname("SHA1"), sha_out)))
    ABORT(r);

  for(i = 0; i < out->len; i++)
    out->data[i] = md5_out->data[i] ^ sha_out->data[i];

  CRDUMPD("PRF out", out);
  _status = 0;
abort:
  r_data_destroy(&md5_out);
  r_data_destroy(&sha_out);
  r_data_destroy(&seed);
  r_data_destroy(&S1);
  r_data_destroy(&S2);
  return (_status);
}

static int tls12_prf(ssl_obj *ssl,
                     Data *secret,
                     char *usage,
                     Data *rnd1,
                     Data *rnd2,
                     Data *out)

{
  const EVP_MD *md;
  int r, _status;
  Data *sha_out = 0;
  Data *seed;
  UCHAR *ptr;
  int i, dgi;

  if((r = r_data_alloc(&sha_out, MAX(out->len, 64)))) /* assume max SHA512 */
    ABORT(r);
  if((r = r_data_alloc(&seed, strlen(usage) + rnd1->len + rnd2->len)))
    ABORT(r);
  ptr = seed->data;
  memcpy(ptr, usage, strlen(usage));
  ptr += strlen(usage);
  memcpy(ptr, rnd1->data, rnd1->len);
  ptr += rnd1->len;
  memcpy(ptr, rnd2->data, rnd2->len);
  ptr += rnd2->len;

  /* Earlier versions of openssl didn't have SHA256 of course... */
  dgi = MAX(DIG_SHA256, ssl->cs->dig);
  dgi -= 0x40;
  if((md = EVP_get_digestbyname(digests[dgi])) == NULL) {
    DBG((0, "Cannot get EVP for digest %s, openssl library current?",
         digests[dgi]));
    ERETURN(SSL_BAD_MAC);
  }
  if((r = tls_P_hash(ssl, secret, seed, md, sha_out)))
    ABORT(r);

  for(i = 0; i < out->len; i++)
    out->data[i] = sha_out->data[i];

  CRDUMPD("PRF out", out);
  _status = 0;
abort:
  r_data_destroy(&sha_out);
  r_data_destroy(&seed);
  return (_status);
}

static int ssl3_generate_export_iv(ssl_obj *ssl,
                                   Data *r1,
                                   Data *r2,
                                   Data *out) {
  MD5_CTX md5;
  UCHAR tmp[16];

  MD5_Init(&md5);
  MD5_Update(&md5, r1->data, r1->len);
  MD5_Update(&md5, r2->data, r2->len);
  MD5_Final(tmp, &md5);

  memcpy(out->data, tmp, out->len);

  return (0);
}

static int ssl3_prf(ssl_obj *ssl,
                    Data *secret,
                    char *usage,
                    Data *r1,
                    Data *r2,
                    Data *out) {
  MD5_CTX md5;
  SHA_CTX sha;
  Data *rnd1, *rnd2;
  int off;
  int i = 0, j;
  UCHAR buf[20];

  rnd1 = r1;
  rnd2 = r2;

  CRDUMPD("Secret", secret);
  CRDUMPD("RND1", rnd1);
  CRDUMPD("RND2", rnd2);

  MD5_Init(&md5);
  memset(&sha, 0, sizeof(sha));
  SHA1_Init(&sha);

  for(off = 0; off < out->len; off += 16) {
    char outbuf[16];
    int tocpy;
    i++;

    /* A, BB, CCC,  ... */
    for(j = 0; j < i; j++) {
      buf[j] = 64 + i;
    }

    SHA1_Update(&sha, buf, i);
    CRDUMP("BUF", buf, i);
    if(secret)
      SHA1_Update(&sha, secret->data, secret->len);
    CRDUMPD("secret", secret);

    if(!strcmp(usage, "client write key") ||
       !strcmp(usage, "server write key")) {
      SHA1_Update(&sha, rnd2->data, rnd2->len);
      CRDUMPD("rnd2", rnd2);
      SHA1_Update(&sha, rnd1->data, rnd1->len);
      CRDUMPD("rnd1", rnd1);
    } else {
      SHA1_Update(&sha, rnd1->data, rnd1->len);
      CRDUMPD("rnd1", rnd1);
      SHA1_Update(&sha, rnd2->data, rnd2->len);
      CRDUMPD("rnd2", rnd2);
    }

    SHA1_Final(buf, &sha);
    CRDUMP("SHA out", buf, 20);

    SHA1_Init(&sha);

    MD5_Update(&md5, secret->data, secret->len);
    MD5_Update(&md5, buf, 20);
    MD5_Final((unsigned char *)outbuf, &md5);
    tocpy = MIN(out->len - off, 16);
    memcpy(out->data + off, outbuf, tocpy);
    CRDUMP("MD5 out", (UCHAR *)outbuf, 16);

    MD5_Init(&md5);
  }

  return (0);
}

static int ssl_generate_keying_material(ssl_obj *ssl, ssl_decoder *d) {
  Data *key_block = 0, temp;
  UCHAR _iv_c[8], _iv_s[8];
  UCHAR _key_c[16], _key_s[16];
  int needed;
  int r, _status;
  UCHAR *ptr, *c_wk, *s_wk, *c_mk = NULL, *s_mk = NULL, *c_iv = NULL,
                            *s_iv = NULL;

  if(!d->MS) {
    if((r = r_data_alloc(&d->MS, 48)))
      ABORT(r);

    if(ssl->extensions->extended_master_secret == 2) {
      if((r = ssl_generate_session_hash(ssl, d)))
        ABORT(r);

      temp.len = 0;
      if((r = PRF(ssl, d->PMS, "extended master secret", d->session_hash, &temp,
                  d->MS)))
        ABORT(r);
    } else if((r = PRF(ssl, d->PMS, "master secret", d->client_random,
                       d->server_random, d->MS)))
      ABORT(r);

    CRDUMPD("MS", d->MS);
  }

  /* Compute the key block. First figure out how much data
       we need*/
  /* Ideally find a cleaner way to check for AEAD cipher */
  needed = !IS_AEAD_CIPHER(ssl->cs) ? ssl->cs->dig_len * 2 : 0;
  needed += ssl->cs->bits / 4;
  if(ssl->cs->block > 1)
    needed += ssl->cs->block * 2;

  if((r = r_data_alloc(&key_block, needed)))
    ABORT(r);
  if((r = PRF(ssl, d->MS, "key expansion", d->server_random, d->client_random,
              key_block)))
    ABORT(r);

  ptr = key_block->data;
  /* Ideally find a cleaner way to check for AEAD cipher */
  if(!IS_AEAD_CIPHER(ssl->cs)) {
    c_mk = ptr;
    ptr += ssl->cs->dig_len;
    s_mk = ptr;
    ptr += ssl->cs->dig_len;
  }

  c_wk = ptr;
  ptr += ssl->cs->eff_bits / 8;
  s_wk = ptr;
  ptr += ssl->cs->eff_bits / 8;

  if(ssl->cs->block > 1) {
    c_iv = ptr;
    ptr += ssl->cs->block;
    s_iv = ptr;
    ptr += ssl->cs->block;
  }

  if(ssl->cs->export) {
    Data iv_c, iv_s;
    Data key_c, key_s;
    Data k;

    if(ssl->cs->block > 1) {
      ATTACH_DATA(iv_c, _iv_c);
      ATTACH_DATA(iv_s, _iv_s);

      if(ssl->version == SSLV3_VERSION) {
        if((r = ssl3_generate_export_iv(ssl, d->client_random, d->server_random,
                                        &iv_c)))
          ABORT(r);
        if((r = ssl3_generate_export_iv(ssl, d->server_random, d->client_random,
                                        &iv_s)))
          ABORT(r);
      } else {
        UCHAR _iv_block[16];
        Data iv_block;
        Data key_null;
        UCHAR _key_null;

        INIT_DATA(key_null, &_key_null, 0);

        /* We only have room for 8 bit IVs, but that's
           all we should need. This is a sanity check */
        if(ssl->cs->block > 8)
          ABORT(R_INTERNAL);

        ATTACH_DATA(iv_block, _iv_block);

        if((r = PRF(ssl, &key_null, "IV block", d->client_random,
                    d->server_random, &iv_block)))
          ABORT(r);

        memcpy(_iv_c, iv_block.data, 8);
        memcpy(_iv_s, iv_block.data + 8, 8);
      }

      c_iv = _iv_c;
      s_iv = _iv_s;
    }

    if(ssl->version == SSLV3_VERSION) {
      MD5_CTX md5;

      MD5_Init(&md5);
      MD5_Update(&md5, c_wk, ssl->cs->eff_bits / 8);
      MD5_Update(&md5, d->client_random->data, d->client_random->len);
      MD5_Update(&md5, d->server_random->data, d->server_random->len);
      MD5_Final(_key_c, &md5);
      c_wk = _key_c;

      MD5_Init(&md5);
      MD5_Update(&md5, s_wk, ssl->cs->eff_bits / 8);
      MD5_Update(&md5, d->server_random->data, d->server_random->len);
      MD5_Update(&md5, d->client_random->data, d->client_random->len);
      MD5_Final(_key_s, &md5);
      s_wk = _key_s;
    } else {
      ATTACH_DATA(key_c, _key_c);
      ATTACH_DATA(key_s, _key_s);
      INIT_DATA(k, c_wk, ssl->cs->eff_bits / 8);
      if((r = PRF(ssl, &k, "client write key", d->client_random,
                  d->server_random, &key_c)))
        ABORT(r);
      c_wk = _key_c;
      INIT_DATA(k, s_wk, ssl->cs->eff_bits / 8);
      if((r = PRF(ssl, &k, "server write key", d->client_random,
                  d->server_random, &key_s)))
        ABORT(r);
      s_wk = _key_s;
    }
  }

  if(!IS_AEAD_CIPHER(ssl->cs)) {
    CRDUMP("Client MAC key", c_mk, ssl->cs->dig_len);
    CRDUMP("Server MAC key", s_mk, ssl->cs->dig_len);
  }
  CRDUMP("Client Write key", c_wk, ssl->cs->bits / 8);
  CRDUMP("Server Write key", s_wk, ssl->cs->bits / 8);

  if(ssl->cs->block > 1) {
    CRDUMP("Client Write IV", c_iv, ssl->cs->block);
    CRDUMP("Server Write IV", s_iv, ssl->cs->block);
  }

  if((r = ssl_create_rec_decoder(&d->c_to_s_n, ssl, c_mk, c_wk, c_iv)))
    ABORT(r);
  if((r = ssl_create_rec_decoder(&d->s_to_c_n, ssl, s_mk, s_wk, s_iv)))
    ABORT(r);

  _status = 0;
abort:
  if(key_block) {
    r_data_zfree(key_block);
    free(key_block);
  }
  return (_status);
}

static int hkdf_expand_label(ssl_obj *ssl,
                             ssl_decoder *d,
                             Data *secret,
                             char *label,
                             Data *context,
                             uint16_t length,
                             UCHAR **out) {
  int r;
  size_t outlen = length;
  EVP_PKEY_CTX *pctx;

  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

  Data hkdf_label;
  UCHAR *ptr;

  // Construct HkdfLabel
  hkdf_label.data = ptr = malloc(512);
  *(uint16_t *)ptr = ntohs(length);
  ptr += 2;
  *(uint8_t *)ptr++ = 6 + (label ? strlen(label) : 0);
  memcpy(ptr, "tls13 ", 6);
  ptr += 6;
  if(label) {
    memcpy(ptr, label, strlen(label));
    ptr += strlen(label);
  }
  *(uint8_t *)ptr++ = context ? context->len : 0;
  if(context) {
    memcpy(ptr, context->data, context->len);
    ptr += context->len;
  }
  hkdf_label.len = ptr - hkdf_label.data;
  CRDUMPD("hkdf_label", &hkdf_label);
  // Load parameters
  *out = malloc(length);
  if(EVP_PKEY_derive_init(pctx) <= 0) {
    fprintf(stderr, "EVP_PKEY_derive_init failed\n");
  }
  /* Error */
  if(EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) {
    fprintf(stderr, "EVP_PKEY_CTX_hkdf_mode failed\n");
    goto abort;
  }
  if(EVP_PKEY_CTX_set_hkdf_md(
         pctx, EVP_get_digestbyname(digests[ssl->cs->dig - 0x40])) <= 0) {
    fprintf(stderr, "EVP_PKEY_CTX_set_hkdf_md failed\n");
    goto abort;
  }
  if(EVP_PKEY_CTX_set1_hkdf_key(pctx, secret->data, secret->len) <= 0) {
    fprintf(stderr, "EVP_PKEY_CTX_set_hkdf_md failed\n");
    goto abort;
  }
  if(EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdf_label.data, hkdf_label.len) <= 0) {
    fprintf(stderr, "EVP_PKEY_CTX_add1_hkdf_info failed\n");
    goto abort;
  }
  if(EVP_PKEY_derive(pctx, *out, &outlen) <= 0) {
    fprintf(stderr, "EVP_PKEY_derive failed\n");
    goto abort;
  }

  CRDUMP("out_hkdf", *out, outlen);
  return 0;
abort:
  ERR_print_errors_fp(stderr);
  return r;
}

// Will update the keys for the particular direction
int ssl_tls13_update_keying_material(ssl_obj *ssl,
                                     ssl_decoder *d,
                                     int direction) {
  Data *secret;
  ssl_rec_decoder *decoder;
  UCHAR *newsecret;
  UCHAR *newkey;
  UCHAR *newiv;

  if(direction == DIR_I2R) {
    secret = d->CTS;
    decoder = d->c_to_s;
  } else {
    secret = d->STS;
    decoder = d->s_to_c;
  }
  hkdf_expand_label(ssl, d, secret, "traffic upd", NULL, ssl->cs->dig_len,
                    &newsecret);
  secret->data = newsecret;
  hkdf_expand_label(ssl, d, secret, "key", NULL, ssl->cs->eff_bits / 8,
                    &newkey);
  hkdf_expand_label(ssl, d, secret, "iv", NULL, 12, &newiv);
  tls13_update_rec_key(decoder, newkey, newiv);

  return 0;
}

int ssl_tls13_generate_keying_material(ssl_obj *ssl, ssl_decoder *d) {
  int r, _status;
  Data out;
  UCHAR *s_wk_h, *s_iv_h, *c_wk_h, *c_iv_h, *s_wk, *s_iv, *c_wk, *c_iv;
  if(!(d->ctx->ssl_key_log_file && ssl_read_key_log_file(ssl, d) == 0 &&
       d->SHTS && d->CHTS && d->STS && d->CTS)) {
    ABORT(-1);
  }
  // It is 12 for all ciphers
  if(hkdf_expand_label(ssl, d, d->SHTS, "key", NULL, ssl->cs->eff_bits / 8,
                       &s_wk_h)) {
    fprintf(stderr, "s_wk_h hkdf_expand_label failed\n");
    ABORT(-1);
  }
  if(hkdf_expand_label(ssl, d, d->SHTS, "iv", NULL, 12, &s_iv_h)) {
    fprintf(stderr, "s_iv_h hkdf_expand_label failed\n");
    ABORT(-1);
  }
  if(hkdf_expand_label(ssl, d, d->CHTS, "key", NULL, ssl->cs->eff_bits / 8,
                       &c_wk_h)) {
    fprintf(stderr, "c_wk_h hkdf_expand_label failed\n");
    ABORT(-1);
  }
  if(hkdf_expand_label(ssl, d, d->CHTS, "iv", NULL, 12, &c_iv_h)) {
    fprintf(stderr, "c_iv_h hkdf_expand_label failed\n");
    ABORT(-1);
  }
  if(hkdf_expand_label(ssl, d, d->STS, "key", NULL, ssl->cs->eff_bits / 8,
                       &s_wk)) {
    fprintf(stderr, "s_wk hkdf_expand_label failed\n");
    ABORT(-1);
  }
  if(hkdf_expand_label(ssl, d, d->STS, "iv", NULL, 12, &s_iv)) {
    fprintf(stderr, "s_iv hkdf_expand_label failed\n");
    ABORT(-1);
  }
  if(hkdf_expand_label(ssl, d, d->CTS, "key", NULL, ssl->cs->eff_bits / 8,
                       &c_wk)) {
    fprintf(stderr, "c_wk hkdf_expand_label failed\n");
    ABORT(-1);
  }
  if(hkdf_expand_label(ssl, d, d->CTS, "iv", NULL, 12, &c_iv)) {
    fprintf(stderr, "c_iv hkdf_expand_label failed\n");
    ABORT(-1);
  }
  CRDUMP("Server Handshake Write key", s_wk_h, ssl->cs->eff_bits / 8);
  CRDUMP("Server Handshake IV", s_iv_h, 12);
  CRDUMP("Client Handshake Write key", c_wk_h, ssl->cs->eff_bits / 8);
  CRDUMP("Client Handshake IV", c_iv_h, 12);
  CRDUMP("Server Write key", s_wk, ssl->cs->eff_bits / 8);
  CRDUMP("Server IV", s_iv, 12);
  CRDUMP("Client Write key", c_wk, ssl->cs->eff_bits / 8);
  CRDUMP("Client IV", c_iv, 12);

  if((r = ssl_create_rec_decoder(&d->c_to_s_n, ssl, NULL, c_wk, c_iv)))
    ABORT(r);
  if((r = ssl_create_rec_decoder(&d->s_to_c_n, ssl, NULL, s_wk, s_iv)))
    ABORT(r);
  if((r = ssl_create_rec_decoder(&d->c_to_s, ssl, NULL, c_wk_h, c_iv_h)))
    ABORT(r);
  if((r = ssl_create_rec_decoder(&d->s_to_c, ssl, NULL, s_wk_h, s_iv_h)))
    ABORT(r);
  return 0;
abort:
  return _status;
}

static int ssl_generate_session_hash(ssl_obj *ssl, ssl_decoder *d) {
  int r, _status, dgi;
  unsigned int len;
  const EVP_MD *md;
  EVP_MD_CTX *dgictx = EVP_MD_CTX_create();

  if((r = r_data_alloc(&d->session_hash, EVP_MAX_MD_SIZE)))
    ABORT(r);

  switch(ssl->version) {
    case TLSV12_VERSION:
      dgi = MAX(DIG_SHA256, ssl->cs->dig) - 0x40;
      if((md = EVP_get_digestbyname(digests[dgi])) == NULL) {
        DBG((0, "Cannot get EVP for digest %s, openssl library current?",
             digests[dgi]));
        ERETURN(SSL_BAD_MAC);
      }

      EVP_DigestInit(dgictx, md);
      EVP_DigestUpdate(dgictx, d->handshake_messages->data,
                       d->handshake_messages->len);
      EVP_DigestFinal(dgictx, d->session_hash->data,
                      (unsigned int *)&d->session_hash->len);

      break;
    case SSLV3_VERSION:
    case TLSV1_VERSION:
    case TLSV11_VERSION:
      EVP_DigestInit(dgictx, EVP_get_digestbyname("MD5"));
      EVP_DigestUpdate(dgictx, d->handshake_messages->data,
                       d->handshake_messages->len);
      EVP_DigestFinal_ex(dgictx, d->session_hash->data,
                         (unsigned int *)&d->session_hash->len);

      EVP_DigestInit(dgictx, EVP_get_digestbyname("SHA1"));
      EVP_DigestUpdate(dgictx, d->handshake_messages->data,
                       d->handshake_messages->len);
      EVP_DigestFinal(dgictx, d->session_hash->data + d->session_hash->len,
                      &len);

      d->session_hash->len += len;
      break;
    default:
      ABORT(SSL_CANT_DO_CIPHER);
  }

  _status = 0;
abort:
  return (_status);
}

static int read_hex_string(char *str, UCHAR *buf, int n) {
  unsigned int t;
  int i;
  for(i = 0; i < n; i++) {
    if(sscanf(str + i * 2, "%02x", &t) != 1)
      return -1;
    buf[i] = (char)t;
  }
  return 0;
}
static int ssl_read_key_log_file(ssl_obj *ssl, ssl_decoder *d) {
  int r, _status, n, i;
  unsigned int t;
  size_t l = 0;
  char *line, *d_client_random, *label, *client_random, *secret;
  if(ssl->version == TLSV13_VERSION &&
     !ssl->cs)  // ssl->cs is not set when called from
                // ssl_process_client_session_id
    ABORT(r);
  if(!(d_client_random = malloc((d->client_random->len * 2) + 1)))
    ABORT(r);
  for(i = 0; i < d->client_random->len; i++)
    if(snprintf(d_client_random + (i * 2), 3, "%02x",
                d->client_random->data[i]) != 2)
      ABORT(r);
  while((n = getline(&line, &l, d->ctx->ssl_key_log_file)) != -1) {
    if(line[n - 1] == '\n')
      line[n - 1] = '\0';
    if(!(label = strtok(line, " ")))
      continue;
    if(!(client_random = strtok(NULL, " ")) || strlen(client_random) != 64 ||
       STRNICMP(client_random, d_client_random, 64))
      continue;
    secret = strtok(NULL, " ");
    if(!(secret) ||
       strlen(secret) !=
           (ssl->version == TLSV13_VERSION ? ssl->cs->dig_len * 2 : 96))
      continue;
    if(!strncmp(label, "CLIENT_RANDOM", 13)) {
      if((r = r_data_alloc(&d->MS, 48)))
        ABORT(r);
      if(read_hex_string(secret, d->MS->data, 48))
        ABORT(r);
    }
    if(ssl->version != TLSV13_VERSION)
      continue;
    if(!strncmp(label, "SERVER_HANDSHAKE_TRAFFIC_SECRET", 31)) {
      if((r = r_data_alloc(&d->SHTS, ssl->cs->dig_len)))
        ABORT(r);
      if(read_hex_string(secret, d->SHTS->data, ssl->cs->dig_len))
        ABORT(r);
    } else if(!strncmp(label, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", 31)) {
      if((r = r_data_alloc(&d->CHTS, ssl->cs->dig_len)))
        ABORT(r);
      if(read_hex_string(secret, d->CHTS->data, ssl->cs->dig_len))
        ABORT(r);
    } else if(!strncmp(label, "SERVER_TRAFFIC_SECRET_0", 23)) {
      if((r = r_data_alloc(&d->STS, ssl->cs->dig_len)))
        ABORT(r);
      if(read_hex_string(secret, d->STS->data, ssl->cs->dig_len))
        ABORT(r);
    } else if(!strncmp(label, "CLIENT_TRAFFIC_SECRET_0", 23)) {
      if((r = r_data_alloc(&d->CTS, ssl->cs->dig_len)))
        ABORT(r);
      if(read_hex_string(secret, d->CTS->data, ssl->cs->dig_len))
        ABORT(r);
    }
    /*
       Eventually add support for other labels defined here:
       https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
    */
  }
  _status = 0;
abort:
  if(d->ctx->ssl_key_log_file != NULL)
    fseek(d->ctx->ssl_key_log_file, 0, SEEK_SET);
  return (_status);
}
#endif
