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
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY SUCH
   DAMAGE.

   $Id: ssl_rec.c,v 1.3 2000/11/03 06:38:06 ekr Exp $


   ekr@rtfm.com  Wed Aug 18 15:46:57 1999
 */

#include "network.h"
#include "ssl_h.h"
#include "sslprint.h"
#include "ssl.enums.h"
#ifdef OPENSSL
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif
#include "ssldecode.h"
#include "ssl_rec.h"

struct ssl_rec_decoder_ {
  SSL_CipherSuite *cs;
  Data *mac_key;
  Data *implicit_iv; /* for AEAD ciphers */
  Data *write_key;   /* for AEAD ciphers */
#ifdef OPENSSL
  EVP_CIPHER_CTX *evp;
#endif
  UINT8 seq;
};

char *digests[] = {"MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", NULL};

char *ciphers[] = {
    "DES",         "3DES",
    "RC4",         "RC2",
    "IDEA",        "AES128",
    "AES256",      "CAMELLIA128",
    "CAMELLIA256", "SEED",
    NULL,          "aes-128-gcm",
    "aes-256-gcm", "ChaCha20-Poly1305",
    "aes-128-ccm",
    "aes-128-ccm",  // for ccm 8, uses the same cipher
};

static int tls_check_mac PROTO_LIST((ssl_rec_decoder * d,
                                     int ct,
                                     int ver,
                                     UCHAR *data,
                                     UINT4 datalen,
                                     UCHAR *iv,
                                     UINT4 ivlen,
                                     UCHAR *mac));
static int fmt_seq PROTO_LIST((UINT4 num, UCHAR *buf));

int ssl_create_rec_decoder(ssl_rec_decoder **dp,
                           ssl_obj *ssl,
                           UCHAR *mk,
                           UCHAR *sk,
                           UCHAR *iv) {
  int r, _status;
  ssl_rec_decoder *dec = 0;
#ifdef OPENSSL
  const EVP_CIPHER *ciph = 0;
  int iv_len = ssl->version == TLSV13_VERSION ? 12 : ssl->cs->block;

  /* Find the SSLeay cipher */
  if(ssl->cs->enc != ENC_NULL) {
    ciph = (EVP_CIPHER *)EVP_get_cipherbyname(ciphers[ssl->cs->enc - 0x30]);
    if(!ciph)
      ABORT(R_INTERNAL);
  } else {
    ciph = EVP_enc_null();
  }

  if(!(dec = (ssl_rec_decoder *)calloc(1, sizeof(ssl_rec_decoder))))
    ABORT(R_NO_MEMORY);

  dec->cs = ssl->cs;

  if((r = r_data_alloc(&dec->mac_key, ssl->cs->dig_len)))
    ABORT(r);

  if((r = r_data_alloc(&dec->implicit_iv, iv_len)))
    ABORT(r);
  memcpy(dec->implicit_iv->data, iv, iv_len);

  if((r = r_data_create(&dec->write_key, sk, ssl->cs->eff_bits / 8)))
    ABORT(r);

  /*
     This is necessary for AEAD ciphers, because we must wait to fully
     initialize the cipher in order to include the implicit IV
  */
  if(IS_AEAD_CIPHER(ssl->cs)) {
    sk = NULL;
    iv = NULL;
  } else
    memcpy(dec->mac_key->data, mk, ssl->cs->dig_len);

  if(!(dec->evp = EVP_CIPHER_CTX_new()))
    ABORT(R_NO_MEMORY);
  EVP_CIPHER_CTX_init(dec->evp);
  EVP_CipherInit(dec->evp, ciph, sk, iv, 0);
#endif

  *dp = dec;
  _status = 0;
abort:
  if(_status) {
    ssl_destroy_rec_decoder(&dec);
  }
  return (_status);
}

int ssl_destroy_rec_decoder(ssl_rec_decoder **dp) {
  ssl_rec_decoder *d;

  if(!dp || !*dp)
    return (0);
  d = *dp;

  r_data_destroy(&d->mac_key);
  r_data_destroy(&d->implicit_iv);
  r_data_destroy(&d->write_key);
#ifdef OPENSSL
  if(d->evp) {
    EVP_CIPHER_CTX_free(d->evp);
  }
  free(*dp);
#endif

  *dp = 0;
  return (0);
}

#define MSB(a) ((a >> 8) & 0xff)
#define LSB(a) (a & 0xff)

int tls13_update_rec_key(ssl_rec_decoder *d, UCHAR *newkey, UCHAR *newiv) {
  d->write_key->data = newkey;
  d->implicit_iv->data = newiv;
  d->seq = 0;
  return 0;
}

int tls13_decode_rec_data(ssl_obj *ssl,
                          ssl_rec_decoder *d,
                          int ct,
                          int version,
                          UCHAR *in,
                          int inl,
                          UCHAR *out,
                          int *outl) {
  int pad, i;
  int r, encpadl, x, _status = 0;
  UCHAR aad[5], aead_nonce[12], *tag;
  int taglen = d->cs->enc == ENC_AES128_CCM_8 ? 8 : 16;
  CRDUMP("CipherText", in, inl);
  CRDUMPD("KEY", d->write_key);
  CRDUMPD("IV", d->implicit_iv);
  if(!IS_AEAD_CIPHER(d->cs)) {
    fprintf(stderr, "Non aead cipher in tls13\n");
    ABORT(-1);
  }
  memcpy(aead_nonce, d->implicit_iv->data, 12);
  for(i = 0; i < 8; i++) {  // AEAD NONCE according to RFC TLS1.3
    aead_nonce[12 - 1 - i] ^= ((d->seq >> (i * 8)) & 0xFF);
  }
  d->seq++;
  CRDUMP("NONCE", aead_nonce, 12);
  tag = in + (inl - taglen);
  CRDUMP("Tag", tag, taglen);

  aad[0] = ct;
  aad[1] = 0x03;
  aad[2] = 0x03;
  aad[3] = MSB(inl);
  aad[4] = LSB(inl);
  CRDUMP("AAD", aad, 5);
  inl -= taglen;

  if(!EVP_CIPHER_CTX_ctrl(d->evp, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)) {
    fprintf(stderr, "Unable to set ivlen\n");
    ABORT(-1);
  }

  if(IS_CCM_CIPHER(d->cs) &&
     !EVP_CIPHER_CTX_ctrl(d->evp, EVP_CTRL_AEAD_SET_TAG, taglen, tag)) {
    fprintf(stderr, "Unable to set tag for ccm cipher\n");
    ABORT(-1);
  }

  if(!EVP_DecryptInit_ex(d->evp, NULL, NULL, d->write_key->data, aead_nonce)) {
    fprintf(stderr, "Unable to init evp1\n");
    ABORT(-1);
  }

  if(IS_CCM_CIPHER(d->cs) &&
     !EVP_DecryptUpdate(d->evp, NULL, outl, NULL, inl)) {
    fprintf(stderr, "Unable to update data length\n");
    ABORT(-1);
  }

  if(!EVP_DecryptUpdate(d->evp, NULL, outl, aad, 5)) {
    fprintf(stderr, "Unable to update aad\n");
    ABORT(-1);
  }

  CRDUMP("Real CipherText", in, inl);
  if(!EVP_DecryptUpdate(d->evp, out, outl, in, inl)) {
    fprintf(stderr, "Unable to update with CipherText\n");
    ABORT(-1);
  }

  if(!IS_CCM_CIPHER(d->cs) &&
     (!EVP_CIPHER_CTX_ctrl(d->evp, EVP_CTRL_GCM_SET_TAG, taglen, tag) ||
      !EVP_DecryptFinal(d->evp, NULL, &x))) {
    fprintf(stderr, "BAD MAC\n");
    ABORT(SSL_BAD_MAC);
  }

abort:
  ERR_print_errors_fp(stderr);
  return _status;
}

int ssl_decode_rec_data(ssl_obj *ssl,
                        ssl_rec_decoder *d,
                        int ct,
                        int version,
                        UCHAR *in,
                        int inl,
                        UCHAR *out,
                        int *outl) {
#ifdef OPENSSL
  int pad;
  int r, encpadl, x;
  UCHAR *mac, aead_tag[13], aead_nonce[12];

  CRDUMP("Ciphertext", in, inl);
  if(IS_AEAD_CIPHER(d->cs)) {
    memcpy(aead_nonce, d->implicit_iv->data, d->implicit_iv->len);
    memcpy(aead_nonce + d->implicit_iv->len, in, 12 - d->implicit_iv->len);
    in += 12 - d->implicit_iv->len;
    inl -= 12 - d->implicit_iv->len;

    EVP_DecryptInit(d->evp, NULL, d->write_key->data, aead_nonce);

    /*
       Then tag is always 16 bytes, as per:
       https://tools.ietf.org/html/rfc5116#section-5.2
    */
    EVP_CIPHER_CTX_ctrl(d->evp, EVP_CTRL_GCM_SET_TAG, 16, in + (inl - 16));
    inl -= 16;

    fmt_seq(d->seq, aead_tag);
    d->seq++;
    aead_tag[8] = ct;
    aead_tag[9] = MSB(version);
    aead_tag[10] = LSB(version);
    aead_tag[11] = MSB(inl);
    aead_tag[12] = LSB(inl);

    EVP_DecryptUpdate(d->evp, NULL, outl, aead_tag, 13);
    EVP_DecryptUpdate(d->evp, out, outl, in, inl);

    if(!(x = EVP_DecryptFinal(d->evp, NULL, &x)))
      ERETURN(SSL_BAD_MAC);
  }

  /*
     Encrypt-then-MAC is not used with AEAD ciphers, as per:
     https://tools.ietf.org/html/rfc7366#section-3
  */
  else if(ssl->extensions->encrypt_then_mac == 2) {
    *outl = inl;

    /* First strip off the MAC */
    *outl -= d->cs->dig_len;
    mac = in + (*outl);

    encpadl = *outl;
    /* Now decrypt */
    EVP_Cipher(d->evp, out, in, *outl);
    CRDUMP("Plaintext", out, *outl);

    /* And then strip off the padding*/
    if(d->cs->block > 1) {
      pad = out[*outl - 1];
      *outl -= (pad + 1);
    }
    /* TLS 1.1 and beyond: remove explicit IV, only used with
     * non-stream ciphers. */
    if(ssl->version >= 0x0302 && ssl->cs->block > 1) {
      UINT4 blk = ssl->cs->block;
      if(blk <= *outl) {
        *outl -= blk;
        memmove(out, out + blk, *outl);
      } else {
        DBG((0, "Block size greater than Plaintext!"));
        ERETURN(SSL_BAD_MAC);
      }

      if((r = tls_check_mac(d, ct, version, in + blk, encpadl, in, blk, mac)))
        ERETURN(r);

    } else if((r = tls_check_mac(d, ct, version, in, encpadl, NULL, 0, mac)))
      ERETURN(r);

  } else {
    /* First decrypt*/
    EVP_Cipher(d->evp, out, in, inl);

    CRDUMP("Plaintext", out, inl);
    *outl = inl;

    /* Now strip off the padding*/
    if(d->cs->block > 1) {
      pad = out[inl - 1];
      *outl -= (pad + 1);
    }

    /* And the MAC */
    *outl -= d->cs->dig_len;
    mac = out + (*outl);
    CRDUMP("Record data", out, *outl);

    /* Now check the MAC */
    if(ssl->version == 0x300) {
      if((r = ssl3_check_mac(d, ct, version, out, *outl, mac)))
        ERETURN(r);
    } else {
      /* TLS 1.1 and beyond: remove explicit IV, only used with
       * non-stream ciphers. */
      if(ssl->version >= 0x0302 && ssl->cs->block > 1) {
        UINT4 blk = ssl->cs->block;
        if(blk <= *outl) {
          *outl -= blk;
          memmove(out, out + blk, *outl);
        } else {
          DBG((0, "Block size greater than Plaintext!"));
          ERETURN(SSL_BAD_MAC);
        }
      }
      if((r = tls_check_mac(d, ct, version, out, *outl, NULL, 0, mac)))
        ERETURN(r);
    }
  }
#endif
  return (0);
}

#ifdef OPENSSL

/* This should go to 2^128, but we're never really going to see
   more than 2^64, so we cheat*/
static int fmt_seq(UINT4 num, UCHAR *buf) {
  UINT4 netnum;

  memset(buf, 0, 8);
  netnum = htonl(num);
  memcpy(buf + 4, &netnum, 4);

  return (0);
}

static int tls_check_mac(ssl_rec_decoder *d,
                         int ct,
                         int ver,
                         UCHAR *data,
                         UINT4 datalen,
                         UCHAR *iv,
                         UINT4 ivlen,
                         UCHAR *mac) {
  HMAC_CTX *hm = HMAC_CTX_new();
  if(!hm)
    ERETURN(R_NO_MEMORY);
  const EVP_MD *md;
  UINT4 l;
  UCHAR buf[128];

  md = EVP_get_digestbyname(digests[d->cs->dig - 0x40]);
  HMAC_Init_ex(hm, d->mac_key->data, d->mac_key->len, md, NULL);

  fmt_seq(d->seq, buf);
  d->seq++;
  HMAC_Update(hm, buf, 8);
  buf[0] = ct;
  HMAC_Update(hm, buf, 1);

  buf[0] = MSB(ver);
  buf[1] = LSB(ver);
  HMAC_Update(hm, buf, 2);

  buf[0] = MSB(datalen);
  buf[1] = LSB(datalen);
  HMAC_Update(hm, buf, 2);

  /* for encrypt-then-mac with an explicit IV */
  if(ivlen && iv) {
    HMAC_Update(hm, iv, ivlen);
    HMAC_Update(hm, data, datalen - ivlen);
  } else
    HMAC_Update(hm, data, datalen);

  HMAC_Final(hm, buf, &l);
  if(memcmp(mac, buf, l))
    ERETURN(SSL_BAD_MAC);

  HMAC_CTX_free(hm);
  return (0);
}

int ssl3_check_mac(ssl_rec_decoder *d,
                   int ct,
                   int ver,
                   UCHAR *data,
                   UINT4 datalen,
                   UCHAR *mac) {
  EVP_MD_CTX *mc = EVP_MD_CTX_new();
  const EVP_MD *md;
  UINT4 l;
  UCHAR buf[64], dgst[20];
  int pad_ct;

  pad_ct = (d->cs->dig == DIG_SHA) ? 40 : 48;

  md = EVP_get_digestbyname(digests[d->cs->dig - 0x40]);
  EVP_DigestInit(mc, md);

  EVP_DigestUpdate(mc, d->mac_key->data, d->mac_key->len);

  memset(buf, 0x36, pad_ct);
  EVP_DigestUpdate(mc, buf, pad_ct);

  fmt_seq(d->seq, buf);
  d->seq++;
  EVP_DigestUpdate(mc, buf, 8);

  buf[0] = ct;
  EVP_DigestUpdate(mc, buf, 1);

  buf[0] = MSB(datalen);
  buf[1] = LSB(datalen);
  EVP_DigestUpdate(mc, buf, 2);

  EVP_DigestUpdate(mc, data, datalen);

  EVP_DigestFinal(mc, dgst, &l);

  EVP_DigestInit(mc, md);

  EVP_DigestUpdate(mc, d->mac_key->data, d->mac_key->len);

  memset(buf, 0x5c, pad_ct);
  EVP_DigestUpdate(mc, buf, pad_ct);

  EVP_DigestUpdate(mc, dgst, l);

  EVP_DigestFinal(mc, dgst, &l);

  if(memcmp(mac, dgst, l))
    ERETURN(SSL_BAD_MAC);

  EVP_MD_CTX_free(mc);

  return (0);
}

#endif
