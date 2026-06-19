/**
   sslxprint.c


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

   $Id: sslxprint.c,v 1.3 2000/11/03 06:38:06 ekr Exp $


   ekr@rtfm.com  Thu Mar 25 21:17:16 1999
 */

#include <json.h>
#include "network.h"
#include "ssl_h.h"
#include "sslprint.h"
#include "ssl.enums.h"
#ifdef OPENSSL
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#endif

#define BUFSIZE 1024


#ifdef OPENSSL
static char *fanx_base64url(const char *in) {
  int in_len = strlen(in);
  int out_len = 4 * ((in_len + 2) / 3);
  char *out = calloc(out_len + 1, 1);
  int i;
  if(!out)
    return NULL;
  EVP_EncodeBlock((unsigned char *)out, (const unsigned char *)in, in_len);
  for(i = 0; out[i]; i++) {
    if(out[i] == '+')
      out[i] = '-';
    else if(out[i] == '/')
      out[i] = '_';
  }
  while(out_len > 0 && out[out_len - 1] == '=')
    out[--out_len] = 0;
  return out;
}
static char *fanx_sha256_hex(const char *in) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len, i;
  char *hex = calloc(SHA256_DIGEST_LENGTH * 2 + 1, 1);
  if(!hex || !mdctx)
    return hex;
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx, in, strlen(in));
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_free(mdctx);
  for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    snprintf(hex + strlen(hex), 3, "%02x", md_value[i]);
  return hex;
}
static char *fanx_fingerprint(const char *features) {
  char *b64 = fanx_base64url(features), *hex = fanx_sha256_hex(features), *fp;
  if(!b64 || !hex) {
    free(b64);
    free(hex);
    return NULL;
  }
  fp = calloc(strlen(b64) + strlen(hex) + 31, 1);
  if(fp) sprintf(fp, "fan1:x509:server:passive:%s:sha256:%s", b64, hex);
  free(b64);
  free(hex);
  return fp;
}
static char *fanx_oid(const ASN1_OBJECT *obj, char *buf, size_t len) {
  if(!obj || OBJ_obj2txt(buf, len, obj, 1) <= 0) buf[0] = 0;
  return buf;
}
static void fanx_add_certificate_json(ssl_obj *ssl,
                                       struct json_object *cert_obj,
                                       X509 *x) {
  char subj[BUFSIZE], iss[BUFSIZE], sig[128], tbssig[128], spki[128];
  char extbuf[2048];
  const ASN1_OBJECT *sigobj = NULL, *tbssigobj = NULL;
  const X509_ALGOR *sigalg = NULL;
  EVP_PKEY *pkey;
  int ext_count = X509_get_ext_count(x), i, pk_bits = 0, days = 0;
  int pday = 0, psec = 0;
  char *features, *fp;
  extbuf[0] = 0;
  X509_NAME_oneline(X509_get_subject_name(x), subj, sizeof(subj));
  X509_NAME_oneline(X509_get_issuer_name(x), iss, sizeof(iss));
  X509_get0_signature(NULL, &sigalg, x);
  X509_ALGOR_get0(&sigobj, NULL, NULL, sigalg);
  X509_ALGOR_get0(&tbssigobj, NULL, NULL, X509_get0_tbs_sigalg(x));
  pkey = X509_get_pubkey(x);
  if(pkey) pk_bits = EVP_PKEY_bits(pkey);
  fanx_oid(sigobj, sig, sizeof(sig));
  fanx_oid(tbssigobj, tbssig, sizeof(tbssig));
  fanx_oid(pkey ? OBJ_nid2obj(EVP_PKEY_base_id(pkey)) : NULL, spki,
           sizeof(spki));
  if(ASN1_TIME_diff(&pday, &psec, X509_getm_notBefore(x),
                    X509_getm_notAfter(x)))
    days = pday + (psec ? 1 : 0);
  for(i = 0; i < ext_count; i++) {
    X509_EXTENSION *ex = X509_get_ext(x, i);
    char oid[128];
    fanx_oid(X509_EXTENSION_get_object(ex), oid, sizeof(oid));
    snprintf(extbuf + strlen(extbuf), sizeof(extbuf) - strlen(extbuf),
             "%s%s:%s", i ? "," : "",
             X509_EXTENSION_get_critical(ex) ? "c" : "n", oid);
  }
  features = calloc(strlen(subj) + strlen(iss) + strlen(sig) +
                        strlen(tbssig) + strlen(spki) + strlen(extbuf) + 256,
                    1);
  if(features) {
    snprintf(features,
             strlen(subj) + strlen(iss) + strlen(sig) + strlen(tbssig) +
                 strlen(spki) + strlen(extbuf) + 256,
             "x509|server|idx=|ver=%ld|serial_len=%d|sig=%s|tbs_sig=%s|issuer=%s|subject=%s|valid_days=%d|spki_alg=%s|spki_param=|pk_bits=%d|san=|ku=|eku=|bc=|ski=|aki=|pol=|aia=|crldp=|nc=|ext=%s",
             X509_get_version(x), X509_get_serialNumber(x)->length, sig, tbssig, iss, subj, days, spki, pk_bits, extbuf);
    fp = fanx_fingerprint(features);
    if(fp) {
      json_object_object_add(cert_obj, "fan1_x509_features",
                             json_object_new_string(features));
      json_object_object_add(cert_obj, "fan1_x509_fp", json_object_new_string(fp));
      explain(ssl, "fan1 x509 features: %s\n", features);
      explain(ssl, "fan1 x509 fingerprint: %s\n", fp);
      free(fp);
    }
    free(features);
  }
  if(pkey)
    EVP_PKEY_free(pkey);
}
#endif

static int sslx__print_dn PROTO_LIST((ssl_obj * ssl, char *x));
#ifdef OPENSSL
static int sslx__print_serial PROTO_LIST((ssl_obj * ssl, ASN1_INTEGER *a));
#endif

int sslx_print_certificate(ssl_obj *ssl, Data *data, int pf) {
#ifdef OPENSSL
  X509 *x = 0;
  ASN1_INTEGER *a;
#endif
  UCHAR *d;
  int _status;
  struct json_object *cert_obj;

#ifdef OPENSSL
  P_(P_ASN) {
    char buf[BUFSIZE];
    int ext;
    char *b64_cert;

    char *serial_str = NULL;
    Data data_tmp;

    struct json_object *jobj;
    jobj = ssl->cur_json_st;

    cert_obj = json_object_new_object();

    d = data->data;

    if(!(b64_cert = (char *)calloc(
             1, sizeof(char) * ((((data->len) + 3 - 1) / 3) * 4 + 1))))
      ABORT(R_NO_MEMORY);

    EVP_EncodeBlock((unsigned char *)b64_cert, d, data->len);
    json_object_object_add(cert_obj, "cert_der",
                           json_object_new_string(b64_cert));
    free(b64_cert);

    if(!(x = d2i_X509(0, (const unsigned char **)&d, data->len))) {
      explain(ssl, "Bad certificate");
      ABORT(R_BAD_DATA);
    }
    X509_NAME_oneline(X509_get_subject_name(x), buf, BUFSIZE);
    explain(ssl, "Subject\n");
    INDENT_INCR;
    json_object_object_add(cert_obj, "cert_subject",
                           json_object_new_string(buf));
    sslx__print_dn(ssl, buf);
    INDENT_POP;
    X509_NAME_oneline(X509_get_issuer_name(x), buf, BUFSIZE);
    explain(ssl, "Issuer\n");
    INDENT_INCR;
    json_object_object_add(cert_obj, "cert_issuer",
                           json_object_new_string(buf));
    sslx__print_dn(ssl, buf);
    INDENT_POP;
    a = X509_get_serialNumber(x);
    explain(ssl, "Serial ");
    if(!(serial_str = (char *)calloc(1, sizeof(char) * (a->length * 3))))
      ABORT(R_NO_MEMORY);
    INIT_DATA(data_tmp, a->data, a->length);
    exstr(ssl, serial_str, &data_tmp);
    json_object_object_add(cert_obj, "cert_serial",
                           json_object_new_string(serial_str));
    free(serial_str);
    sslx__print_serial(ssl, a);
    fanx_add_certificate_json(ssl, cert_obj, x);

    ext = X509_get_ext_count(x);
    if(ext > 0) {
      int i, j;
      UCHAR buf[1024];

      explain(ssl, "Extensions\n");
      INDENT_INCR;
      for(i = 0; i < ext; i++) {
        X509_EXTENSION *ex;
        ASN1_OBJECT *obj;

        ex = X509_get_ext(x, i);
        obj = X509_EXTENSION_get_object(ex);
        i2t_ASN1_OBJECT((char *)buf, sizeof(buf), obj);

        explain(ssl, "Extension: %s\n", buf);
        j = X509_EXTENSION_get_critical(ex);
        if(j) {
          INDENT;
          explain(ssl, "Critical\n");
        }
        if(SSL_print_flags & SSL_PRINT_NROFF) {
          if(ssl->process_ciphertext & ssl->direction)
            printf("\\f(CI");
          else
            printf("\\fC");

          INDENT_INCR;
          INDENT;
          if(!X509V3_EXT_print_fp(stdout, ex, 0, 0)) {
            printf("Hex value");
          }
          INDENT_POP;
          explain(ssl, "\n");
        }
      }
      INDENT_POP;

    } else {
#endif
      P_(pf) { exdump(ssl, "certificate", data); }
#ifdef OPENSSL
    }

    struct json_object *certs_array;
    json_object_object_get_ex(jobj, "cert_chain", &certs_array);
    json_object_array_add(certs_array, cert_obj);
  }
#endif

  _status = 0;
abort:
#ifdef OPENSSL
  if(x)
    X509_free(x);
#endif
  if(_status && cert_obj)
    json_object_put(cert_obj);
  return _status;
}

int sslx_print_dn(ssl_obj *ssl, Data *data, int pf) {
  UCHAR buf[BUFSIZE];
  int _status;
  UCHAR *d = data->data;
#ifdef OPENSSL
  X509_NAME *n = 0;
#endif

  P_(pf){
#ifdef OPENSSL
      P_(P_ASN){if(!(n = d2i_X509_NAME(0, (const unsigned char **)&d,
                                       data->len))) ABORT(R_BAD_DATA);
  X509_NAME_oneline(n, (char *)buf, BUFSIZE);
  sslx__print_dn(ssl, (char *)buf);
}
else {
#endif
  exdump(ssl, 0, data);
#ifdef OPENSSL
}
#endif
}

_status = 0;
abort :
#ifdef OPENSSL
    if(n) X509_NAME_free(n);
#endif
return _status;
}

static int sslx__print_dn(ssl_obj *ssl, char *x) {
  char *slash;

  if(*x == '/')
    x++;

  while(x) {
    if((slash = strchr(x, '/'))) {
      *slash = 0;
    }

    explain(ssl, "%s\n", x);

    x = slash ? slash + 1 : 0;
  };

  return 0;
}

#ifdef OPENSSL
static int sslx__print_serial(ssl_obj *ssl, ASN1_INTEGER *a) {
  Data d;

  if(a->length == 0)
    printf("0");

  INIT_DATA(d, a->data, a->length);
  exdump(ssl, 0, &d);

  return 0;
}
#endif
