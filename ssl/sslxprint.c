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
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY SUCH DAMAGE.

   $Id: sslxprint.c,v 1.3 2000/11/03 06:38:06 ekr Exp $


   ekr@rtfm.com  Thu Mar 25 21:17:16 1999
 */


static char *RCSSTRING="$Id: sslxprint.c,v 1.3 2000/11/03 06:38:06 ekr Exp $";

#include "network.h"
#include "ssl_h.h"
#include "sslprint.h"
#include "ssl.enums.h"
#ifdef OPENSSL
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

#define BUFSIZE 1024

static int sslx__print_dn PROTO_LIST((ssl_obj *ssl,char *x));
#ifdef OPENSSL
static int sslx__print_serial PROTO_LIST((ssl_obj *ssl,ASN1_INTEGER *a));
#endif

int sslx_print_certificate(ssl,data,pf)
  ssl_obj *ssl;
  Data *data;
  int pf;
  {
#ifdef OPENSSL    
    X509 *x=0;
    ASN1_INTEGER *a;
#endif    
    UCHAR *d;
    int _status;
    
#ifdef OPENSSL        
    P_(P_ASN){
      char buf[BUFSIZE];
      int ext;
        
      d=data->data;
	
      if(!(x=d2i_X509(0,&d,data->len))){
        explain(ssl,"Bad certificate");
        ABORT(R_BAD_DATA);
      }
      X509_NAME_oneline(X509_get_subject_name(x),buf,
        BUFSIZE);
      explain(ssl,"Subject\n");
      INDENT_INCR;
      sslx__print_dn(ssl,buf);
      INDENT_POP;
      X509_NAME_oneline(X509_get_issuer_name(x),buf,
        BUFSIZE);
      explain(ssl,"Issuer\n");
      INDENT_INCR;
      sslx__print_dn(ssl,buf);
      INDENT_POP;
      a=X509_get_serialNumber(x);
      explain(ssl,"Serial ");
      sslx__print_serial(ssl,a);

      ext=X509_get_ext_count(x);
      if(ext>0){
        int i,j;
        UCHAR buf[1024];
          
        explain(ssl,"Extensions\n");
        INDENT_INCR;
        for(i=0;i<ext;i++){
          X509_EXTENSION *ex;
          ASN1_OBJECT *obj;

          ex=X509_get_ext(x,i);
          obj=X509_EXTENSION_get_object(ex);
          i2t_ASN1_OBJECT(buf,sizeof(buf),obj);
            
          explain(ssl,"Extension: %s\n",buf);
          j=X509_EXTENSION_get_critical(ex);
          if(j){
            INDENT;
            explain(ssl,"Critical\n");
          }
          if(SSL_print_flags & SSL_PRINT_NROFF){
            if(ssl->process_ciphertext&ssl->direction)
              printf("\\f(CI");
            else
              printf("\\fC");

            INDENT_INCR;
            INDENT;
            if(!X509V3_EXT_print_fp(stdout,ex,0,0)){
              printf("Hex value");
            }
            INDENT_POP;
            explain(ssl,"\n");
          }
        }
        INDENT_POP;
        
      }
      else{
#endif
        P_(pf){
          exdump(ssl,"certificate",data);
        }
#ifdef OPENSSL        
      }
    }
#endif

    _status=0;
  abort:
#ifdef OPENSSL    
    if(x) X509_free(x);
#endif    
    return(_status);
  }  

int sslx_print_dn(ssl,data,pf)
  ssl_obj *ssl;
  Data *data;
  int pf;
  {
    UCHAR buf[BUFSIZE];
    int _status;
    UCHAR *d=data->data;
#ifdef OPENSSL    
    X509_NAME *n=0;
#endif
    
    P_(pf){
#ifdef OPENSSL      
      P_(P_ASN){
	if(!(n=d2i_X509_NAME(0,&d,data->len)))
	  ABORT(R_BAD_DATA);
	X509_NAME_oneline(n,buf,BUFSIZE);
	sslx__print_dn(ssl,buf);
      }
      else{
#endif        
	exdump(ssl,0,data);
#ifdef OPENSSL        
      }
#endif
    }

    _status=0;
  abort:
#ifdef OPENSSL    
    if(n) X509_NAME_free(n);
#endif    
    return(_status);
  }

static int sslx__print_dn(ssl,x)
  ssl_obj *ssl;
  char *x;
  {
    char *slash;

    if(*x=='/') x++;
    
    while (x){
      if(slash=strchr(x,'/')){
	*slash=0;
      }

      explain(ssl,"%s\n",x);

      x=slash?slash+1:0;
    };

    return(0);
  }

#ifdef OPENSSL
static int sslx__print_serial(ssl,a)
  ssl_obj *ssl;
  ASN1_INTEGER *a;
  {
    Data d;
    
    if(a->length==0)
      printf("0");

    INIT_DATA(d,a->data,a->length);
    exdump(ssl,0,&d);

    return(0);
  }
#endif
