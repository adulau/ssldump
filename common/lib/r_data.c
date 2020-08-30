/**
   r_data.c


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

   $Id: r_data.c,v 1.3 2001/07/20 23:33:15 ekr Exp $


   ekr@rtfm.com  Tue Aug 17 15:39:50 1999
 */



#include <r_common.h>
#include <r_data.h>

int r_data_create(dp,d,l)
  Data **dp;
  UCHAR *d;
  int l;
  {
    Data *d_=0;
    int _status;
    
    if(!(d_=(Data *)calloc(sizeof(Data),1)))
      ABORT(R_NO_MEMORY);
    if(!(d_->data=(UCHAR *)malloc(l)))
      ABORT(R_NO_MEMORY);

    memcpy(d_->data,d,l);
    d_->len=l;

    *dp=d_;

    _status=0;
  abort:
    if(_status)
      r_data_destroy(&d_);

    return(_status);
  }

int r_data_alloc(dp,l)
  Data **dp;
  int l;
  {
    Data *d_=0;
    int _status;
    
    if(!(d_=(Data *)calloc(sizeof(Data),1)))
      ABORT(R_NO_MEMORY);
    if(!(d_->data=(UCHAR *)calloc(l,1)))
      ABORT(R_NO_MEMORY);

    d_->len=l;
    
    *dp=d_;
    _status=0;
  abort:
    if(_status)
      r_data_destroy(&d_);

    return(_status);
  }

int r_data_make(dp,d,l)
  Data *dp;
  UCHAR *d;
  int l;
  {
    if(!(dp->data=(UCHAR *)malloc(l)))
      ERETURN(R_NO_MEMORY);

    memcpy(dp->data,d,l);
    dp->len=l;

    return(0);
  }
  
int r_data_destroy(dp)
  Data **dp;
  {
    if(!dp || !*dp)
      return(0);

    if((*dp)->data)
      free((*dp)->data);

    free(*dp);
    *dp=0;

    return(0);
  }
    
int r_data_copy(dst,src)
  Data *dst;
  Data *src;
  {
    if(!(dst->data=(UCHAR *)malloc(src->len)))
      ERETURN(R_NO_MEMORY);
    memcpy(dst->data,src->data,dst->len=src->len);
    return(0);
  }

int r_data_zfree(d)
  Data *d;
  {
    if(!d)
      return(0);
    if(!d->data)
      return(0);
    memset(d->data,0,d->len);
    free(d->data);
    return(0);
  }

int r_data_compare(d1,d2)
  Data *d1;
  Data *d2;
  {
    if(d1->len<d2->len)
      return(-1);
    if(d2->len<d1->len)
      return(-1);
    return(memcmp(d1->data,d2->data,d1->len));
  }
  
