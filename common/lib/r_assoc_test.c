/**
   r_assoc_test.c


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

   $Id: r_assoc_test.c,v 1.2 2000/10/17 16:10:00 ekr Exp $


   ekr@rtfm.com  Sun Jan 17 21:09:22 1999
 */


static char *RCSSTRING="$Id: r_assoc_test.c,v 1.2 2000/10/17 16:10:00 ekr Exp $";

#include <r_common.h>
#include <r_assoc.h>

int main()
  {
    char test_vector[1024],*v;
    int rnd,ct,r;
    r_assoc *assoc,*new_assoc;

    if(r=r_assoc_create(&assoc)){
      fprintf(stderr,"Couldn't create\n");
      exit(1);
    }

    srand(getpid());

    v=test_vector;
    for(ct=0;ct<256;ct++){
      v[0]=ct & 255;
      v[1]=(ct>>8) & 255;
      v[2]=(ct>>16) & 255;
      v[3]=(ct>>24) & 255;

      
      if(r=r_assoc_insert(assoc,v,4,v,0,0,R_ASSOC_REPLACE)){
	fprintf(stderr,"Couldn't insert %d\n",ct);
	exit(1);
      }

      v+=4;
    }

    fetch_test(assoc);
    
    if(r=r_assoc_copy(&new_assoc,assoc)){
      fprintf(stderr,"Couldn't copy\n");
      exit(1);
    }
      
    r_assoc_destroy(&assoc);
    
    fetch_test(new_assoc);
    
    r_assoc_destroy(&new_assoc);

    printf("Tests pass\n");
    exit(0);
  }

int fetch_test(assoc)
  r_assoc *assoc;
  {
    int ct;
    char vec[4],*v;
    int r,_status,rnd;
    
    for(ct=0;ct<65537;ct++){
      rnd=rand();

      rnd &= 0x3ff;
      
      vec[0]=rnd & 255;
      vec[1]=(rnd>>8) & 255;
      vec[2]=(rnd>>16) & 255;
      vec[3]=(rnd>>24) & 255;

      if(r=r_assoc_fetch(assoc,vec,4,(void **)&v)){

	if(rnd<256){
	  fprintf(stderr,"Couldn't fetch\n");
	  exit(1);
	}
	else
	  continue;
      }
      else{
	if(rnd>255){
	  fprintf(stderr,"Spurious fetch\n");
	  exit(1);
	}
      }
      
      if(memcmp(vec,v,4)){
	fprintf(stderr,"Fetch error\n");
	exit(1);
      }
    }
    return(0);
  }
