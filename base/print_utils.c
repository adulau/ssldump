/**
   print_utils.c


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

   $Id: print_utils.c,v 1.2 2000/10/17 16:09:58 ekr Exp $


   ekr@rtfm.com  Mon Feb 15 17:23:36 1999
 */


static char *RCSSTRING="$Id: print_utils.c,v 1.2 2000/10/17 16:09:58 ekr Exp $";
int explain(char *format,...)
  {
    va_list ap;

    va_start(ap,format);

    INDENT;

    vprintf(format,ap);
    va_end(ap);
    return(0);
  }

int exdump(name,data)
  char *name;
  Data *data;
  {
    int i,j;
    char prefix[100];

    INDENT;

    if(name){
      sprintf(prefix,"%s[%d]=\n",name,data->len);
      printf("%s",prefix);
      INDENT_INCR;
    }
    for(i=0;i<data->len;i++){
      if(!i && (data->len>8)) INDENT;
      if((data->len>8) && i && !(i%12)){
        printf("\n"); INDENT; 
      }
      printf("%.2x ",data->data[i]&255);
    }
    if(name) INDENT_POP;
    if(data->len>8 && i%12)
      printf("\n");
    return(0);
  }
      

