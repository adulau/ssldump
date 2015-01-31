/**
   main.c


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

   $Id: main.c,v 1.2 2000/10/17 16:10:01 ekr Exp $


   ekr@rtfm.com  Mon Jan 18 16:28:43 1999
 */


static char *RCSSTRING="$Id: main.c,v 1.2 2000/10/17 16:10:01 ekr Exp $";

#include <stdarg.h>
#include <r_common.h>

extern int yydebug;

FILE *doth,*dotc;

int verr_exit(char *fmt,...)
  {
    va_list ap;

    va_start(ap,fmt);
    vfprintf(stderr,fmt,ap);
    exit(1);
  }


int main(argc,argv)
  int argc;
  char **argv;
  {
    char name[100];
    FILE *in;

    if(!(in=freopen(argv[1],"r",stdin)))
      verr_exit("Couldn't open input file %s\n",argv[1]);
    
    sprintf(name,"%s.c",argv[1]);
    dotc=fopen(name,"w");
    sprintf(name,"%s.h",argv[1]);
    doth=fopen(name,"w");
    
    fprintf(dotc,"#include \"network.h\"\n#include \"ssl_h.h\"\n#include \"sslprint.h\"\n#include \"sslxprint.h\"\n#ifdef OPENSSL\n#include <openssl/ssl.h>\n#endif\n");
    fprintf(dotc,"#include \"%s\"\n",name);
    
    yyparse();
  }


extern int yylineno;

int yywrap()
{
;}

int yyerror(s)
  char *s;
  {
    printf("Parse error %s at line %d\n",s,yylineno);
    exit(1);
  }
