/**
   ssl.y

   Copyright (C) 1998, RTFM, Inc.
   All Rights Reserved.

   ekr@rtfm.com  Fri Dec 25 20:33:47 1998
 */


%{

typedef struct select_st_ {
	char *name;
        char *code;
	int val;
	struct select_st_ *next;
} select_st;


select_st *select_base;
select_st *select_ptr;

select_st *constant_base;
select_st *constant_ptr;

#include <stdio.h>
 
extern FILE *dotc;
extern FILE *doth;
 
%}
%union {
     int val;
     unsigned char str[8192];
}


/*These tokens have attributes*/
%token <str> NAME_
%token <val> NUM_

/*Tokens*/
%token <val> DOT_DOT_
%token <val> STRUCT_
%token <val> SELECT_
%token <str> OPAQUE_
%token <val> SELECT_
%token <val> ENUM_
%token <val> DIGITALLY_SIGNED_
%token <val> COMMENT_START_
%token <str> CODE_
%token <val> COMMENT_END_
%token <val> CASE_
%token <val> CONSTANT_ 
/*Types for nonterminals*/
%type <val> module
%type <val> typelist
%type <val> definition
%type <val> selecttype
%type <val> constant_type
%type <val> selecterateds
%type <val> selectmax
%type <val> constval
/*%type <val> selecterated*/
%%
module: typelist

typelist: {$$=1};
	| definition typelist
  {
    $$=1;
  }
;

definition: selecttype
          | constant_type
;

selecttype: SELECT_ '{' selecterateds ',' selectmax '}' NAME_ ';'
  {
	select_st *en;
	char filename[100];

	for(en=select_base;en;en=en->next){
	  fprintf(dotc,"static int decode_%s_%s(ssl,dir,seg,data)\n",
			 $7,en->name);
	  fprintf(dotc,"  ssl_obj *ssl;\n");
	  fprintf(dotc,"  int dir;\n");
	  fprintf(dotc,"  segment *seg;\n");
	  fprintf(dotc,"  Data *data;\n");
	  fprintf(dotc,"  {\n");
          if(en->code){
            en->code+=2;
            en->code[strlen(en->code)-2]=0;
            fprintf(dotc,"\n%s\n",en->code);
          }
          else{
/*            fprintf(dotc,"	fprintf(dotc,\"Decoding %s...%cn\");\n",en->name,'\\');*/
            fprintf(dotc,"	return(0);\n");
          }
	  fprintf(dotc,"  }\n");
        }

	fprintf(dotc,"decoder %s_decoder[]={\n",$7);
	fprintf(doth,"extern decoder %s_decoder[];\n",$7);	
	for(en=select_base;en;en=en->next){
	  fprintf(dotc,"	{\n");
	  fprintf(dotc,"		%d,\n",en->val);
	  fprintf(dotc,"		\"%s\",\n",en->name);
	  fprintf(dotc,"		decode_%s_%s\n",$7,en->name);
	  fprintf(dotc,"	},\n");
	}

	fprintf(dotc,"{-1}\n");
	fprintf(dotc,"};\n\n");

        

	select_base=0;
  }
;

selecterateds: selecterateds ',' selecterated
	   | selecterated
{;
}
;

selectmax: '(' NUM_ ')'
{$$=1;};

selecterated: selecterated_no_code
          | selecterated_code
;


selecterated_code: NAME_ '(' NUM_ ')' CODE_
{
	select_st *en;

	en=malloc(sizeof(select_st));

	en->next=0;
	en->val=$3;
	en->name=strdup($1);
        en->code=strdup($5);
        
	if(!select_base){
	  select_base=en;
	  select_ptr=en;
        }
	else{
	  select_ptr->next=en;
	  select_ptr=en;
	}
};


selecterated_no_code: NAME_ '(' NUM_ ')' 
{
	select_st *en;

	en=malloc(sizeof(select_st));

	en->next=0;
	en->val=$3;
	en->name=strdup($1);
        en->code=0;
        
	if(!select_base){
	  select_base=en;
	  select_ptr=en;
        }
	else{
	  select_ptr->next=en;
	  select_ptr=en;
	}
};

constant_type: CONSTANT_ '{' constants '}' NAME_ ';'
  {
    select_st *en;

	fprintf(dotc,"decoder %s_decoder[]={\n",$5);
	fprintf(doth,"extern decoder %s_decoder[];\n",$5);
	
	for(en=constant_base;en;en=en->next){
	  fprintf(dotc,"	{\n");
	  fprintf(dotc,"		%d,\n",en->val);
	  fprintf(dotc,"		\"%s\",\n",en->name);
	  fprintf(dotc,"		0");
	  fprintf(dotc,"	},\n");
	}

	fprintf(dotc,"{-1}\n");
	fprintf(dotc,"};\n\n");
        constant_ptr=0;
        constant_base=0;
  }
    
constants: constants constant
         | constant
{;
}
;

constant: NAME_ NAME_ '=' '{' constval '}' ';'
{
	select_st *en;

	en=malloc(sizeof(select_st));

	en->next=0;
	en->val=$5;
	en->name=strdup($2);
        
	if(!constant_base){
	  constant_base=en;
	  constant_ptr=en;
        }
	else{
	  constant_ptr->next=en;
	  constant_ptr=en;
	}
};

constval: NUM_ ',' NUM_ ',' NUM_
  {
    $$=($1 << 16) | ($3 << 8) | $5;
  }
 |  NUM_ ',' NUM_
  {
    $$=($1 << 8) | $3;
  }
        | NUM_
  {
    $$=$1;
  }
;
  
