/**
   r_assoc.c

   This is an associative array implementation, using an open-chained
   hash bucket technique.

   Note that this implementation permits each data entry to have
   separate copy constructors and destructors. This currently wastes
   space, but could be implemented while saving space by using
   the high order bit of the length value or somesuch.

   The major problem with this code is it's not resizable, though it
   could be made so.
   

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

   $Id: r_assoc.c,v 1.4 2001/12/24 06:06:26 ekr Exp $


   ekr@rtfm.com  Sun Jan 17 17:57:15 1999
 */

static char *RCSSTRING="$Id: r_assoc.c,v 1.4 2001/12/24 06:06:26 ekr Exp $";

#include <r_common.h>
#include "r_assoc.h"

typedef struct r_assoc_el_ {
     char *key;
     int key_len;
     void *data;
     struct r_assoc_el_ *prev;
     struct r_assoc_el_ *next;
     int (*copy) PROTO_LIST((void **new,void *old));
     int (*destroy) PROTO_LIST((void *ptr));
} r_assoc_el;
     
struct r_assoc_ {
     int size;
     int bits;
     r_assoc_el **chains;	
};

#define DEFAULT_TABLE_BITS 5

static int destroy_assoc_chain PROTO_LIST((r_assoc_el *chain));
static int r_assoc_fetch_bucket PROTO_LIST((r_assoc *assoc,
  char *key,int len,r_assoc_el **bucketp));
UINT4 hash_compute PROTO_LIST((char *key,int len,int size));
static int copy_assoc_chain PROTO_LIST((r_assoc_el **newp,
  r_assoc_el *old));

int r_assoc_create(assocp)
  r_assoc **assocp;
  {
    r_assoc *assoc=0;
    int _status;
    
    if(!(assoc=(r_assoc *)calloc(sizeof(r_assoc),1)))
      ABORT(R_NO_MEMORY);
    assoc->size=(1<<DEFAULT_TABLE_BITS);
    assoc->bits=DEFAULT_TABLE_BITS;
    
    if(!(assoc->chains=(r_assoc_el **)calloc(sizeof(r_assoc_el *),
      assoc->size)))
      ABORT(R_NO_MEMORY);

    *assocp=assoc;
    
    _status=0;
  abort:
    if(_status){
      r_assoc_destroy(&assoc);
    }
    return(_status);
  }

int r_assoc_destroy(assocp)
  r_assoc **assocp;
  {
    r_assoc *assoc;
    int i;
	    
    if(!assocp || !*assocp)
      return(0);

    assoc=*assocp;
    for(i=0;i<assoc->size;i++)
      destroy_assoc_chain(assoc->chains[i]);

    return(0);
  }

static int destroy_assoc_chain(chain)
  r_assoc_el *chain;
  {
    r_assoc_el *nxt;
    
    while(chain){
      nxt=chain->next;

      if(chain->destroy)
	chain->destroy(chain->data);

      free(chain->key);
      
      free(chain);
      chain=nxt;
    }

    return(0);
  }

static int copy_assoc_chain(newp,old)
  r_assoc_el **newp;
  r_assoc_el *old;
  {
    r_assoc_el *new=0,*ptr,*tmp;
    int r,_status;

    if(!old) {
      *newp=0;
      return(0);
    }
    for(;old;old=old->next){
      if(!(tmp=(r_assoc_el *)calloc(sizeof(r_assoc_el),1)))
	ABORT(R_NO_MEMORY);
      
      if(!new){
	new=tmp;
	ptr=new;
      }
      else{
	ptr->next=tmp;
	tmp->prev=ptr;
	ptr=tmp;
      }

      ptr->destroy=old->destroy;
      ptr->copy=old->copy;
	
      if(old->copy){
	if(r=old->copy(&ptr->data,old->data))
	  ABORT(r);
      }
      else
	ptr->data=old->data;

      if(!(ptr->key=(char *)malloc(old->key_len)))
	ABORT(R_NO_MEMORY);
      memcpy(ptr->key,old->key,ptr->key_len=old->key_len);
    }

    *newp=new;
    
    _status=0;
  abort:
    if(_status){
      destroy_assoc_chain(new);
    }
    return(_status);
  }

static int r_assoc_fetch_bucket(assoc,key,len,bucketp)
  r_assoc *assoc;
  char *key;
  int len;
  r_assoc_el **bucketp;
  {
    UINT4 hash_value;
    r_assoc_el *bucket;
    
    hash_value=hash_compute(key,len,assoc->bits);

    for(bucket=assoc->chains[hash_value];bucket;bucket=bucket->next){
      if(bucket->key_len == len && !memcmp(bucket->key,key,len)){
	*bucketp=bucket;
	return(0);
      }
    }

    return(R_NOT_FOUND);
  }

int r_assoc_fetch(assoc,key,len,datap)
  r_assoc *assoc;
  char *key;
  int len;
  void **datap;
  {
    r_assoc_el *bucket;
    int r;

    if(r=r_assoc_fetch_bucket(assoc,key,len,&bucket)){
      if(r!=R_NOT_FOUND)
	ERETURN(r);
      return(r);
    }

    *datap=bucket->data;
    return(0);
  }

int r_assoc_insert(assoc,key,len,data,copy,destroy,how)
  r_assoc *assoc;
  char *key;
  int len;
  void *data;
  int (*copy) PROTO_LIST((void **new,void *old));
  int (*destroy) PROTO_LIST((void *ptr));
  int how;
  {
    r_assoc_el *bucket,*new_bucket=0;
    int r,_status;
    
    if(r=r_assoc_fetch_bucket(assoc,key,len,&bucket)){
      /*Note that we compute the hash value twice*/
      UINT4 hash_value;

      if(r!=R_NOT_FOUND)
	ABORT(r);
      hash_value=hash_compute(key,len,assoc->bits);
    
      if(!(new_bucket=(r_assoc_el *)calloc(sizeof(r_assoc_el),1)))
	ABORT(R_NO_MEMORY);
      if(!(new_bucket->key=(char *)malloc(len)))
	ABORT(R_NO_MEMORY);
      memcpy(new_bucket->key,key,len);
      new_bucket->key_len=len;
      
      /*Insert at the list head. Is FIFO a good algorithm?*/
      if(assoc->chains[hash_value])
        assoc->chains[hash_value]->prev=new_bucket;
      new_bucket->next=assoc->chains[hash_value];
      assoc->chains[hash_value]=new_bucket;
      bucket=new_bucket;
    }
    else{
      if(!(how&R_ASSOC_REPLACE))
	ABORT(R_ALREADY);

      if(bucket->destroy)
	bucket->destroy(bucket->data);
    }

    bucket->data=data;
    bucket->copy=copy;
    bucket->destroy=destroy;
    
    _status=0;
  abort:
    if(_status && new_bucket){
      free(new_bucket->key);
      free(new_bucket);
    }
    return(_status);
  }

int r_assoc_copy(newp,old)
  r_assoc **newp;
  r_assoc *old;
  {
    int r,_status,i;
    r_assoc *new;
    
    if(!(new=(r_assoc *)calloc(sizeof(r_assoc),1)))
      ABORT(r);
    new->size=old->size;
    new->bits=old->bits;
    
    if(!(new->chains=(r_assoc_el **)calloc(sizeof(r_assoc_el),old->size)))
      ABORT(R_NO_MEMORY);
    for(i=0;i<new->size;i++){
      if(r=copy_assoc_chain(new->chains+i,old->chains[i]))
	ABORT(r);
    }
    *newp=new;
    
    _status=0;
  abort:
    if(_status){
      r_assoc_destroy(&new);
    }
    return(_status);
  }

int r_assoc_init_iter(assoc,iter)
  r_assoc *assoc;
  r_assoc_iterator *iter;
  {
    int i;
    
    iter->assoc=assoc;
    iter->prev_chain=-1;
    iter->prev=0;

    iter->next_chain=assoc->size;
    iter->next=0;
    
    for(i=0;i<assoc->size;i++){
      if(assoc->chains[i]!=0){
	iter->next_chain=i;
	iter->next=assoc->chains[i];
	break;
      }
    }

    return(0);
  }

int r_assoc_iter(iter,key,keyl,val)
  r_assoc_iterator *iter;
  void **key;
  int *keyl;
  void **val;
  {
    int i;
    r_assoc_el *ret;
    
    if(!iter->next)
      return(R_EOD);
    ret=iter->next;

    *key=ret->key;
    *keyl=ret->key_len;
    *val=ret->data;
    
    /* Now increment */
    iter->prev_chain=iter->next_chain;
    iter->prev=iter->next;

    /* More on this chain */
    if(iter->next->next){
      iter->next=iter->next->next;
    }
    else{
      iter->next=0;
      
      /* FInd the next occupied chain*/
      for(i=iter->next_chain;i<iter->assoc->size;i++){
	if(iter->assoc->chains[i]){
	  iter->next_chain=i;
	  iter->next=iter->assoc->chains[i];
	  break;
	}
      }
    }

    return(0);
  }

/* Delete the last returned value*/
int r_assoc_iter_delete(iter)
  r_assoc_iterator *iter;
  {
    /* First unhook it from the list*/
    if(!iter->prev->prev){
      /* First element*/
      iter->assoc->chains[iter->prev_chain]=iter->prev->next;
    }
    else{
      iter->prev->prev->next=iter->prev->next;
    }

    if(iter->prev->next){
      iter->prev->next->prev=iter->prev->prev;
    }

    iter->prev->destroy(iter->prev->data);
    free(iter->prev->data);
    free(iter->prev);
    return(0);
  }
    
    
/*This is a hack from AMS. Supposedly, it's pretty good for strings, even
 though it doesn't take into account all the data*/
UINT4 hash_compute(key,len,bits)
  char *key;
  int len;
  int bits;
  {
    UINT4 h=0;

    h=key[0] +(key[len-1] * len);

    h &= (1<<bits) - 1;

    return(h);
  }

