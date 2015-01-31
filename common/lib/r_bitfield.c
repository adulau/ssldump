/**
   r_bitfield.c

   Copyright (C) 2001 RTFM, Inc.
   All Rights Reserved.

   ekr@rtfm.com  Wed Oct  3 11:15:23 2001
 */


static char *RCSSTRING="$Id: r_bitfield.c,v 1.3 2001/12/24 06:06:26 ekr Exp $";

#include <r_common.h>
#include "r_bitfield.h"

int r_bitfield_create(setp,size)
  r_bitfield **setp;
  UINT4 size;
  {
    r_bitfield *set=0;
    int _status;
    int num_words=size/32+!!(size%32);
    
    if(!(set=(r_bitfield *)RMALLOC(sizeof(r_bitfield))))
      ABORT(R_NO_MEMORY);

    if(!(set->data=(UINT4 *)RMALLOC(num_words*4)))
      ABORT(R_NO_MEMORY);
    memset(set->data,0,4*num_words);
    
    set->base=0;
    set->len=num_words;

    *setp=set;
    
    _status=0;
  abort:
    if(_status){
      r_bitfield_destroy(&set);
    }
    return(_status);
  }

int r_bitfield_destroy(setp)
  r_bitfield **setp;
  {
    r_bitfield *set;
    
    if(!setp || !*setp)
      return(0);

    set=*setp;

    RFREE(set->data);
    RFREE(set);

    *setp=0;
    return(0);
  }

int r_bitfield_set(set,bit)
  r_bitfield *set;
  int bit;
  {
    int word=(bit-set->base)/32;
    int bbit=(bit-set->base)%32;
    int _status;

    /* Resize? */
    if(word>set->len){
      UINT4 newlen=set->len;
      UINT4 *tmp;
      
      while(newlen<word)
	newlen*=2;
      
      if(!(tmp=(UINT4 *)RMALLOC(newlen)))
	ABORT(R_NO_MEMORY);
      
      memcpy(tmp,set->data,set->len*4);
      memset(tmp+set->len*4,0,(newlen-set->len)*4);

      RFREE(set->data);
      set->data=tmp;
    }

    set->data[word]|=1<<bbit;

    _status=0;
  abort:
    return(_status);
  }

int r_bitfield_isset(set,bit)
  r_bitfield *set;
  int bit;
  {
    int word=(bit-set->base)/32;
    int bbit=(bit-set->base)%32;
    int _status;

    if(bit<set->base)
      return(0);

    /* Resize? */
    if(word>set->len)
      return(0);

    return(set->data[word]&(1<<bbit));

    _status=0;
    return(_status);
  }
