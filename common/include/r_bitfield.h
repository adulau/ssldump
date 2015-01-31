/**
   r_bitfield.h

   Copyright (C) 2001 RTFM, Inc.
   All Rights Reserved.

   ekr@rtfm.com  Wed Oct  3 10:43:50 2001
 */


#ifndef _r_bitfield_h
#define _r_bitfield_h

typedef struct r_bitfield_ {
     UINT4 *data;
     UINT4 len;
     UINT4 base;
} r_bitfield;

int r_bitfield_set PROTO_LIST((r_bitfield *,int bit));
int r_bitfield_isset PROTO_LIST((r_bitfield *,int bit));
int r_bitfield_create PROTO_LIST((r_bitfield **setp,UINT4 size));
int r_bitfield_destroy PROTO_LIST((r_bitfield **setp));

#endif

