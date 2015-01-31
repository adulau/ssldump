#include "network.h"
#include "ssl.h"
#include "sslprint.h"
static int decode_ContentType_change_cipher_spec(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_ContentType_alert(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_ContentType_handshake(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


    extern decoder HandshakeType_decoder[];
    int r;
    UINT4 t,l;

    SSL_DECODE_UINT8(ssl,0,0,data,&t);
    SSL_DECODE_UINT24(ssl,0,0,data,&l);

    if(data->len!=l){
      fprintf(stderr,"Error: short handshake length: expected %d got %d\n",
        l,data->len);
      ERETURN(R_EOD);
    }
      
    ssl_decode_switch(ssl,HandshakeType_decoder,t,dir,seg,data);

  }
static int decode_ContentType_application_data(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
decoder ContentType_decoder[]={
	{
		20,
		"change_cipher_spec",
		decode_ContentType_change_cipher_spec
	},
	{
		21,
		"alert",
		decode_ContentType_alert
	},
	{
		22,
		"handshake",
		decode_ContentType_handshake
	},
	{
		23,
		"application_data",
		decode_ContentType_application_data
	},
{0}
};

static int decode_HandshakeType_hello_request(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_HandshakeType_client_hello(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


    UINT4 vj,vn,cs,cslen,complen,comp;
    Data session_id,random;
    int r;

    extern decoder cipher_suite_decoder[];
    extern decoder compression_method_decoder[];    
    
    SSL_DECODE_UINT8(ssl,0,0,data,&vj);
    SSL_DECODE_UINT8(ssl,0,0,data,&vn);    

    P_(P_ND) {explain(ssl,"Client version %d.%d ",vj,vn);}

    printf("\n");
    SSL_DECODE_OPAQUE_ARRAY(ssl,"random",32,P_ND,data,&random);
    SSL_DECODE_OPAQUE_ARRAY(ssl,"session_id",-32,0,data,&session_id);

    if(session_id.len)
      exdump(ssl,"resume ",&session_id);

    SSL_DECODE_UINT16(ssl,"cipher Suites len",0,data,&cslen);
    explain(ssl,"cipher suites\n");
    
    for(;cslen;cslen-=2){
      SSL_DECODE_ENUM(ssl,0,2,cipher_suite_decoder,
        P_HL,data,&cs);
      printf("\n");
    }

    SSL_DECODE_UINT8(ssl,"compressionMethod len",0,data,&complen);
    if(complen){
      explain(ssl,"compression methods\n");
      for(;complen;complen--){
        SSL_DECODE_ENUM(ssl,0,1,compression_method_decoder,P_HL,data,&comp);
        printf("\n");
      }
    }
    return(0);

  }
static int decode_HandshakeType_server_hello(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


    int r;

    UINT4 vj,vn;
    
    SSL_DECODE_UINT8(ssl,0,0,data,&vj);
    SSL_DECODE_UINT8(ssl,0,0,data,&vn);    

    P_(P_ND) {explain(ssl,"SSL version %d.%d ",vj,vn);}
    SSL_DECODE_OPAQUE_ARRAY(ssl,"random",32,P_ND,data,0);
    SSL_DECODE_OPAQUE_ARRAY(ssl,"session_id",32,P_ND,data,0);
    SSL_DECODE_ENUM(ssl,0,2,cipher_suite_decoder,
      P_HL,data,0);
    SSL_DECODE_ENUM(ssl,0,1,compression_method_decoder,P_HL,data,0);

    return(0);

  }
static int decode_HandshakeType_certificate(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_HandshakeType_server_key_exchange(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_HandshakeType_certificate_request(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_HandshakeType_server_hello_done(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_HandshakeType_certificate_verify(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_HandshakeType_client_key_exchange(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_HandshakeType_finished(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
decoder HandshakeType_decoder[]={
	{
		0,
		"hello_request",
		decode_HandshakeType_hello_request
	},
	{
		1,
		"client_hello",
		decode_HandshakeType_client_hello
	},
	{
		2,
		"server_hello",
		decode_HandshakeType_server_hello
	},
	{
		11,
		"certificate",
		decode_HandshakeType_certificate
	},
	{
		12,
		"server_key_exchange",
		decode_HandshakeType_server_key_exchange
	},
	{
		13,
		"certificate_request",
		decode_HandshakeType_certificate_request
	},
	{
		14,
		"server_hello_done",
		decode_HandshakeType_server_hello_done
	},
	{
		15,
		"certificate_verify",
		decode_HandshakeType_certificate_verify
	},
	{
		16,
		"client_key_exchange",
		decode_HandshakeType_client_key_exchange
	},
	{
		20,
		"finished",
		decode_HandshakeType_finished
	},
{0}
};

decoder cipher_suite_decoder[]={
	{
		1,
		"TLS_RSA_WITH_NULL_MD5",
		0	},
	{
		2,
		"TLS_RSA_WITH_NULL_SHA",
		0	},
	{
		3,
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
		0	},
	{
		4,
		"TLS_RSA_WITH_RC4_128_MD5",
		0	},
	{
		5,
		"TLS_RSA_WITH_RC4_128_SHA",
		0	},
	{
		6,
		"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
		0	},
	{
		7,
		"TLS_RSA_WITH_IDEA_CBC_SHA",
		0	},
	{
		8,
		"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
		0	},
	{
		9,
		"TLS_RSA_WITH_DES_CBC_SHA",
		0	},
	{
		10,
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		11,
		"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
		0	},
	{
		12,
		"TLS_DH_DSS_WITH_DES_CBC_SHA",
		0	},
	{
		13,
		"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		14,
		"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
		0	},
	{
		15,
		"TLS_DH_RSA_WITH_DES_CBC_SHA",
		0	},
	{
		16,
		"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		17,
		"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
		0	},
	{
		18,
		"TLS_DHE_DSS_WITH_DES_CBC_SHA",
		0	},
	{
		19,
		"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		20,
		"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
		0	},
	{
		21,
		"TLS_DHE_RSA_WITH_DES_CBC_SHA",
		0	},
	{
		22,
		"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		23,
		"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
		0	},
	{
		24,
		"TLS_DH_anon_WITH_RC4_128_MD5",
		0	},
	{
		25,
		"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
		0	},
	{
		26,
		"TLS_DH_anon_WITH_DES_CBC_SHA",
		0	},
	{
		27,
		"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
		0	},
{-1}
};

decoder compression_method_decoder[]={
	{
		7,
		"NULL",
		0	},
{-1}
};

