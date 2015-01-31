#include "network.h"
#include "ssl_h.h"
#include "sslprint.h"
#include "sslxprint.h"
#ifdef OPENSSL
#include <openssl/ssl.h>
#endif
#include "ssl.enums.h"
static int decode_ContentType_ChangeCipherSpec(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


    ssl_process_change_cipher_spec(ssl,ssl->decoder,dir);

    if(dir==DIR_I2R){
      ssl->i_state=SSL_ST_SENT_CHANGE_CIPHER_SPEC;
    }
    else{
      ssl->r_state=SSL_ST_SENT_CHANGE_CIPHER_SPEC;
    }
    
    printf("\n");
    return(0);

  }
static int decode_ContentType_Alert(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {

 
   int r;

   if(ssl->record_encryption==REC_CIPHERTEXT){
     printf("\n");
     return(0);
   }

   if(data->len!=2){
	fprintf(stderr,"Wrong length for alert message: %d\n",
	data->len);
	ERETURN(R_EOD);
   }

   P_(P_HL){
      printf("\n");
      SSL_DECODE_ENUM(ssl,"level",1,AlertLevel_decoder,P_HL,data,0);
      printf("\n");
      SSL_DECODE_ENUM(ssl,"value",1,AlertDescription_decoder,P_HL,data,0);
      printf("\n");
   }
   else {
         SSL_DECODE_ENUM(ssl,0,1,AlertLevel_decoder,SSL_PRINT_ALL,data,0);
         SSL_DECODE_ENUM(ssl,0,1,AlertDescription_decoder,SSL_PRINT_ALL,data,0);
	 printf("\n");
   }
   return(0);
	

  }
static int decode_ContentType_Handshake(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


    extern decoder HandshakeType_decoder[];
    int r;
    UINT4 t,l;
    int rs=0;
    Data d;	

    if(ssl->record_encryption==REC_CIPHERTEXT){
      printf("\n");
      return(0);
    }

    while(data->len>0){
      SSL_DECODE_UINT8(ssl,0,0,data,&t);
      SSL_DECODE_UINT24(ssl,0,0,data,&l);
	
      if(data->len<l){
        fprintf(stderr,"Error: short handshake length: expected %d got %d\n",
        l,data->len);
        ERETURN(R_EOD);
      }
	
      d.data=data->data;
      d.len=l;
      data->len-=l;
      data->data+=l;	
      P_(P_HL){
	if(!rs){
	  printf("\n");
	  rs=1;
	}
      }
      ssl_decode_switch(ssl,HandshakeType_decoder,t,dir,seg,&d);
     }
     return(0);

  }
static int decode_ContentType_application_data(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {

  
    int r;
    Data d;
    		
    SSL_DECODE_OPAQUE_ARRAY(ssl,"data",data->len,0,data,&d);

    P_(P_AD){	
	    print_data(ssl,&d);
    }
    else {
	printf("\n");
    }      
    return(0);

  }
decoder ContentType_decoder[]={
	{
		20,
		"ChangeCipherSpec",
		decode_ContentType_ChangeCipherSpec
	},
	{
		21,
		"Alert",
		decode_ContentType_Alert
	},
	{
		22,
		"Handshake",
		decode_ContentType_Handshake
	},
	{
		23,
		"application_data",
		decode_ContentType_application_data
	},
{0}
};

static int decode_HandshakeType_HelloRequest(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


  printf("\n");

  }
static int decode_HandshakeType_ClientHello(ssl,dir,seg,data)
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
	
    printf("\n");			    
    SSL_DECODE_UINT8(ssl,0,0,data,&vj);
    SSL_DECODE_UINT8(ssl,0,0,data,&vn);    

    P_(P_HL) {explain(ssl,"Version %d.%d ",vj,vn);
        printf("\n");
   }

    SSL_DECODE_OPAQUE_ARRAY(ssl,"random",32,P_ND,data,&random);
    ssl_set_client_random(ssl->decoder,random.data,random.len);

    SSL_DECODE_OPAQUE_ARRAY(ssl,"session_id",-32,0,data,&session_id);
    ssl_set_client_session_id(ssl->decoder,session_id.data,session_id.len);

    P_(P_HL){
      if(session_id.len)
        exdump(ssl,"resume ",&session_id);
    }

    P_(P_HL){
	SSL_DECODE_UINT16(ssl,"cipher Suites len",0,data,&cslen);
        explain(ssl,"cipher suites\n");
    
	    for(;cslen;cslen-=2){
	      ssl_decode_enum(ssl,0,2,cipher_suite_decoder,
	        0,data,&cs);
	      ssl_print_cipher_suite(ssl,(vj<<8)|vn,P_HL,cs);
	      printf("\n");
	    }
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
static int decode_HandshakeType_ServerHello(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


    int r;
    Data rnd,session_id;	
    UINT4 vj,vn;
    printf("\n");			        
    SSL_DECODE_UINT8(ssl,0,0,data,&vj);
    SSL_DECODE_UINT8(ssl,0,0,data,&vn);    

    ssl->version=vj*256+vn;	        
    P_(P_HL) {explain(ssl,"Version %d.%d ",vj,vn);
        printf("\n");
   }
    	 
	       
    SSL_DECODE_OPAQUE_ARRAY(ssl,"random",32,P_ND,data,&rnd);
    ssl_set_server_random(ssl->decoder,rnd.data,rnd.len);
    SSL_DECODE_OPAQUE_ARRAY(ssl,"session_id",-32,P_HL,data,&session_id);
    SSL_DECODE_ENUM(ssl,"cipherSuite",2,cipher_suite_decoder,
      0,data,&ssl->cipher_suite);
    P_(P_HL){
     explain(ssl,"cipherSuite ");
     ssl_print_cipher_suite(ssl,ssl->version,P_HL,ssl->cipher_suite);      
    }
    ssl_find_cipher(ssl->cipher_suite,&ssl->cs);

    ssl_process_server_session_id(ssl,ssl->decoder,session_id.data,
      session_id.len);

    P_(P_HL) printf("\n");
    SSL_DECODE_ENUM(ssl,"compressionMethod",1,compression_method_decoder,P_HL,data,0);
    P_(P_HL) printf("\n");					
    return(0);

  }
static int decode_HandshakeType_Certificate(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


    UINT4 len;
    Data cert;
    int r;
  
    printf("\n");
    SSL_DECODE_UINT24(ssl,"certificates len",0,data,&len);

    while(len){
      SSL_DECODE_OPAQUE_ARRAY(ssl,"certificate",-((1<<23)-1),
        0,data,&cert);
      sslx_print_certificate(ssl,&cert,P_ND);
      len-=(cert.len + 3);
    }

    return(0);

  }
static int decode_HandshakeType_ServerKeyExchange(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


   int r;

    printf("\n");			      

   if(ssl->cs){
     P_(P_ND){
	explain(ssl,"params\n");
     }
     INDENT_INCR;

     switch(ssl->cs->kex){
	case KEX_DH:
	  SSL_DECODE_OPAQUE_ARRAY(ssl,"DH_p",-((1<<15)-1),P_ND,data,0);
	  SSL_DECODE_OPAQUE_ARRAY(ssl,"DH_g",-((1<<15)-1),P_ND,data,0);	  
	  SSL_DECODE_OPAQUE_ARRAY(ssl,"DH_Ys",-((1<<15)-1),P_ND,data,0);	  
	  break;
	case KEX_RSA:
	  SSL_DECODE_OPAQUE_ARRAY(ssl,"RSA_modulus",-((1<<15)-1),P_ND,data,0);
	  SSL_DECODE_OPAQUE_ARRAY(ssl,"RSA_exponent",-((1<<15)-1),P_ND,data,0);
	  break;
      }
      INDENT_POP;
      SSL_DECODE_OPAQUE_ARRAY(ssl,"signature",-((1<<15)-1),P_ND,data,0);
   }
     
   return(0);

  }
static int decode_HandshakeType_CertificateRequest(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


    UINT4 len;
    Data ca;
    int r;
    
    printf("\n");
    SSL_DECODE_UINT8(ssl,"certificate_types len",0,data,&len);
    for(;len;len--){
      SSL_DECODE_ENUM(ssl,"certificate_types",1,
        client_certificate_type_decoder, P_HL,data,0);
      P_(P_HL){
	printf("\n");
      }
    };

    SSL_DECODE_UINT16(ssl,"certificate_authorities len",0,data,&len);
    while(len){
      SSL_DECODE_OPAQUE_ARRAY(ssl,"certificate_authorities",
        -((1<<15)-1),0,data,&ca); 
      explain(ssl,"certificate_authority\n");
      INDENT_INCR;
      sslx_print_dn(ssl,&ca,P_HL);
      INDENT_POP;
      len-=(ca.len + 2);
    }
    return(0);

  }
static int decode_HandshakeType_ServerHelloDone(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


  printf("\n");

  }
static int decode_HandshakeType_CertificateVerify(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


  int r;
  printf("\n");
  SSL_DECODE_OPAQUE_ARRAY(ssl,"Signature",-(1<<15-1),P_HL,data,0);
  return(0);

  }
static int decode_HandshakeType_ClientKeyExchange(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


   int r;
   Data pms;
	
    printf("\n");
   if(ssl->cs){
     switch(ssl->cs->kex){

	case KEX_RSA:
	   if(ssl->version > 768) {
	           SSL_DECODE_OPAQUE_ARRAY(ssl,"EncryptedPreMasterSecret",-(1<<15-1),
	             P_ND,data,&pms);
		     
	        }
	        else {
	           SSL_DECODE_OPAQUE_ARRAY(ssl,"EncryptedPreMasterSecret",data->len,P_ND,data,&pms);   
	        }
	        ssl_process_client_key_exchange(ssl,
	        ssl->decoder,pms.data,pms.len);

            break;
        case KEX_DH:
            SSL_DECODE_OPAQUE_ARRAY(ssl,"DiffieHellmanClientPublicValue",
	        -(1<<15-1),P_HL,data,0);
      }
   }
   return(0);

  }
static int decode_HandshakeType_Finished(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


   int r;

    printf("\n");   
   switch(ssl->version){
     case 0x300:
       SSL_DECODE_OPAQUE_ARRAY(ssl,"md5_hash",16,P_ND,data,0);

       SSL_DECODE_OPAQUE_ARRAY(ssl,"sha_hash",20,P_ND,data,0);
       break;
     case 0x301:
       SSL_DECODE_OPAQUE_ARRAY(ssl,"verify_data",12,P_ND,data,0);
	P_(P_ND)
	  printf("\n");
       break;
   }

   return (0);

  }
decoder HandshakeType_decoder[]={
	{
		0,
		"HelloRequest",
		decode_HandshakeType_HelloRequest
	},
	{
		1,
		"ClientHello",
		decode_HandshakeType_ClientHello
	},
	{
		2,
		"ServerHello",
		decode_HandshakeType_ServerHello
	},
	{
		11,
		"Certificate",
		decode_HandshakeType_Certificate
	},
	{
		12,
		"ServerKeyExchange",
		decode_HandshakeType_ServerKeyExchange
	},
	{
		13,
		"CertificateRequest",
		decode_HandshakeType_CertificateRequest
	},
	{
		14,
		"ServerHelloDone",
		decode_HandshakeType_ServerHelloDone
	},
	{
		15,
		"CertificateVerify",
		decode_HandshakeType_CertificateVerify
	},
	{
		16,
		"ClientKeyExchange",
		decode_HandshakeType_ClientKeyExchange
	},
	{
		20,
		"Finished",
		decode_HandshakeType_Finished
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
	{
		96,
		"TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
		0	},
	{
		97,
		"TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",
		0	},
	{
		98,
		"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
		0	},
	{
		99,
		"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
		0	},
	{
		100,
		"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
		0	},
	{
		101,
		"TLS_DHE_DSS_WITH_RC2_56_CBC_SHA",
		0	},
	{
		102,
		"TLS_DHE_DSS_WITH_RC4_128_SHA",
		0	},
	{
		103,
		"TLS_DHE_DSS_WITH_NULL_SHA",
		0	},
	{
		65664,
		"SSL2_CK_RC4",
		0	},
	{
		131200,
		"SSL2_CK_RC4_EXPORT40",
		0	},
	{
		196736,
		"SSL2_CK_RC2",
		0	},
	{
		262272,
		"SSL2_CK_RC2_EXPORT40",
		0	},
	{
		327808,
		"SSL2_CK_IDEA",
		0	},
	{
		393280,
		"SSL2_CK_DES",
		0	},
	{
		524416,
		"SSL2_CK_RC464",
		0	},
	{
		458944,
		"SSL2_CK_3DES",
		0	},
	{
		74,
		"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		72,
		"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
		0	},
	{
		65408,
		"SSL_RSA_WITH_RC2_CBC_MD5",
		0	},
	{
		73,
		"TLS_ECDH_ECDSA_WITH_DES_CBC_SHA",
		0	},
	{
		65413,
		"TLS_ECDH_ECDSA_EXPORT_WITH_RC4_56_SHA",
		0	},
	{
		65412,
		"TLS_ECDH_ECDSA_EXPORT_WITH_RC4_40_SHA",
		0	},
{-1}
};

static int decode_AlertLevel_warning(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertLevel_fatal(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
decoder AlertLevel_decoder[]={
	{
		1,
		"warning",
		decode_AlertLevel_warning
	},
	{
		2,
		"fatal",
		decode_AlertLevel_fatal
	},
{0}
};

static int decode_AlertDescription_close_notify(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_unexpected_message(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_bad_record_mac(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_decryption_failed(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_record_overflow(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_decompression_failure(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_handshake_failure(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_bad_certificate(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_unsupported_certificate(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_certificate_revoked(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_certificate_expired(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_certificate_unknown(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_illegal_parameter(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_unknown_ca(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_access_denied(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_decode_error(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_decrypt_error(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_export_restriction(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_protocol_version(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_insufficient_security(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_internal_error(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_user_canceled(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_AlertDescription_no_renegotiation(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
decoder AlertDescription_decoder[]={
	{
		0,
		"close_notify",
		decode_AlertDescription_close_notify
	},
	{
		10,
		"unexpected_message",
		decode_AlertDescription_unexpected_message
	},
	{
		20,
		"bad_record_mac",
		decode_AlertDescription_bad_record_mac
	},
	{
		21,
		"decryption_failed",
		decode_AlertDescription_decryption_failed
	},
	{
		22,
		"record_overflow",
		decode_AlertDescription_record_overflow
	},
	{
		30,
		"decompression_failure",
		decode_AlertDescription_decompression_failure
	},
	{
		40,
		"handshake_failure",
		decode_AlertDescription_handshake_failure
	},
	{
		42,
		"bad_certificate",
		decode_AlertDescription_bad_certificate
	},
	{
		43,
		"unsupported_certificate",
		decode_AlertDescription_unsupported_certificate
	},
	{
		44,
		"certificate_revoked",
		decode_AlertDescription_certificate_revoked
	},
	{
		45,
		"certificate_expired",
		decode_AlertDescription_certificate_expired
	},
	{
		46,
		"certificate_unknown",
		decode_AlertDescription_certificate_unknown
	},
	{
		47,
		"illegal_parameter",
		decode_AlertDescription_illegal_parameter
	},
	{
		48,
		"unknown_ca",
		decode_AlertDescription_unknown_ca
	},
	{
		49,
		"access_denied",
		decode_AlertDescription_access_denied
	},
	{
		50,
		"decode_error",
		decode_AlertDescription_decode_error
	},
	{
		51,
		"decrypt_error",
		decode_AlertDescription_decrypt_error
	},
	{
		60,
		"export_restriction",
		decode_AlertDescription_export_restriction
	},
	{
		70,
		"protocol_version",
		decode_AlertDescription_protocol_version
	},
	{
		71,
		"insufficient_security",
		decode_AlertDescription_insufficient_security
	},
	{
		80,
		"internal_error",
		decode_AlertDescription_internal_error
	},
	{
		90,
		"user_canceled",
		decode_AlertDescription_user_canceled
	},
	{
		100,
		"no_renegotiation",
		decode_AlertDescription_no_renegotiation
	},
{0}
};

decoder compression_method_decoder[]={
	{
		0,
		"NULL",
		0	},
{-1}
};

static int decode_client_certificate_type_rsa_sign(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_client_certificate_type_dss_sign(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_client_certificate_type_rsa_fixed_dh(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
static int decode_client_certificate_type_dss_fixed_dh(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
	return(0);
  }
decoder client_certificate_type_decoder[]={
	{
		1,
		"rsa_sign",
		decode_client_certificate_type_rsa_sign
	},
	{
		2,
		"dss_sign",
		decode_client_certificate_type_dss_sign
	},
	{
		3,
		"rsa_fixed_dh",
		decode_client_certificate_type_rsa_fixed_dh
	},
	{
		4,
		"dss_fixed_dh",
		decode_client_certificate_type_dss_fixed_dh
	},
{0}
};

