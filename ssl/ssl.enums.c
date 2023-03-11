#include <json-c/json.h>
#include <openssl/md5.h>
#include "network.h"
#include "ssl_h.h"
#include "sslprint.h"
#include "sslxprint.h"
#ifdef OPENSSL
#include <openssl/ssl.h>
#endif
#include "ssl.enums.h"
static int decode_extension(ssl_obj *ssl, int dir, segment *seg, Data *data);
static int decode_server_name(ssl_obj *ssl, int dir, segment *seg, Data *data);
static int decode_ContentType_ChangeCipherSpec(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {

    struct json_object *jobj;

    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "msg_type", json_object_new_string("ChangeCipherSpec"));

    ssl_process_change_cipher_spec(ssl,ssl->decoder,dir);

    if(dir==DIR_I2R){
      ssl->i_state=SSL_ST_SENT_CHANGE_CIPHER_SPEC;
    }
    else{
      ssl->r_state=SSL_ST_SENT_CHANGE_CIPHER_SPEC;
    }

    LF;
    return(0);

  }
static int decode_ContentType_Alert(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {

   int r;
   struct json_object *jobj;

   if(ssl->record_encryption==REC_CIPHERTEXT){
     LF;
     return(0);
   }

   if(data->len!=2){
	fprintf(stderr,"Wrong length for alert message: %d\n",
	data->len);
	ERETURN(R_EOD);
   }

   jobj = ssl->cur_json_st;
   json_object_object_add(jobj, "msg_type", json_object_new_string("Alert"));

   P_(P_HL){
      LF;
      SSL_DECODE_ENUM(ssl,"level",1,AlertLevel_decoder,P_HL,data,0);
      LF;
      SSL_DECODE_ENUM(ssl,"value",1,AlertDescription_decoder,P_HL,data,0);
      LF;
   }
   else {
         SSL_DECODE_ENUM(ssl,0,1,AlertLevel_decoder,SSL_PRINT_ALL,data,0);
         SSL_DECODE_ENUM(ssl,0,1,AlertDescription_decoder,SSL_PRINT_ALL,data,0);
	 LF;
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
    struct json_object *jobj;

    if(ssl->record_encryption==REC_CIPHERTEXT){
      LF;
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

      jobj = ssl->cur_json_st;
      json_object_object_add(jobj, "msg_type", json_object_new_string("Handshake"));

      d.data=data->data;
      d.len=l;
      data->len-=l;
      data->data+=l;
      P_(P_HL){
	if(!rs){
	  LF;
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
    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "msg_type", json_object_new_string("application data"));

    SSL_DECODE_OPAQUE_ARRAY(ssl,"data",data->len,0,data,&d);

    if(NET_print_flags & NET_PRINT_JSON) { 
    	json_object_object_add(jobj, "msg_data", json_object_new_string_len(d.data, d.len));
	} else P_(P_AD) {
	    print_data(ssl,&d);
    } else {
	LF;
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
{-1}
};

static int decode_HandshakeType_HelloRequest(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "handshake_type", json_object_new_string("HelloRequest"));


  LF;
  return(0);

  }
static int decode_HandshakeType_ClientHello(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "handshake_type", json_object_new_string("ClientHello"));

    UINT4 vj,vn,cs,cslen,complen,comp,odd,exlen,ex;
    Data session_id,random;
    int r;
    char *ja3_fp = NULL;
    char *ja3_str = NULL;
    char *ja3_ver_str = NULL;
    char *ja3_cs_str = NULL;
    char *ja3_ex_str = NULL;
    char *ja3_ec_str = NULL;
    char *ja3_ecp_str = NULL;

    ssl->cur_ja3_ec_str = NULL;
    ssl->cur_ja3_ecp_str = NULL;

    extern decoder cipher_suite_decoder[];
    extern decoder compression_method_decoder[];
    extern decoder extension_decoder[];

    LF;
    ssl_update_handshake_messages(ssl,data);
    SSL_DECODE_UINT8(ssl,0,0,data,&vj);
    SSL_DECODE_UINT8(ssl,0,0,data,&vn);

    ja3_ver_str = calloc(7,sizeof(char));
    snprintf(ja3_ver_str, 7, "%u", ((vj & 0xff) << 8) | (vn & 0xff));

    P_(P_HL) {explain(ssl,"Version %d.%d ",vj,vn);
        LF;
    }

    SSL_DECODE_OPAQUE_ARRAY(ssl,"random",32,P_ND,data,&random);
    ssl_set_client_random(ssl->decoder,random.data,random.len);

    SSL_DECODE_OPAQUE_ARRAY(ssl,"session_id",-32,0,data,&session_id);
    ssl_set_client_session_id(ssl->decoder,session_id.data,session_id.len);

    P_(P_HL){
      if(session_id.len)
        exdump(ssl,"resume ",&session_id);
    }

    ssl_process_client_session_id(ssl,ssl->decoder,session_id.data,
      session_id.len);

    P_(P_HL){
	SSL_DECODE_UINT16(ssl,"cipher Suites len",0,data,&cslen);
        explain(ssl,"cipher suites\n");

        odd = cslen % 2;
        if(odd) {
            printf("Wrong cipher suites length, fixing ...\n");
            cslen -= odd;
        }

	    for(;cslen;cslen-=2){
	      if(ssl_decode_enum(ssl,0,2,cipher_suite_decoder,
	        0,data,&cs))
                return(1);
	      ssl_print_cipher_suite(ssl,(vj<<8)|vn,P_HL,cs);
              if(!ja3_cs_str)
                  ja3_cs_str = calloc(7, 1);
              else
                  ja3_cs_str = realloc(ja3_cs_str, strlen(ja3_cs_str) + 7);

	      snprintf(ja3_cs_str + strlen(ja3_cs_str), 7, "%u-", cs);
	      LF;
	    }
	    if(ja3_cs_str && ja3_cs_str[strlen(ja3_cs_str) - 1] == '-')
		ja3_cs_str[strlen(ja3_cs_str) - 1] = '\0';
    }

    SSL_DECODE_UINT8(ssl,"compressionMethod len",0,data,&complen);
    if(complen){
      explain(ssl,"compression methods\n");
      for(;complen;complen--){
        SSL_DECODE_ENUM(ssl,0,1,compression_method_decoder,P_HL,data,&comp);
        LF;
      }
    }

    SSL_DECODE_UINT16(ssl,"extensions len",0,data,&exlen);
    if (exlen) {
      explain(ssl , "extensions\n");
      while(data->len) {
    	SSL_DECODE_UINT16(ssl, "extension type", 0, data, &ex);
        if(!ja3_ex_str)
            ja3_ex_str = calloc(7, 1);
        else
            ja3_ex_str = realloc(ja3_ex_str, strlen(ja3_ex_str) + 7);

	snprintf(ja3_ex_str + strlen(ja3_ex_str), 7, "%u-", ex);

    	if (ssl_decode_switch(ssl,extension_decoder,ex,dir,seg,data) == R_NOT_FOUND) {
	  decode_extension(ssl,dir,seg,data);
    	  P_(P_RH){
     	    explain(ssl, "Extension type: %u not yet implemented in ssldump\n", ex);
    	  }
    	  continue;
    	}
        LF;
      }
      if(ja3_ex_str && ja3_ex_str[strlen(ja3_ex_str) - 1] == '-')
          ja3_ex_str[strlen(ja3_ex_str) - 1] = '\0';
    }

    ja3_ec_str = ssl->cur_ja3_ec_str;
    ja3_ecp_str = ssl->cur_ja3_ecp_str;

    if(!ja3_ver_str) {
	ja3_ver_str = calloc(1, 1);
	*ja3_ver_str = '\0';
    }

    if(!ja3_cs_str) {
	ja3_cs_str = calloc(1, 1);
	*ja3_cs_str = '\0';
    }

    if(!ja3_ex_str) {
	ja3_ex_str = calloc(1, 1);
	*ja3_ex_str = '\0';
    }

    if(!ja3_ec_str) {
	ja3_ec_str = calloc(1, 1);
	*ja3_ec_str = '\0';
    }

    if(!ja3_ecp_str) {
	ja3_ecp_str = calloc(1, 1);
	*ja3_ecp_str = '\0';
    }

    int ja3_str_len =
	strlen(ja3_ver_str) + 1
	+ strlen(ja3_cs_str) + 1
	+ strlen(ja3_ex_str) + 1
	+ strlen(ja3_ec_str) + 1
	+ strlen(ja3_ecp_str) + 1;
    ja3_str = calloc(ja3_str_len, 1);
    snprintf(ja3_str, ja3_str_len, "%s,%s,%s,%s,%s",
	ja3_ver_str, ja3_cs_str, ja3_ex_str, ja3_ec_str, ja3_ecp_str);

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

    md = EVP_get_digestbyname("MD5");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, ja3_str, strlen(ja3_str));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    ja3_fp = calloc(33,1);
    *ja3_fp = '\0';
    for(i=0; i<16; i++) {
	snprintf(ja3_fp + strlen(ja3_fp), 3, "%02x", md_value[i]);
    }

    json_object_object_add(jobj, "ja3_str", json_object_new_string(ja3_str));
    json_object_object_add(jobj, "ja3_fp", json_object_new_string(ja3_fp));

    explain(ssl, "ja3 string: %s\n", ja3_str);
    explain(ssl, "ja3 fingerprint: %s\n", ja3_fp);

    free(ja3_fp);
    free(ja3_str);
    free(ja3_ver_str);
    free(ja3_cs_str);
    free(ja3_ex_str);
    free(ja3_ec_str);
    free(ja3_ecp_str);

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
    UINT4 vj,vn,exlen,ex;
    char *ja3s_fp = NULL;
    char *ja3s_str = NULL;
    char *ja3s_ver_str = NULL;
    char *ja3s_c_str = NULL;
    char *ja3s_ex_str = NULL;


    extern decoder extension_decoder[];

    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "handshake_type", json_object_new_string("ServerHello"));

    LF;
    ssl_update_handshake_messages(ssl,data);
    SSL_DECODE_UINT8(ssl,0,0,data,&vj);
    SSL_DECODE_UINT8(ssl,0,0,data,&vn);

    ja3s_ver_str = calloc(7,sizeof(char));
    snprintf(ja3s_ver_str, 7, "%u", ((vj & 0xff) << 8) | (vn & 0xff));

    ssl->version=vj*256+vn;
    P_(P_HL) {explain(ssl,"Version %d.%d ",vj,vn);
        LF;
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

    ja3s_c_str = calloc(6, 1);
    snprintf(ja3s_c_str, 6, "%u", ssl->cipher_suite);


    P_(P_HL) LF;
    SSL_DECODE_ENUM(ssl,"compressionMethod",1,compression_method_decoder,P_HL,data,0);
    P_(P_HL) LF;

    SSL_DECODE_UINT16(ssl,"extensions len",0,data,&exlen);
    if (exlen) {
      explain(ssl , "extensions\n");
      while(data->len) {
    	SSL_DECODE_UINT16(ssl, "extension type", 0, data, &ex);
        if(!ja3s_ex_str)
            ja3s_ex_str = calloc(7, 1);
        else
            ja3s_ex_str = realloc(ja3s_ex_str, strlen(ja3s_ex_str) + 7);

	snprintf(ja3s_ex_str + strlen(ja3s_ex_str), 7, "%u-", ex);

    	if (ssl_decode_switch(ssl,extension_decoder,ex,dir,seg,data) == R_NOT_FOUND) {
	  decode_extension(ssl,dir,seg,data);
    	  P_(P_RH){
    	    explain(ssl, "Extension type: %u not yet implemented in ssldump,\n", ex);
    	  }
    	  continue;
    	}
        LF;
      }
      if(ja3s_ex_str && ja3s_ex_str[strlen(ja3s_ex_str) - 1] == '-')
          ja3s_ex_str[strlen(ja3s_ex_str) - 1] = '\0';
    }

    if (ssl->version==TLSV13_VERSION){ 
	  // tls version is known in server hello for tls1.3 hence generate keying material here
      ssl_tls13_generate_keying_material(ssl,ssl->decoder);
    }

    ssl_process_server_session_id(ssl,ssl->decoder,session_id.data,
      session_id.len);

    if(!ja3s_ver_str) {
	ja3s_ver_str = calloc(1, 1);
	*ja3s_ver_str = '\0';
    }

    if(!ja3s_c_str) {
	ja3s_c_str = calloc(1, 1);
	*ja3s_c_str = '\0';
    }

    if(!ja3s_ex_str) {
	ja3s_ex_str = calloc(1, 1);
	*ja3s_ex_str = '\0';
    }

    int ja3s_str_len =
	strlen(ja3s_ver_str) + 1
	+ strlen(ja3s_c_str) + 1
	+ strlen(ja3s_ex_str) + 1;
    ja3s_str = calloc(ja3s_str_len, 1);
    snprintf(ja3s_str, ja3s_str_len, "%s,%s,%s",
	ja3s_ver_str, ja3s_c_str, ja3s_ex_str);

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

    md = EVP_get_digestbyname("MD5");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, ja3s_str, strlen(ja3s_str));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    ja3s_fp = calloc(33,1);
    *ja3s_fp = '\0';
    for(i=0; i<16; i++) {
	snprintf(ja3s_fp + strlen(ja3s_fp), 3, "%02x", md_value[i]);
    }

    json_object_object_add(jobj, "ja3s_str", json_object_new_string(ja3s_str));
    json_object_object_add(jobj, "ja3s_fp", json_object_new_string(ja3s_fp));

    explain(ssl, "ja3s string: %s\n", ja3s_str);
    explain(ssl, "ja3s fingerprint: %s\n", ja3s_fp);

    free(ja3s_fp);
    free(ja3s_str);
    free(ja3s_ver_str);
    free(ja3s_c_str);
    free(ja3s_ex_str);

    return(0);

  }
static int decode_HandshakeType_Certificate(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    UINT4 len,exlen,ex;
    Data cert;
    int r;

    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "handshake_type", json_object_new_string("Certificate"));
    extern decoder extension_decoder[];

    LF;
    ssl_update_handshake_messages(ssl,data);
    if (ssl->version==TLSV13_VERSION){
      SSL_DECODE_OPAQUE_ARRAY(ssl,"certificate request context",-((1<<7)-1),0, data, NULL);
    }
    SSL_DECODE_UINT24(ssl,"certificates len",0,data,&len);

    json_object_object_add(jobj, "cert_chain", json_object_new_array());

    while(len){
      SSL_DECODE_OPAQUE_ARRAY(ssl,"certificate",-((1<<23)-1),
        0,data,&cert);
      sslx_print_certificate(ssl,&cert,P_ND);
      len-=(cert.len + 3);
      if (ssl->version==TLSV13_VERSION) { // TLS 1.3 has certificates
        SSL_DECODE_UINT16(ssl,"certificate extensions len",0,data,&exlen);
        len-=2;
     	while (exlen) {
     	  SSL_DECODE_UINT16(ssl, "extension type", 0, data, &ex);
		  len -= (2+ex);
     	  if (ssl_decode_switch(ssl, extension_decoder, ex, dir, seg, data) == R_NOT_FOUND) {
     	    decode_extension(ssl, dir, seg, data);
     	    P_(P_RH) { explain(ssl, "Extension type: %u not yet implemented in ssldump\n", ex); }
     	    continue;
     	  }
     	  LF;
     	}
      }
    }

    return(0);

  }

static int decode_HandshakeType_SessionTicket(ssl,dir,seg,data)
    ssl_obj *ssl;
    int dir;
    segment *seg;
    Data *data;
{
    int r;
    UINT4 exlen, ex, val;
    extern decoder extension_decoder[];
										
    LF;
    SSL_DECODE_UINT32(ssl, "ticket_lifetime",0, data, &val);
    explain(ssl, "ticket_lifetime %u\n", val);
    SSL_DECODE_UINT32(ssl, "ticket_age_add", 0,data, &val);
    explain(ssl, "ticket_age_add %u\n", val);
    SSL_DECODE_UINT8(ssl, "ticket_nonce",0,data, &val);
    if (val>data->len) {
      fprintf(stderr, "Short read: %d bytes available (expecting %d)\n", data->len, val);
      ERETURN(R_EOD);
    }
    CRDUMP("ticket_nonce", data->data, val);
    data->data+=val;data->len-=val;
    SSL_DECODE_UINT16(ssl, "ticket",0,data, &val);
    if (val>data->len) {
      fprintf(stderr, "Short read: %d bytes available (expecting %d)\n", data->len, val);
      ERETURN(R_EOD);
    }
    CRDUMP("ticket", data->data, val);
    data->data+=val;data->len-=val;
    SSL_DECODE_UINT16(ssl, "exlen", 0, data, &exlen);
    LF;
    if (exlen) {
      while (data->len) {
        SSL_DECODE_UINT16(ssl, "extension type", 0, data, &ex);
        if (ssl_decode_switch(ssl, extension_decoder, ex, dir, seg, data) == R_NOT_FOUND) {
          decode_extension(ssl, dir, seg, data);
          P_(P_RH) { explain(ssl, "Extension type: %u not yet implemented in ssldump\n", ex); }
          continue;
        }
        LF;
      }
    }
}

static int decode_HandshakeType_EncryptedExtensions(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    int r;
    UINT4 exlen, ex;
    extern decoder extension_decoder[];
										
    SSL_DECODE_UINT16(ssl, 0, 0, data, &exlen);
    LF;
    if (exlen) {
      while (data->len) {
        SSL_DECODE_UINT16(ssl, "extension type", 0, data, &ex);
        if (ssl_decode_switch(ssl, extension_decoder, ex, dir, seg, data) == R_NOT_FOUND) {
          decode_extension(ssl, dir, seg, data);
          P_(P_RH) { explain(ssl, "Extension type: %u not yet implemented in ssldump\n", ex); }
          continue;
        }
        LF;
      }
    }
  }

static int decode_HandshakeType_ServerKeyExchange(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


   int r;

    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "handshake_type", json_object_new_string("ServerKeyExchange"));

    LF;
    ssl_update_handshake_messages(ssl,data);
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

    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "handshake_type", json_object_new_string("CertificateRequest"));

    LF;
    ssl_update_handshake_messages(ssl,data);
    SSL_DECODE_UINT8(ssl,"certificate_types len",0,data,&len);
    for(;len;len--){
      SSL_DECODE_ENUM(ssl,"certificate_types",1,
        client_certificate_type_decoder, P_HL,data,0);
      P_(P_HL){
	LF;
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

    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "handshake_type", json_object_new_string("ServerHelloDone"));

  LF;
  ssl_update_handshake_messages(ssl,data);
  return(0);

  }
static int decode_HandshakeType_CertificateVerify(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {


  int r;
  UINT4 signature_type;

    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "handshake_type", json_object_new_string("CertificateVerify"));

  LF;
  ssl_update_handshake_messages(ssl,data);
  if (ssl->version == TLSV13_VERSION) {
    SSL_DECODE_UINT16(ssl,"signature_type",P_HL,data,&signature_type);
  }
  SSL_DECODE_OPAQUE_ARRAY(ssl,"Signature",-((1<<15)-1),P_HL,data,0);
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

    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "handshake_type", json_object_new_string("ClientKeyExchange"));

    LF;
    ssl_update_handshake_messages(ssl,data);
   if(ssl->cs){
     switch(ssl->cs->kex){

	case KEX_RSA:
	   if(ssl->version > 768) {
	           SSL_DECODE_OPAQUE_ARRAY(ssl,"EncryptedPreMasterSecret",-((1<<15)-1),
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
				  -((1<<7)-1),P_HL,data,0);
	  ssl_process_client_key_exchange(ssl,
					  ssl->decoder,NULL,0);
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

    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "handshake_type", json_object_new_string("Finished"));

    LF;
   switch(ssl->version){
     case 0x300:
       SSL_DECODE_OPAQUE_ARRAY(ssl,"md5_hash",16,P_ND,data,0);

       SSL_DECODE_OPAQUE_ARRAY(ssl,"sha_hash",20,P_ND,data,0);
       break;
     case 0x301:
       SSL_DECODE_OPAQUE_ARRAY(ssl,"verify_data",12,P_ND,data,0);
	P_(P_ND)
	  LF;
       break;
   }

   ssl_process_handshake_finished(ssl,ssl->decoder,data);
   return (0);

  }

static int decode_HandshakeType_KeyUpdate(ssl,dir,seg,data)
	ssl_obj *ssl;
	int dir;
	segment *seg;
	Data *data;
{
    LF;
	ssl_tls13_update_keying_material(ssl, ssl->decoder, dir);
	return 0;
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
		4,
		"SessionTicket",
		decode_HandshakeType_SessionTicket
	},
	{
		8,
		"EncryptedExtensions",
		decode_HandshakeType_EncryptedExtensions
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
	{
		24,
		"KeyUpdate",
		decode_HandshakeType_KeyUpdate
	},
{-1}
};

decoder cipher_suite_decoder[]={
	// https://www.iana.org/assignments/tls-parameters/tls-parameters.txt
	{
		0,
		"TLS_NULL_WITH_NULL_NULL",
		0	},
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
		30,
		"TLS_KRB5_WITH_DES_CBC_SHA",
		0	},
	{
		31,
		"TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		32,
		"TLS_KRB5_WITH_RC4_128_SHA",
		0	},
	{
		33,
		"TLS_KRB5_WITH_IDEA_CBC_SHA",
		0	},
	{
		34,
		"TLS_KRB5_WITH_DES_CBC_MD5",
		0	},
	{
		35,
		"TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
		0	},
	{
		36,
		"TLS_KRB5_WITH_RC4_128_MD5",
		0	},
	{
		37,
		"TLS_KRB5_WITH_IDEA_CBC_MD5",
		0	},
	{
		38,
		"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
		0	},
	{
		39,
		"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
		0	},
	{
		40,
		"TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
		0	},
	{
		41,
		"TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
		0	},
	{
		42,
		"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
		0	},
	{
		43,
		"TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
		0	},
	{
		44,
		"TLS_PSK_WITH_NULL_SHA",
		0	},
	{
		45,
		"TLS_DHE_PSK_WITH_NULL_SHA",
		0	},
	{
		46,
		"TLS_RSA_PSK_WITH_NULL_SHA",
		0	},
	{
		47,
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		0	},
	{
		48,
		"TLS_DH_DSS_WITH_AES_128_CBC_SHA",
		0	},
	{
		49,
		"TLS_DH_RSA_WITH_AES_128_CBC_SHA",
		0	},
	{
		50,
		"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
		0	},
	{
		51,
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		0	},
	{
		52,
		"TLS_DH_anon_WITH_AES_128_CBC_SHA",
		0	},
	{
		53,
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		0	},
	{
		54,
		"TLS_DH_DSS_WITH_AES_256_CBC_SHA",
		0	},
	{
		55,
		"TLS_DH_RSA_WITH_AES_256_CBC_SHA",
		0	},
	{
		56,
		"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
		0	},
	{
		57,
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		0	},
	{
		58,
		"TLS_DH_anon_WITH_AES_256_CBC_SHA",
		0	},
	{
		59,
		"TLS_RSA_WITH_NULL_SHA256",
		0	},
	{
		60,
		"TLS_RSA_WITH_AES_128_CBC_SHA256",
		0	},
	{
		61,
		"TLS_RSA_WITH_AES_256_CBC_SHA256",
		0	},
	{
		62,
		"TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
		0	},
	{
		63,
		"TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
		0	},
	{
		64,
		"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
		0	},
	{
		65,
		"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
		0	},
	{
		66,
		"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
		0	},
	{
		67,
		"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
		0	},
	{
		68,
		"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
		0	},
	{
		69,
		"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
		0	},
	{
		70,
		"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
		0	},
	{
		103,
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		0	},
	{
		104,
		"TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
		0	},
	{
		105,
		"TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
		0	},
	{
		106,
		"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
		0	},
	{
		107,
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		0	},
	{
		108,
		"TLS_DH_anon_WITH_AES_128_CBC_SHA256",
		0	},
	{
		109,
		"TLS_DH_anon_WITH_AES_256_CBC_SHA256",
		0	},
	{
		132,
		"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
		0	},
	{
		133,
		"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
		0	},
	{
		134,
		"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
		0	},
	{
		135,
		"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
		0	},
	{
		136,
		"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
		0	},
	{
		137,
		"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
		0	},
	{
		138,
		"TLS_PSK_WITH_RC4_128_SHA",
		0	},
	{
		139,
		"TLS_PSK_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		140,
		"TLS_PSK_WITH_AES_128_CBC_SHA",
		0	},
	{
		141,
		"TLS_PSK_WITH_AES_256_CBC_SHA",
		0	},
	{
		142,
		"TLS_DHE_PSK_WITH_RC4_128_SHA",
		0	},
	{
		143,
		"TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		144,
		"TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
		0	},
	{
		145,
		"TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
		0	},
	{
		146,
		"TLS_RSA_PSK_WITH_RC4_128_SHA",
		0	},
	{
		147,
		"TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		148,
		"TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
		0	},
	{
		149,
		"TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
		0	},
	{
		150,
		"TLS_RSA_WITH_SEED_CBC_SHA",
		0	},
	{
		151,
		"TLS_DH_DSS_WITH_SEED_CBC_SHA",
		0	},
	{
		152,
		"TLS_DH_RSA_WITH_SEED_CBC_SHA",
		0	},
	{
		153,
		"TLS_DHE_DSS_WITH_SEED_CBC_SHA",
		0	},
	{
		154,
		"TLS_DHE_RSA_WITH_SEED_CBC_SHA",
		0	},
	{
		155,
		"TLS_DH_anon_WITH_SEED_CBC_SHA",
		0	},
	{
		156,
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		0	},
	{
		157,
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
		0	},
	{
		158,
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		0	},
	{
		159,
		"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		0	},
	{
		160,
		"TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
		0	},
	{
		161,
		"TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
		0	},
	{
		162,
		"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
		0	},
	{
		163,
		"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
		0	},
	{
		164,
		"TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
		0	},
	{
		165,
		"TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
		0	},
	{
		166,
		"TLS_DH_anon_WITH_AES_128_GCM_SHA256",
		0	},
	{
		167,
		"TLS_DH_anon_WITH_AES_256_GCM_SHA384",
		0	},
	{
		168,
		"TLS_PSK_WITH_AES_128_GCM_SHA256",
		0	},
	{
		169,
		"TLS_PSK_WITH_AES_256_GCM_SHA384",
		0	},
	{
		170,
		"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
		0	},
	{
		171,
		"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
		0	},
	{
		172,
		"TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
		0	},
	{
		173,
		"TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
		0	},
	{
		174,
		"TLS_PSK_WITH_AES_128_CBC_SHA256",
		0	},
	{
		175,
		"TLS_PSK_WITH_AES_256_CBC_SHA384",
		0	},
	{
		176,
		"TLS_PSK_WITH_NULL_SHA256",
		0	},
	{
		177,
		"TLS_PSK_WITH_NULL_SHA384",
		0	},
	{
		178,
		"TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
		0	},
	{
		179,
		"TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
		0	},
	{
		180,
		"TLS_DHE_PSK_WITH_NULL_SHA256",
		0	},
	{
		181,
		"TLS_DHE_PSK_WITH_NULL_SHA384",
		0	},
	{
		182,
		"TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
		0	},
	{
		183,
		"TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
		0	},
	{
		184,
		"TLS_RSA_PSK_WITH_NULL_SHA256",
		0	},
	{
		185,
		"TLS_RSA_PSK_WITH_NULL_SHA384",
		0	},
	{
		186,
		"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		187,
		"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		188,
		"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		189,
		"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		190,
		"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		191,
		"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		192,
		"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		0	},
	{
		193,
		"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
		0	},
	{
		194,
		"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		0	},
	{
		195,
		"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
		0	},
	{
		196,
		"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		0	},
	{
		197,
		"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
		0	},
	{
		255,
		"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
		0	},
	{
		4865,
		"TLS_AES_128_GCM_SHA256",
		0	},
	{
		4866,
		"TLS_AES_256_GCM_SHA384",
		0	},
	{
		4867,
		"TLS_CHACHA20_POLY1305_SHA256",
		0	},
	{
		4868,
		"TLS_AES_128_CCM_SHA256",
		0	},
	{
		4869,
		"TLS_AES_128_CCM_8_SHA256",
		0	},
	{
		22016,
		"TLS_FALLBACK_SCSV",
		0	},
	{
		49153,
		"TLS_ECDH_ECDSA_WITH_NULL_SHA",
		0	},
	{
		49154,
		"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
		0	},
	{
		49155,
		"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		49156,
		"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
		0	},
	{
		49157,
		"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
		0	},
	{
		49158,
		"TLS_ECDHE_ECDSA_WITH_NULL_SHA",
		0	},
	{
		49159,
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		0	},
	{
		49160,
		"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		49161,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		0	},
	{
		49162,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		0	},
	{
		49163,
		"TLS_ECDH_RSA_WITH_NULL_SHA",
		0	},
	{
		49164,
		"TLS_ECDH_RSA_WITH_RC4_128_SHA",
		0	},
	{
		49165,
		"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		49166,
		"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
		0	},
	{
		49167,
		"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
		0	},
	{
		49168,
		"TLS_ECDHE_RSA_WITH_NULL_SHA",
		0	},
	{
		49169,
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		0	},
	{
		49170,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		49171,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		0	},
	{
		49172,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		0	},
	{
		49173,
		"TLS_ECDH_anon_WITH_NULL_SHA",
		0	},
	{
		49174,
		"TLS_ECDH_anon_WITH_RC4_128_SHA",
		0	},
	{
		49175,
		"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		49176,
		"TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
		0	},
	{
		49177,
		"TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
		0	},
	{
		49178,
		"TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		49179,
		"TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		49180,
		"TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		49181,
		"TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
		0	},
	{
		49182,
		"TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
		0	},
	{
		49183,
		"TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
		0	},
	{
		49184,
		"TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
		0	},
	{
		49185,
		"TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
		0	},
	{
		49186,
		"TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
		0	},
	{
		49187,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		0	},
	{
		49188,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		0	},
	{
		49189,
		"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
		0	},
	{
		49190,
		"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
		0	},
	{
		49191,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		0	},
	{
		49192,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		0	},
	{
		49193,
		"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
		0	},
	{
		49194,
		"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
		0	},
	{
		49195,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		0	},
	{
		49196,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		0	},
	{
		49197,
		"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
		0	},
	{
		49198,
		"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
		0	},
	{
		49199,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0	},
	{
		49200,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0	},
	{
		49201,
		"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
		0	},
	{
		49202,
		"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
		0	},
	{
		49203,
		"TLS_ECDHE_PSK_WITH_RC4_128_SHA",
		0	},
	{
		49204,
		"TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		49205,
		"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
		0	},
	{
		49206,
		"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
		0	},
	{
		49207,
		"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
		0	},
	{
		49208,
		"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
		0	},
	{
		49209,
		"TLS_ECDHE_PSK_WITH_NULL_SHA",
		0	},
	{
		49210,
		"TLS_ECDHE_PSK_WITH_NULL_SHA256",
		0	},
	{
		49211,
		"TLS_ECDHE_PSK_WITH_NULL_SHA384",
		0	},
	{
		49212,
		"TLS_RSA_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49213,
		"TLS_RSA_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49214,
		"TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49215,
		"TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49216,
		"TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49217,
		"TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49218,
		"TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49219,
		"TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49220,
		"TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49221,
		"TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49222,
		"TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49223,
		"TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49224,
		"TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49225,
		"TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49226,
		"TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49227,
		"TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49228,
		"TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49229,
		"TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49230,
		"TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49231,
		"TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49232,
		"TLS_RSA_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49233,
		"TLS_RSA_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49234,
		"TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49235,
		"TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49236,
		"TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49237,
		"TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49238,
		"TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49239,
		"TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49240,
		"TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49241,
		"TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49242,
		"TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49243,
		"TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49244,
		"TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49245,
		"TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49246,
		"TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49247,
		"TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49248,
		"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49249,
		"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49250,
		"TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49251,
		"TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49252,
		"TLS_PSK_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49253,
		"TLS_PSK_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49254,
		"TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49255,
		"TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49256,
		"TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49257,
		"TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49258,
		"TLS_PSK_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49259,
		"TLS_PSK_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49260,
		"TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49261,
		"TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49262,
		"TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
		0	},
	{
		49263,
		"TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
		0	},
	{
		49264,
		"TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
		0	},
	{
		49265,
		"TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
		0	},
	{
		49266,
		"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		49267,
		"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
		0	},
	{
		49268,
		"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		49269,
		"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
		0	},
	{
		49270,
		"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		49271,
		"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
		0	},
	{
		49272,
		"TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		49273,
		"TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
		0	},
	{
		49274,
		"TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49275,
		"TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49276,
		"TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49277,
		"TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49278,
		"TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49279,
		"TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49280,
		"TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49281,
		"TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49282,
		"TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49283,
		"TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49284,
		"TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49285,
		"TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49286,
		"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49287,
		"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49288,
		"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49289,
		"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49290,
		"TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49291,
		"TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49292,
		"TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49293,
		"TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49294,
		"TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49295,
		"TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49296,
		"TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49297,
		"TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49298,
		"TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
		0	},
	{
		49299,
		"TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
		0	},
	{
		49300,
		"TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		49301,
		"TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
		0	},
	{
		49302,
		"TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		49303,
		"TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
		0	},
	{
		49304,
		"TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		49305,
		"TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
		0	},
	{
		49306,
		"TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
		0	},
	{
		49307,
		"TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
		0	},
	{
		49308,
		"TLS_RSA_WITH_AES_128_CCM",
		0	},
	{
		49309,
		"TLS_RSA_WITH_AES_256_CCM",
		0	},
	{
		49310,
		"TLS_DHE_RSA_WITH_AES_128_CCM",
		0	},
	{
		49311,
		"TLS_DHE_RSA_WITH_AES_256_CCM",
		0	},
	{
		49312,
		"TLS_RSA_WITH_AES_128_CCM_8",
		0	},
	{
		49313,
		"TLS_RSA_WITH_AES_256_CCM_8",
		0	},
	{
		49314,
		"TLS_DHE_RSA_WITH_AES_128_CCM_8",
		0	},
	{
		49315,
		"TLS_DHE_RSA_WITH_AES_256_CCM_8",
		0	},
	{
		49316,
		"TLS_PSK_WITH_AES_128_CCM",
		0	},
	{
		49317,
		"TLS_PSK_WITH_AES_256_CCM",
		0	},
	{
		49318,
		"TLS_DHE_PSK_WITH_AES_128_CCM",
		0	},
	{
		49319,
		"TLS_DHE_PSK_WITH_AES_256_CCM",
		0	},
	{
		49320,
		"TLS_PSK_WITH_AES_128_CCM_8",
		0	},
	{
		49321,
		"TLS_PSK_WITH_AES_256_CCM_8",
		0	},
	{
		49322,
		"TLS_PSK_DHE_WITH_AES_128_CCM_8",
		0	},
	{
		49323,
		"TLS_PSK_DHE_WITH_AES_256_CCM_8",
		0	},
	{
		49324,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
		0	},
	{
		49325,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
		0	},
	{
		49326,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
		0	},
	{
		49327,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
		0	},
	{
		52392,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		0	},
	{
		52393,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		0	},
	{
		52394,
		"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		0	},
	{
		52395,
		"TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
		0	},
	{
		52396,
		"TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
		0	},
	{
		52397,
		"TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
		0	},
	{
		52398,
		"TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
		0	},
        // DRAFT-IETF-TLS-ECC
	{
		71,
		"TLS_ECDH_ECDSA_WITH_NULL_SHA",
		0	},
	{
		72,
		"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
		0	},
	{
		73,
		"TLS_ECDH_ECDSA_WITH_DES_CBC_SHA",
		0	},
	{
		74,
		"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		75,
		"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
		0	},
	{
		76,
		"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
		0	},
	{
		75,
		"TLS_ECDH_ECDSA_EXPORT_WITH_RC4_40_SHA",
		0	},
	{
		76,
		"TLS_ECDH_ECDSA_EXPORT_WITH_RC4_56_SHA",
		0	},
	{
		77,
		"TLS_ECDH_RSA_WITH_NULL_SHA",
		0	},
	{
		78,
		"TLS_ECDH_RSA_WITH_RC4_128_SHA",
		0	},
	{
		79,
		"TLS_ECDH_RSA_WITH_DES_CBC_SHA",
		0	},
	{
		80,
		"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		81,
		"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
		0	},
	{
		82,
		"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
		0	},
	{
		83,
		"TLS_ECDH_RSA_EXPORT_WITH_RC4_40_SHA",
		0	},
	{
		84,
		"TLS_ECDH_RSA_EXPORT_WITH_RC4_56_SHA",
		0	},
	{
		85,
		"TLS_ECDH_anon_NULL_WITH_SHA",
		0	},
	{
		86,
		"TLS_ECDH_anon_WITH_RC4_128_SHA",
		0	},
	{
		87,
		"TLS_ECDH_anon_WITH_DES_CBC_SHA",
		0	},
	{
		88,
		"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
		0	},
	{
		89,
		"TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA",
		0	},
	{
		90,
		"TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA",
		0	},
	// DRAFT-IETF-TLS-56-BIT-CIPHERSUITES
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
		"TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
		0	},
	{
		102,
		"TLS_DHE_DSS_WITH_RC4_128_SHA",
		0	},
	// FIPS SSL (Netscape)
	{
		65278,
		"SSL_RSA_FIPS_WITH_DES_CBC_SHA",
		0	},
	{
		65279,
		"SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
		0	},
	// SSL 2.0
	{
		65664,
		"SSL2_RC4_128_WITH_MD5",
		0	},
	{
		131200,
		"SSL2_RC4_128_EXPORT40_WITH_MD5",
		0	},
	{
		196736,
		"SSL2_RC2_CBC_128_CBC_WITH_MD5",
		0	},
	{
		262272,
		"SSL2_RC2_128_CBC_EXPORT40_WITH_MD5",
		0	},
	{
		327808,
		"SSL2_IDEA_128_CBC_WITH_MD5",
		0	},
	{
		393280,
		"SSL2_DES_64_CBC_WITH_MD5",
		0	},
	{
		393536,
		"SSL2_DES_64_CBC_WITH_SHA",
		0	},
	{
		458944,
		"SSL2_DES_192_EDE3_CBC_WITH_MD5",
		0	},
	{
		459200,
		"SSL2_DES_192_EDE3_CBC_WITH_SHA",
		0	},
	{
		524416,
		"SSL2_RC4_64_WITH_MD5",
		0	},
	{
		2570,
		"GREASE 0x0A0A",
		0	},
	{
		6682,
		"GREASE 0x1A1A",
		0	},
	{
		10794,
		"GREASE 0x2A2A",
		0	},
	{
		14906,
		"GREASE 0x3A3A",
		0	},
	{
		19018,
		"GREASE 0x4A4A",
		0	},
	{
		23130,
		"GREASE 0x5A5A",
		0	},
	{
		27242,
		"GREASE 0x6A6A",
		0	},
	{
		31354,
		"GREASE 0x7A7A",
		0	},
	{
		35466,
		"GREASE 0x8A8A",
		0	},
	{
		39578,
		"GREASE 0x9A9A",
		0	},
	{
		43690,
		"GREASE 0xAAAA",
		0	},
	{
		47802,
		"GREASE 0xBABA",
		0	},
	{
		51914,
		"GREASE 0xCACA",
		0	},
	{
		56026,
		"GREASE 0xDADA",
		0	},
	{
		60138,
		"GREASE 0xEAEA",
		0	},
	{
		64250,
		"GREASE 0xFAFA",
		0	},
{-1}
};

static int decode_AlertLevel_warning(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "alert_level", json_object_new_string("warning"));
	return(0);
  }
static int decode_AlertLevel_fatal(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    struct json_object *jobj;
    jobj = ssl->cur_json_st;
    json_object_object_add(jobj, "alert_level", json_object_new_string("fatal"));
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
{-1}
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
{-1}
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
{-1}
};

static int decode_extension_server_name(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    UINT4 t,l;
    int r,p;

    extern decoder server_name_type_decoder[];

    SSL_DECODE_UINT16(ssl,"extension length",0,data,&l);

    if(dir==DIR_I2R){
      SSL_DECODE_UINT16(ssl,"server name list length",0,data,&l);
      LF;
      while(l) {
	p=data->len;
	SSL_DECODE_UINT8(ssl, "server name type", 0, data, &t);

	if (ssl_decode_switch(ssl,server_name_type_decoder,t,dir,seg,data) == R_NOT_FOUND) {
	  decode_server_name(ssl,dir,seg,data);
	  P_(P_RH){
	    explain(ssl, "Server Name type: %u not yet implemented in ssldump\n", t);
	  }
	  continue;
	}
	l-=(p-data->len);
      }
    }
    else{
      data->len-=l;
      data->data+=l;
    }
    return(0);
  }
static int decode_extension_encrypt_then_mac(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    int r,*etm;
    UINT4 l;

    etm=&ssl->extensions->encrypt_then_mac;

    SSL_DECODE_UINT16(ssl,"extension length",0,data,&l);
    data->len-=l;
    data->data+=l;

    dir==DIR_I2R?*etm=1:++*etm;
    return(0);
  }
static int decode_extension_extended_master_secret(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    int r,*ems;
    UINT4 l;

    ems=&ssl->extensions->extended_master_secret;

    SSL_DECODE_UINT16(ssl,"extension length",0,data,&l);
    data->len-=l;
    data->data+=l;

    dir==DIR_I2R?*ems=1:++*ems;
    return(0);
  }
static int decode_extension(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    int r;
    UINT4 l;
    SSL_DECODE_UINT16(ssl,"extension length",0,data,&l);
    data->len-=l;
    data->data+=l;
    return(0);
  }

decoder supported_groups_decoder[] = {
	{0x0017,"secp256r1",0},
	{0x0018,"secp384r1",0},
	{0x0019,"secp521r1",0},
	{0x001d,"x25519",0},
	{0x001e,"x448",0},
	{0x0100,"ffdhe2048",0},
	{0x0101,"ffdhe3072",0},
	{0x0102,"ffdhe4096",0},
	{0x0103,"ffdhe6144",0},
	{0x0104,"ffdhe8192",0},
};
// Extension #10 supported_groups (renamed from "elliptic_curves")
static int decode_extension_supported_groups(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    int r,p;
    UINT4 l,g;
    char *ja3_ec_str = NULL;
    SSL_DECODE_UINT16(ssl,"extension length",0,data,&l);

    if(dir==DIR_I2R){
      SSL_DECODE_UINT16(ssl,"supported_groups list length",0,data,&l);
      LF;
      while(l) {
	p=data->len;
    SSL_DECODE_ENUM(ssl,"supported group",2,supported_groups_decoder,SSL_PRINT_ALL,data,&g);
	LF;
        if(!ja3_ec_str)
            ja3_ec_str = calloc(7, 1);
        else
            ja3_ec_str = realloc(ja3_ec_str, strlen(ja3_ec_str) + 7);
	snprintf(ja3_ec_str + strlen(ja3_ec_str), 7, "%u-", g);
	l-=(p-data->len);
      }
      if(ja3_ec_str && ja3_ec_str[strlen(ja3_ec_str) - 1] == '-')
          ja3_ec_str[strlen(ja3_ec_str) - 1] = '\0';
    }
    else{
      data->len-=l;
      data->data+=l;
    }
    ssl->cur_ja3_ec_str = ja3_ec_str;
    return(0);
  }

decoder ec_point_formats_decoder[] = {
	{0,"uncompressed",0,},
	{1,"ansiX962_compressed_prime",0,},
	{2,"ansiX962_compressed_char2",0,}
};
// Extension #11 ec_point_formats
static int decode_extension_ec_point_formats(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    int r,p;
    UINT4 l,f;
    char *ja3_ecp_str = NULL;
    SSL_DECODE_UINT16(ssl,"extension length",0,data,&l);

    if(dir==DIR_I2R){
      SSL_DECODE_UINT8(ssl,"ec_point_formats list length",0,data,&l);
      LF;
      while(l) {
	p=data->len;
    SSL_DECODE_ENUM(ssl,"ec point format",1,ec_point_formats_decoder,SSL_PRINT_ALL,data, &f);
	LF;
        if(!ja3_ecp_str)
            ja3_ecp_str = calloc(5, 1);
        else
            ja3_ecp_str = realloc(ja3_ecp_str, strlen(ja3_ecp_str) + 5);
	snprintf(ja3_ecp_str + strlen(ja3_ecp_str), 5, "%u-", f);
	l-=(p-data->len);
      }
      if(ja3_ecp_str && ja3_ecp_str[strlen(ja3_ecp_str) - 1] == '-')
          ja3_ecp_str[strlen(ja3_ecp_str) - 1] = '\0';
    }
    else{
      data->len-=l;
      data->data+=l;
    }

    ssl->cur_ja3_ecp_str = ja3_ecp_str;
    return(0);
  }

static int decode_extension_supported_versions(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
{
    int r;
    UINT4 len, version;
    SSL_DECODE_UINT16(ssl, "extensions length", 0, data, &len);
    LF;
    if (dir == DIR_I2R) SSL_DECODE_UINT8(ssl, "supported versions length", 0, data, &len);//client sends extension<..>
    while (len) {
        SSL_DECODE_UINT16(ssl, "supported version", 0, data, &version);
        explain(ssl, "version: %u.%u", (version>>8)&0xff, version&0xff);
        len -= 2;
		if (len) printf("\n");
    }
    if (dir == DIR_R2I) ssl->version = version; // Server sets the tls version
}

decoder tls13_certificate_types[] = {
	{0,"x509",0},
	{1,"openpgp",0},
	{2,"raw public key",0},
	{3,"1609 dot 2",0}
};
static int decode_extension_client_certificate_type(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
{
    int r;
    UINT4 len, certificate_type;
    SSL_DECODE_UINT16(ssl, "extensions length", 0, data, &len);
    LF;
    if (dir == DIR_I2R) SSL_DECODE_UINT8(ssl, "client certificates length", 0, data, &len);//client sends certificates<..>
    while (len) {
        SSL_DECODE_ENUM(ssl,"certificate type",1,tls13_certificate_types,SSL_PRINT_ALL,data, &certificate_type);
        len -= 1;
		data += 1;
		if (len) printf("\n");
    }
    if (dir == DIR_R2I) ssl->extensions->client_certificate_type = certificate_type; // Server sets the client_certificate_type
}

static int decode_extension_server_certificate_type(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
{
    int r;
    UINT4 len, certificate_type;
    SSL_DECODE_UINT16(ssl, "extensions length", 0, data, &len);
    LF;
    if (dir == DIR_I2R) SSL_DECODE_UINT8(ssl, "server certificates length", 0, data, &len);//client sends certificates<..>
    while (len) {
        SSL_DECODE_ENUM(ssl,"certificate type",1,tls13_certificate_types,SSL_PRINT_ALL,data, &certificate_type);
        len -= 1;
		data += 1;
		if (len) printf("\n");
    }
    if (dir == DIR_R2I) ssl->extensions->server_certificate_type = certificate_type; // Server sets the server_certificate_type
}

decoder extension_decoder[] = {
	{
		0,
		"server_name",
		decode_extension_server_name,
	},
	{
		1,
		"max_fragment_length",
		decode_extension
	},
	{
		2,
		"client_certificate_url",
		decode_extension
	},
	{
		3,
		"trusted_ca_keys",
		decode_extension
	},
	{
		4,
		"truncated_hmac",
		decode_extension
	},
	{
		5,
		"status_request",
		decode_extension
	},
        {
                6,
                "user_mapping",
                decode_extension
        },
        {
                7,
                "client_authz",
                decode_extension
        },
        {
                8,
                "server_authz",
                decode_extension
        },
        {
                9,
                "cert_type",
                decode_extension
        },
        {
                10,
                "supported_groups",
                decode_extension_supported_groups
        },
        {
                11,
                "ec_point_formats",
                decode_extension_ec_point_formats
        },
        {
                12,
                "srp",
                decode_extension
        },
	{
		13,
		"signature_algorithms",
		decode_extension
	},
        {
                14,
                "use_srtp",
                decode_extension
        },
        {
                15,
                "heartbeat",
                decode_extension
        },
	{
		16,
		"application_layer_protocol_negotiation",
		decode_extension
	},
        {
                17,
                "status_request_v2",
                decode_extension
        },
        {
                18,
                "signed_certificate_timestamp",
                decode_extension
        },
        {
                19,
                "client_certificate_type",
                decode_extension_client_certificate_type
        },
        {
                20,
                "server_certificate_type",
                decode_extension_server_certificate_type
        },
        {
                21,
                "padding",
                decode_extension
        },
	{
		22,
		"encrypt_then_mac",
		decode_extension_encrypt_then_mac
	},
	{
		23,
		"extended_master_secret",
		decode_extension_extended_master_secret
	},
        {
                24,
                "token_binding",
                decode_extension
        },
        {
                25,
                "cached_info",
                decode_extension
        },
        {
                26,
                "tls_lts",
                decode_extension
        },
        {
                27,
                "compress_certificate",
                decode_extension
        },
        {
                28,
                "record_size_limit",
                decode_extension
        },
        {
                29,
                "pwd_protect",
                decode_extension
        },
        {
                30,
                "pwd_clear",
                decode_extension
        },
        {
                31,
                "password_salt",
                decode_extension
        },
        {
                32,
                "ticket_pinning",
                decode_extension
        },
        {
                33,
                "tls_cert_with_extern_psk",
                decode_extension
        },
        {
                34,
                "delegated_credentials",
                decode_extension
        },
        {
                35,
                "session_ticket",
                decode_extension
        },
        {
                36,
                "TLMSP",
                decode_extension
        },
        {
                37,
                "TLMSP_proxying",
                decode_extension
        },
        {
                38,
                "TLMSP_delegate",
                decode_extension
        },
        {
                39,
                "supported_ekt_ciphers",
                decode_extension
        },
        {
                41,
                "pre_shared_key",
                decode_extension
        },
        {
                42,
                "early_data",
                decode_extension
        },
        {
                43,
                "supported_versions",
                decode_extension_supported_versions
        },
        {
                44,
                "cookie",
                decode_extension
        },
        {
                45,
                "psk_key_exchange_modes",
                decode_extension
        },
        {
                47,
                "certificate_authorities",
                decode_extension
        },
        {
                48,
                "oid_filters",
                decode_extension
        },
        {
                49,
                "post_handshake_auth",
                decode_extension
        },
        {
                50,
                "signature_algorithms_cert",
                decode_extension
        },
        {
                51,
                "key_share",
                decode_extension
        },
        {
                52,
                "transparency_info",
                decode_extension
        },
        {
                53,
                "connection_id",
                decode_extension
        },
        {
                55,
                "external_id_hash",
                decode_extension
        },
        {
                56,
                "external_session_id",
                decode_extension
        },
	{
		13172,
		"next_protocol_negotiation",
		decode_extension
	},
	{
		0xff01,
		"renegotiation_info",
		decode_extension
	},
{-1}
};

static int decode_server_name_type_host_name(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    int r;
    UINT4 l;
    SSL_DECODE_UINT16(ssl,"server name length",0,data,&l);
    if(!(NET_print_flags & NET_PRINT_JSON))
	printf(": %.*s",l,data->data);

    /* Possibly use data->data to set/modify ssl->server_name */
	if (l!=0)
	{
		char* server_name;
		server_name = calloc(l+1,sizeof(char));
		if (server_name != NULL)
		{
			if (ssl->server_name) free(ssl->server_name);
			if (l > data->len) l = data->len;
			memcpy(server_name,data->data,l);
			ssl->server_name = server_name;
		}
	}

    data->len-=l;
    data->data+=l;
    return(0);
  }
static int decode_server_name(ssl,dir,seg,data)
  ssl_obj *ssl;
  int dir;
  segment *seg;
  Data *data;
  {
    int r;
    UINT4 l;
    SSL_DECODE_UINT16(ssl,"server name length",0,data,&l);
    data->len-=l;
    data->data+=l;
    return(0);
  }

decoder server_name_type_decoder[]={
	{
		0,
		"host_name",
		decode_server_name_type_host_name
	},
{-1}
};
