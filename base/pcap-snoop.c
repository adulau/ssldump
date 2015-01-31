/**
   pcap-snoop.c


   Copyright (C) 1999-2001 RTFM, Inc.
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

   $Id: pcap-snoop.c,v 1.14 2002/09/09 21:02:58 ekr Exp $


   ekr@rtfm.com  Tue Dec 29 10:17:41 1998
 */


static char *RCSSTRING="$Id: pcap-snoop.c,v 1.14 2002/09/09 21:02:58 ekr Exp $";


#include <pcap.h>
#include <unistd.h>
#include <net/bpf.h>
#ifndef _WIN32
#include <sys/param.h>
#endif
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#include <bittypes.h>
#endif
#include <signal.h>

#include <net/if.h>
#include <netinet/if_ether.h>
#include "network.h"
#include <r_common.h>
#include <r_time.h>
#include "null_analyze.h"
#include "ssl_analyze.h"
#ifdef ENABLE_RECORD
#include "record_analyze.h"
#endif

#ifndef ETHERTYPE_8021Q
# define ETHERTYPE_8021Q 0x8100
#endif

char *collapse_args PROTO_LIST((int argc,char **argv));
static int pcap_if_type=DLT_NULL;
int err_exit PROTO_LIST((char *str,int num));
int usage PROTO_LIST((void));
int print_version PROTO_LIST((void));
RETSIGTYPE sig_handler PROTO_LIST((void));
void pcap_cb PROTO_LIST((u_char *ptr,struct pcap_pkthdr *hdr,u_char *data));
int main PROTO_LIST((int argc,char **argv));

int err_exit(str,num)
  char *str;
  int num;
  {
    fprintf(stderr,"ERROR: %s\n",str);
    exit(num);
  }

int usage()
  {
    fprintf(stderr,"Usage: ssldump [-r dumpfile] [-i interface] \n");
    fprintf(stderr,"               [-k keyfile] [-p password] [-vtaTnsAxVNde]\n");
    fprintf(stderr,"               [filter]\n");
    exit(0);
  }

int print_version()
  {
    printf("ssldump 0.9b3\n");
    printf("Copyright (C) 1998-2001 RTFM, Inc.\n");
    printf("All rights reserved.\n");
#ifdef OPENSSL    
    printf("Compiled with OpenSSL: decryption enabled\n");
#endif    
    exit(0);
  }

RETSIGTYPE sig_handler()
  {
    fflush(stdout);
    exit(0);
  }
    
void pcap_cb(ptr,hdr,data)
  u_char *ptr;
  struct pcap_pkthdr *hdr;
  u_char *data;
  {
    n_handler *n;
    int len;
    struct ether_header *e_hdr=(struct ether_header *)data;
    int type;
    
    n=(n_handler *)ptr;
    if(hdr->caplen!=hdr->len) err_exit("Length mismatch",-1);

    len=hdr->len;
    
    switch(pcap_if_type){
      case DLT_NULL:
        data+=4;
        len-=4;
        break;
      case DLT_EN10MB:
        type=ntohs(e_hdr->ether_type);

        data+=sizeof(struct ether_header);
        len-=sizeof(struct ether_header);

        /* if vlans, push past VLAN header (4 bytes) */
        if(type==ETHERTYPE_8021Q) {
          type=ntohs(*(u_int16_t *)(data + 2));

          data+=4;
          len+=4;
        }

        if(type!=ETHERTYPE_IP)
          return;
        
        break;
    }
    network_process_packet(n,&hdr->ts,data,len);
  }

typedef struct module_def_ {
     char *name;
     proto_mod *mod;
} module_def;

static module_def modules[]={
     {"SSL",&ssl_mod},
     {"NULL",&null_mod},
#ifdef ENABLE_RECORD
     {"RECORD",&record_mod},
#endif
     {0,0}
};


int parse_ssl_flag PROTO_LIST((int c));

int main(argc,argv)
  int argc;
  char **argv;
  {
    pcap_t *p;
    int r;
    n_handler *n;
#ifdef _WIN32
    __declspec(dllimport) char *optarg;
    __declspec(dllimport) int optind;
#else
    extern char *optarg;
    extern int optind;
#endif
    char *interface_name=0;
    char *file=0;
    char *filter=0;
    proto_mod *mod=&ssl_mod;
    bpf_u_int32 localnet,netmask;
    int c;
    module_def *m=0;
    int no_promiscuous=0;
    
    char errbuf[PCAP_ERRBUF_SIZE];

    signal(SIGINT,sig_handler);
    
    while((c=getopt(argc,argv,"vr:f:S:Ttai:k:p:nsAxXhHVNdqem:P"))!=EOF){
      switch(c){
        case 'v':
          print_version();
          break;
        case 'f':
          fprintf(stderr,"-f option replaced by -r. Use that in the future\n");
	case 'r':
	  file=strdup(optarg);
	  break;
        case 'S':
          ssl_mod.vtbl->parse_flags(optarg);
          break;
        case 'y':
          NET_print_flags|=NET_PRINT_TYPESET;
          /*Kludge*/
          SSL_print_flags |= SSL_PRINT_NROFF;
          break;
	case 'a':
	  NET_print_flags |= NET_PRINT_ACKS;
	  break;
        case 'T':
          NET_print_flags |= NET_PRINT_TCP_HDR;
          break;
        case 'i':
          interface_name=strdup(optarg);
          break;
        case 'k':
          SSL_keyfile=strdup(optarg);
          break;
        case 'p':
          SSL_password=strdup(optarg);
          break;
	case 'P':
	  ++no_promiscuous;
	  break;
        case 'n':
          NET_print_flags |= NET_PRINT_NO_RESOLVE;
          break;
	case 'm':
	  for(m=modules;m->name!=0;m++){
	    if(!strcmp(m->name,optarg)){
	      mod=m->mod;
	      break;
	    }
	  }
	  if(!m->name){
	    fprintf(stderr,"Request analysis module %s not found\n",
	      optarg);
	    exit(1);
	  }
	  break;
        case 'h':
          usage();
          printf("Do 'man ssldump' for documentation\n");
          exit(1);

	case '?':
          usage();
          exit(1);

          /* must be an SSL flag. This is kind of a gross
	     special case */
        default:
          parse_ssl_flag(c);
          break;
      }
    }

    argv+=optind;
    argc-=optind;
    
    if(!file){
      if(!interface_name){
        interface_name=pcap_lookupdev(errbuf);
        if(!interface_name){
          fprintf(stderr,"PCAP: %s\n",errbuf);
          err_exit("Aborting",-1);
        }
      }
      if(!(p=pcap_open_live(interface_name,5000,!no_promiscuous,1000,errbuf))){
	fprintf(stderr,"PCAP: %s\n",errbuf);
	err_exit("Aborting",-1);
      }

      if (pcap_lookupnet(interface_name, &localnet, &netmask, errbuf) < 0)
        verr_exit("PCAP: %s\n",errbuf);
      
    }
    else{
      if(!(p=pcap_open_offline(file,errbuf))){
	fprintf(stderr,"PCAP: %s\n",errbuf);
	err_exit("Aborting",-1);
      }
      
      netmask=0;
      localnet=0;
    }

    if(argc!=0)
      filter=collapse_args(argc,argv);

    if(filter){
      struct bpf_program fp;

      if(pcap_compile(p,&fp,filter,0,netmask)<0)
        verr_exit("PCAP: %s\n",pcap_geterr(p));

      if(pcap_setfilter(p,&fp)<0)
        verr_exit("PCAP: %s\n",pcap_geterr(p));
    }

    pcap_if_type=pcap_datalink(p);
    
    if(NET_print_flags & NET_PRINT_TYPESET)
      printf("\n.nf\n.ps -2\n");
    
    if(r=network_handler_create(mod,&n))
      err_exit("Couldn't create network handler",r);

    pcap_loop(p,-1,pcap_cb,(u_char *)n);

    if(NET_print_flags & NET_PRINT_TYPESET)
      printf("\n.ps\n.fi\n");
    
    exit(0);
  }
      

char *collapse_args(argc,argv)
  int argc;
  char **argv;
  {
    int i,len=0;
    char *ret;
    
    if(!argc)
      return(0);

    for(i=0;i<argc;i++){
      len+=strlen(argv[i])+1;
    }

    if(!(ret=(char *)malloc(len)))
      err_exit("Out of memory",1);

    len=0;
    for(i=0;i<argc;i++){
      strcpy(ret+len,argv[i]);
      len+=strlen(argv[i]);

      if(i!=(argc-1))
        ret[len++]=' ';
    }

    return(ret);
  }
