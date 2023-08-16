
#include <pcap.h>
#include <unistd.h>
#ifndef __OpenBSD__
#include <pcap-bpf.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "network.h"
#include "proto_mod.h"
#include "debug.h"

#include "pcap_logger.h"
#include "logpkt.h"

#define DFLT_FILEMODE 0666

static int init_pcap_logger PROTO_LIST((void *data));
static int deinit_pcap_logger PROTO_LIST(());
static int create_pcap_logger PROTO_LIST((proto_obj * *objp,
                                          struct sockaddr_storage *i_addr,
                                          u_short i_port,
                                          struct sockaddr_storage *r_addr,
                                          u_short r_port,
                                          struct timeval *base_time));
static int destroy_pcap_logger PROTO_LIST((proto_obj * *objp));
static int data_pcap_logger PROTO_LIST(
    (proto_obj * _obj, unsigned char *data, unsigned int len, int dir));
static int close_pcap_logger PROTO_LIST(
    (proto_obj * _obj, unsigned char *data, unsigned int len, int dir));

int pcap_fd = -1;
static uint8_t content_pcap_src_ether[ETHER_ADDR_LEN] = {0x02, 0x00, 0x00,
                                                         0x11, 0x11, 0x11};
static uint8_t content_pcap_dst_ether[ETHER_ADDR_LEN] = {0x02, 0x00, 0x00,
                                                         0x22, 0x22, 0x22};

static int init_pcap_logger(void *data) {
  char *pcap_outfile = (char *)data;
  pcap_fd = open(pcap_outfile, O_RDWR | O_CREAT, DFLT_FILEMODE);
  if(pcap_fd == -1) {
    // printf("Failed to open pcap '%s' for writing\n", pcap_outfile);
    return -1;
  }
  if(logpkt_pcap_open_fd(pcap_fd) == -1) {
    // printf("Failed to prepare '%s' for PCAP writing\n", pcap_outfile);
    close(pcap_fd);
    pcap_fd = -1;
    return -1;
  }
  return 0;
}

static int deinit_pcap_logger(void) {
  fdatasync(pcap_fd);
  close(pcap_fd);
  return 0;
}

static int create_pcap_logger(proto_obj **objp,
                              struct sockaddr_storage *i_addr,
                              u_short i_port,
                              struct sockaddr_storage *r_addr,
                              u_short r_port,
                              struct timeval *base_time) {
  int _status;
  logpkt_ctx_t *pcap_obj = 0;
  struct sockaddr_in src_addr, dst_addr;

  if(!(pcap_obj = (logpkt_ctx_t *)calloc(1, sizeof(logpkt_ctx_t))))
    ABORT(R_NO_MEMORY);

  // src_addr.sin_family = AF_INET;
  // src_addr.sin_addr = *i_addr;
  memcpy(&src_addr, i_addr, sizeof(struct sockaddr_in));
  src_addr.sin_port = htons(i_port);

  // dst_addr.sin_family = AF_INET;
  // dst_addr.sin_addr = *r_addr;
  memcpy(&dst_addr, r_addr, sizeof(struct sockaddr_in));
  dst_addr.sin_port = htons(r_port);

  logpkt_ctx_init(pcap_obj, NULL, 0, content_pcap_src_ether,
                  content_pcap_dst_ether, (const struct sockaddr *)&src_addr,
                  sizeof(src_addr), (const struct sockaddr *)&dst_addr,
                  sizeof(dst_addr));
  *objp = (proto_obj *)pcap_obj;
  _status = 0;
abort:
  if(_status) {
    destroy_pcap_logger((proto_obj **)&pcap_obj);
  }
  return (_status);
}

static int destroy_pcap_logger(proto_obj **objp) {
  logpkt_ctx_t *pcap_obj;

  if(!objp || !*objp)
    return (0);

  pcap_obj = (logpkt_ctx_t *)*objp;

  free(pcap_obj);
  *objp = 0;

  return (0);
}

static int data_pcap_logger(proto_obj *_obj,
                            unsigned char *data,
                            unsigned int len,
                            int dir) {
  logpkt_ctx_t *pcap_obj = (logpkt_ctx_t *)_obj;
  int direction;
  int status;

  if(dir == DIR_I2R)
    direction = LOGPKT_REQUEST;
  else
    direction = LOGPKT_RESPONSE;

  status = logpkt_write_payload(pcap_obj, pcap_fd, direction, data, len);

  return status;
}

int close_pcap_logger(proto_obj *_obj,
                      unsigned char *data,
                      unsigned int len,
                      int dir) {
  logpkt_ctx_t *pcap_obj = (logpkt_ctx_t *)_obj;
  int direction;
  int status;

  if(dir == DIR_I2R)
    direction = LOGPKT_REQUEST;
  else
    direction = LOGPKT_RESPONSE;

  status = logpkt_write_close(pcap_obj, pcap_fd, direction);

  return status;
}

static struct logger_mod_vtbl_ pcap_vtbl = {
    init_pcap_logger,    deinit_pcap_logger, create_pcap_logger,
    destroy_pcap_logger, data_pcap_logger,   close_pcap_logger,
};

struct logger_mod_ pcap_mod = {"PCAP", &pcap_vtbl};
