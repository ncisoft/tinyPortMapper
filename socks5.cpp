#include "socks5.h"
#include "log.h"
#include "common.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define SOCKS5_VERSION     0x05
#define SOCKS5_NOAUTH      0x00
#define SOCKS5_CONNECT     0x01
#define SOCKS5_HOST        0x03
#define SOCKS5_IPV6        0x04
#define SOCKS5_RESERVED    0x00
#define SOCKS5_SUCCEEDED   0x00

/*
 * Start SOCKS5 negotiation with authentication negotiation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

static int
send_auth_req(int socks5_fd)
{
  // For Xaptum, only the "NO AUTHENTICATION REQUIRED" method is supported.
  const unsigned char auth_req[] = {
      SOCKS5_VERSION,   // SOCKS version 5
      0x01,             // One authentication method offered
      SOCKS5_NOAUTH};   // method = "No authentication required"

  if (sizeof(auth_req) != write(socks5_fd, auth_req, sizeof(auth_req))) {
      fprintf(stderr, "send_auth_req: Failed to write SOCKS5 Authentication Request\n");
      return -1;
  }

  return 0;
}

static int
read_auth_resp(int fd)
{
    // Always 2 bytes (per RFC).
    unsigned char auth_resp[2] = {};
    if (sizeof(auth_resp) != read(fd, auth_resp, sizeof(auth_resp))) {
        fprintf(stderr, "Failed to read SOCKS5 Authentication Response\n");
        return -1;
    }

    // For Xaptum, first byte must be version5.
    if (SOCKS5_VERSION != auth_resp[0]) {
        fprintf(stderr, "Received SOCKS5 Authentication Response with bad version: %d\n",
                        auth_resp[0]);
        return -1;
    }

    // For Xaptum, second byte must be "NO AUTHENTICATION REQUIRED".
    if (SOCKS5_NOAUTH != auth_resp[1]) {
        fprintf(stderr, "Received SOCKS5 Authentication Response with bad auth method: %d\n",
                        auth_resp[1]);
        return -1;
    }

    return 0;
}
/*
 * Send request to establish a proxied TCP connection
 * to the given Xaptum IPv6 address at the given port.
 */
static int
send_conn_req(int fd,
              const char *hostname,
              int port)
{
  // 1) Build request preamble.
  u_int8_t hostname_len = strlen(hostname);
    unsigned char conn_req[256] = {
        SOCKS5_VERSION,     // SOCKS version 5
        SOCKS5_CONNECT,     // Request an outbound connection
        SOCKS5_RESERVED,    // Reserved byte
        SOCKS5_HOST,        // Address is DOMAIN
        0x0,
                            // hostname_len
                            // hostname
                            // port_big_endian
    };
    int len=4;
    conn_req[len++] = hostname_len;
    memcpy(conn_req + len, hostname, hostname_len);
    len += hostname_len;

    // 3) Convert port to network byte-order
    uint16_t *port_write = (uint16_t*)(&conn_req[len]);
    *port_write = htons((uint16_t)port);
    len += 2;

    // 4) Write connection request
    if (len != write(fd, conn_req, len)) {
        fprintf(stderr, "Failed to write SOCKS5 Connection Request\n");
        return -1;
    }

    return 0;
}

/*
 * Receive response after connection request,
 * validate it,
 * and read out bound address:port information.
 */
static int
read_conn_resp(int fd)
{
    // 1) Receive connection response.
    unsigned char conn_resp_preamble[4] = {};
    if (sizeof(conn_resp_preamble) != read(fd, conn_resp_preamble, sizeof(conn_resp_preamble))) {
        fprintf(stderr, "Failed to read beginning of SOCKS5 Connection Response\n");
        return -1;
    }

    // 2) First byte must be version5
    if (SOCKS5_VERSION != conn_resp_preamble[0]) {
        fprintf(stderr, "Received SOCKS5 Connection Response with bad version: %d\n",
                        conn_resp_preamble[0]);
        return -1;
    }

    // 3) If second byte isn't "SUCCEEDED", something's wrong.
    //    The values of these codes are defined in the RFC.
    if (SOCKS5_SUCCEEDED != conn_resp_preamble[1]) {
        fprintf(stderr, "Received SOCKS5 Connect Response with unsuccessful reply code: %d\n",
                        conn_resp_preamble[1]);
        return -1;
    }

    // 6) Receive the address and port assigned to us.
    // SOCKS5, REQUEST_GRANTED, RESERVED addr_type(1) ack_addr(4) ack_port(2)
    unsigned char conn_resp_bound[4+2] = {};
    ssize_t sz = read(fd, conn_resp_bound, sizeof(conn_resp_bound));
    if (sizeof(conn_resp_bound) != sz) {
        fprintf(stderr, "%d Failed to read SOCKS5 rest of Connection Response %lu\n", __LINE__, sz);
        return -1;
    }

    return 0;
}

int init_socks5_server(int socks5_fd, const char* hostname, int port)
{
  if (socks5_fd > 0)
    {
      int rc;
      rc = send_auth_req(socks5_fd);
      if (!rc)
        {
          rc = read_auth_resp(socks5_fd);
          if (!rc)
            {
              rc = send_conn_req(socks5_fd, hostname, port);
              if (!rc)
                rc = read_conn_resp(socks5_fd);
            }
        }
      else
        {
          printf("rc=%d\n", rc);
        }

      mylog(log_debug, "init socks5 server succ %s:%d\n", hostname, port);
      return rc;
    }
  return 0;
}
