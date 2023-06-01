/*
* 
* 
* 
 * ngtcp2
 *
 * Copyright (c) 2021 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stddef.h>
//#include <sys/socket.h>
//#include <netdb.h>
//#include <arpa/inet.h>
#include <WinSock2.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <wchar.h>
#include <chrono>


#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>
//#include <ngtcp2/ngtcp2_crypto_boringssl.h>


#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string>
#include <random>

#include "uv.h"

#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT "2023"
//#define ALPN "h2"

FILE* debug_file;

int message_index = 0;

char* hello_message = "HELLO Excalibur!";
std::string uuid;
char* messages[] = {
"First",
"Second",
"Third",
"Fourth",
"Fifth",
"Sixth",
"Seventh"
};

// Excalibur API
static int send_hello_message_to_server(ngtcp2_conn*, void*);
static int extend_max_local_streams_bidi(ngtcp2_conn*, uint64_t, void*);
static int send_test_message_to_server(ngtcp2_conn*, void*);
static int send_message_to_server(ngtcp2_conn*, void*, char*);
// When enabled, this callback will call send_test_message_to_server 
static void timer_cb(uv_timer_t* w);


//////////////////////////////////////////
//
// Utility Functions
//
//////////////////////////////////////////

std::chrono::time_point<std::chrono::steady_clock> timestamp_start = std::chrono::steady_clock::now();
ngtcp2_tstamp timestamp() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - timestamp_start)
        .count();
}

static int numeric_host_family(const char* hostname, int family) {
    uint8_t dst[sizeof(struct in6_addr)];
    return inet_pton(family, hostname, dst) == 1;
}

static int numeric_host(const char* hostname) {
    return numeric_host_family(hostname, AF_INET) ||
        numeric_host_family(hostname, AF_INET6);
}




///////////////////////////////
//
// ngtcp2 structures
//
///////////////////////////////

struct client {
    ngtcp2_crypto_conn_ref conn_ref;
    int fd;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    socklen_t local_addrlen;
    SSL_CTX* ssl_ctx;
    SSL* ssl;
    ngtcp2_conn* conn;

    struct {
        int64_t stream_id;
        const uint8_t* data;
        size_t datalen;
        size_t nwrite;
    } stream;

    ngtcp2_ccerr last_error;


    uv_loop_t uv_loop;
    uv_timer_t timer;
    uint64_t repeat;
    uv_poll_t handlePoll;

};

///////////////////////////////
//
// ngtcp2 callback functions
//
///////////////////////////////

static int create_sock(struct sockaddr *addr, socklen_t *paddrlen,
                       const char *host, const char *port) {
  struct addrinfo hints = {0};
  struct addrinfo *res, *rp;
  int rv;
  int fd = -1;

  hints.ai_flags = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

  err = WSAStartup(wVersionRequested, &wsaData);
  if (err != 0)
  {
      fprintf(stderr, "couldn't load winsocket2 dll.");
      return -1;
  }
  rv = getaddrinfo(host, port, &hints, &res);
  if (rv != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return -1;
  }

  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }

    break;
  }

  if (fd == -1) {
    goto end;
  }

  *paddrlen = rp->ai_addrlen;
  memcpy(addr, rp->ai_addr, rp->ai_addrlen);

end:
  freeaddrinfo(res);

  return fd;
}

static int connect_sock(struct sockaddr *local_addr, socklen_t *plocal_addrlen,
                        int fd, const struct sockaddr *remote_addr,
                        std::size_t remote_addrlen) {
  socklen_t len;

  if (connect(fd, remote_addr, (socklen_t)remote_addrlen) != 0) {
    fprintf(stderr, "connect: %s\n", strerror(errno));
    return -1;
  }

  len = *plocal_addrlen;

  if (getsockname(fd, local_addr, &len) == -1) {
    fprintf(stderr, "getsockname: %s\n", strerror(errno));
    return -1;
  }

  *plocal_addrlen = len;

  return 0;
}



static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  size_t i;
  (void)rand_ctx;

  for (i = 0; i < destlen; ++i) {
    *dest = (uint8_t)std::rand();
  }
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data) {
  (void)conn;
  (void)user_data;

  if (RAND_bytes(cid->data, (int)cidlen) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  cid->datalen = cidlen;

  if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

int remove_connection_id(ngtcp2_conn* conn, const ngtcp2_cid* cid, void* user_data)
{
    fprintf(debug_file, "CB: REMOVE CONNECTION ID!\n");
    return 0;
}



int handshake_completed(ngtcp2_conn* conn, void* user_data) {

    fprintf(debug_file, "CB: HANDSHAKE COMPLETED!\n");

    send_hello_message_to_server(conn, user_data);

    return 0;
}

int handshake_confirmed(ngtcp2_conn* conn, void* user_data) {

    fprintf(debug_file, "CB: HANDSHAKE CONFIRMED!\n");
    return 0;
}


int stream_open(ngtcp2_conn* conn, int64_t stream_id, void* user_data) {
    fprintf(debug_file, "CB: STREAM_OPEN, stream_id: %ld\n", stream_id);
    return 0;
}


int stream_close(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id, uint64_t app_error_code, void* user_data, void* stream_user_data) {
    struct client* c = static_cast<struct client*>(user_data);
    fprintf(debug_file, "CB: STREAM_CLOSE, closed stream_id: %ld, client stream_id: %ld, ERROR_CODE: %ld\n", stream_id, c->stream.stream_id, app_error_code);


    if (stream_id == c->stream.stream_id)
    {
        c->stream.stream_id = -1;
        c->stream.nwrite = 0;
    }

    return 0;
}

int recv_datagram(ngtcp2_conn* conn, uint32_t flags, const uint8_t* data, size_t datalen, void* user_data) {

    fprintf(debug_file, "CB: RECV_DATAGRAM %s", data);

    return 0;
}

int ack_datagram(ngtcp2_conn* conn, uint64_t dgram_id, void* user_data) {
    fprintf(debug_file, "CB: ACK_DATAGRAM!!! %ld", dgram_id);

    return 0;
}

int lost_datagram(ngtcp2_conn* conn, uint64_t dgram_id, void* user_data) {
    fprintf(debug_file, "CB: LOST_DATAGRAM!!! %ld", dgram_id);

    return 0;
}

int stream_reset(ngtcp2_conn* conn, int64_t stream_id, uint64_t final_size, uint64_t app_error_code, void* user_data, void* stream_user_data) {
    fprintf(debug_file, "STREAM RESET! STREAM_ID: %ld\n", stream_id);
    return 0;
}

// ngtcp2 CALLBACK
static int recv_stream_data(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t* data, size_t datalen, void* user_data, void* stream_user_data) {
    fprintf(debug_file, "CB: RECV_STREAM_DATA, STREAM_ID: %ld, DATA: %s\n", stream_id, data);

    // EXCALIBUR API
    if (uuid.empty()) {
        // Display just the UUID (starts at character with offset 9)
        fprintf(debug_file, "  Does this look like UUID? %s\n", data + 9);
        uuid = (char*)data+9;


        // TODO: should be a separate thread/ev_loop sending messages on an interval
        send_test_message_to_server(conn, user_data);
    }

    else {
        fprintf(debug_file, "RECEIVED RELIABLE MESSAGE %s len: %ld\n", data, datalen);
        // do something with reliable message
    }
    return 0;
}




static int client_read(struct client *c) {
  uint8_t buf[65536];
  struct sockaddr_storage addr{};
  int addrlen = sizeof(addr);
  ngtcp2_path path;
  ngtcp2_pkt_info pi = {0};
  int rv;

  for (;;) {
    int nread = recv(c->fd, (CHAR*)buf, sizeof(buf), 0);

    //fprintf(debug_file, "[CLIENT READ] %ld\n", nread);

    if ( nread< 0) 
    {
      if (WSAGetLastError() != WSAEWOULDBLOCK) {
        fprintf(debug_file, "recv: %d\n", WSAGetLastError());
      }

      break;
    }

    path.local.addrlen = c->local_addrlen;
    path.local.addr = (struct sockaddr *)&c->local_addr;
    path.remote.addrlen = sizeof(c->remote_addr);
    path.remote.addr = (struct sockaddr *)&c->remote_addr;

    rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, (size_t)nread,
                              timestamp());
    if (rv != 0) {
      fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
      if (!c->last_error.error_code) {
        if (rv == NGTCP2_ERR_CRYPTO) {
            ngtcp2_ccerr_set_tls_alert(
              &c->last_error, ngtcp2_conn_get_tls_alert(c->conn), NULL, 0);
        } else {
            ngtcp2_ccerr_set_liberr(
              &c->last_error, rv, NULL, 0);
        }
      }
      return -1;
    }
    else {
        fprintf(debug_file, "[CLIENT READ] %d bytes\n", nread);
    }
  }

  return 0;
}




static int client_send_packet(struct client *c, const uint8_t *data,
                              size_t datalen) {
  WSABUF wsabuf;
  DWORD nwrite;

  wsabuf.buf = (CHAR*)data;
  wsabuf.len = (ULONG)datalen;

  if (WSASend(c->fd, &wsabuf, 1, &nwrite, 0, NULL, NULL) == SOCKET_ERROR) {
    fprintf(stderr, "WSASend: %d\n", WSAGetLastError());
    return -1;
  }

  return 0;
}

static size_t client_get_message(struct client *c, int64_t *pstream_id,
                                 int *pfin, ngtcp2_vec *datav,
                                 size_t datavcnt) {
  if (datavcnt == 0) {
    return 0;
  }

  if (c->stream.stream_id != -1 && c->stream.nwrite < c->stream.datalen) {
    *pstream_id = c->stream.stream_id;
    *pfin = 1;
    datav->base = (uint8_t *)c->stream.data + c->stream.nwrite;
    datav->len = c->stream.datalen - c->stream.nwrite;
    return 1;
  }

  *pstream_id = -1;
  *pfin = 0;
  datav->base = NULL;
  datav->len = 0;

  return 0;
}

static int client_write_streams(struct client *c) {
  ngtcp2_tstamp ts = timestamp();
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  uint8_t buf[1280];
  ngtcp2_path_storage ps;
  ngtcp2_vec datav;
  size_t datavcnt;
  int64_t stream_id;
  ngtcp2_ssize wdatalen;
  uint32_t flags;
  int fin;

  ngtcp2_path_storage_zero(&ps);

  for (;;) {
    datavcnt = client_get_message(c, &stream_id, &fin, &datav, 1);

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf, sizeof(buf),
                                       &wdatalen, flags, stream_id, &datav,
                                       datavcnt, ts);
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_WRITE_MORE:
        c->stream.nwrite += (size_t)wdatalen;
        continue;
      default:
        fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n",
                ngtcp2_strerror((int)nwrite));
        ngtcp2_ccerr_set_liberr(&c->last_error, (int)nwrite, NULL, 0);
        return -1;
      }
    }

    if (nwrite == 0) {
      return 0;
    }

    if (wdatalen > 0) {
      c->stream.nwrite += (size_t)wdatalen;
    }

    if (client_send_packet(c, buf, (size_t)nwrite) != 0) {
      break;
    }
  }

  return 0;
}


static int client_write(struct client *c) {
  ngtcp2_tstamp expiry, now;
  
  uint64_t t;

  if (client_write_streams(c) != 0) {
    return -1;
  }

  expiry = ngtcp2_conn_get_expiry(c->conn);
  now = timestamp();

  t = expiry < now ? 1e-9 : (uint64_t)(expiry - now) / NGTCP2_SECONDS;
  c->repeat = t;

  uv_timer_again(&c->timer);

  return 0;
}

static int client_handle_expiry(struct client *c) {
  int rv = ngtcp2_conn_handle_expiry(c->conn, timestamp());
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  return 0;
}

static void client_close(struct client *c) {
  ngtcp2_ssize nwrite;
  ngtcp2_pkt_info pi;
  ngtcp2_path_storage ps;
  uint8_t buf[1280];

  if (ngtcp2_conn_is_in_closing_period(c->conn) ||
      ngtcp2_conn_is_in_draining_period(c->conn)) {
    goto fin;
  }

  ngtcp2_path_storage_zero(&ps);

  nwrite = ngtcp2_conn_write_connection_close(
      c->conn, &ps.path, &pi, buf, sizeof(buf), &c->last_error, timestamp());
  if (nwrite < 0) {
    fprintf(stderr, "ngtcp2_conn_write_connection_close: %s\n",
            ngtcp2_strerror((int)nwrite));
    goto fin;
  }

  client_send_packet(c, buf, (size_t)nwrite);

fin:
  return;
}

static void read_cb(uv_poll_t *handle, int status, int mask) {
    if (handle->data == NULL)
    {
        return;
    }
  struct client *c = (struct client *)handle->data;

  if (client_read(c) != 0) {
    client_close(c);
    return;
  }

  if (client_write(c) != 0) {
    client_close(c);
  }
}

static void write_cb(uv_poll_t *handle, int status, int mask) {
    if (handle->data == NULL)
    {
        return;
    }
  struct client *c = (struct client *)handle->data;

  if (client_write(c) != 0) {
    client_close(c);
  }
}

static void timer_cb(uv_timer_t *w) {
  struct client *c = (struct client *)w->data;


  if (client_handle_expiry(c) != 0) {
    client_close(c);
    return;
  }

  if (client_write(c) != 0) {
    client_close(c);
  }

  send_test_message_to_server(c->conn, c);
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
  struct client *c = (struct client *)conn_ref->user_data;
  return c->conn;
}


static void client_free(struct client *c) {
  ngtcp2_conn_del(c->conn);
  SSL_free(c->ssl);
  SSL_CTX_free(c->ssl_ctx);
}


int init_debug_file() {
    char debug_file_name[255];
    if (snprintf(debug_file_name, 255, "debug.%ld.txt", timestamp())) {
        debug_file = fopen(debug_file_name, "w");
        if (!debug_file) {
            fprintf(stderr, "File opening failed!\n");
            return 1;
        }

        // Set the FILE to be line buffered
        if (setvbuf(debug_file, NULL, _IONBF, 0) != 0) {
            printf("Failed to set line buffering\n");
            return -1;
        }
    }
    else {
        printf("Couldn't allocate debug_file!");
        return 1;
    }

    return 0;
}
 

///////////////////////////////////
//
// ngtcp2 init functions
//
///////////////////////////////////

static int client_ssl_init(struct client* c) {
    c->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ssl_ctx) {
        fprintf(stderr, "SSL_CTX_new: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    if (ngtcp2_crypto_openssl_configure_client_context(c->ssl_ctx) != 0) {
        fprintf(stderr, "ngtcp2_crypto_openssl_configure_client_context failed\n");
        return -1;
    }

    c->ssl = SSL_new(c->ssl_ctx);
    if (!c->ssl) {
        fprintf(stderr, "SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    SSL_set_app_data(c->ssl, &c->conn_ref);
    SSL_set_connect_state(c->ssl);
    //SSL_set_alpn_protos(c->ssl, (const unsigned char *)ALPN, sizeof(ALPN) - 1);
    if (!numeric_host(REMOTE_HOST)) {
        SSL_set_tlsext_host_name(c->ssl, REMOTE_HOST);
    }

    /* For NGTCP2_PROTO_VER_V1 */
    SSL_set_quic_transport_version(c->ssl, TLSEXT_TYPE_quic_transport_parameters);

    return 0;
}

static void log_printf(void* user_data, const char* fmt, ...) {
    va_list ap;
    (void)user_data;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}

static int client_quic_init(struct client* c,
    const struct sockaddr* remote_addr,
    socklen_t remote_addrlen,
    const struct sockaddr* local_addr,
    socklen_t local_addrlen) {
    ngtcp2_path path = {
        {
            (struct sockaddr*)local_addr,
            local_addrlen,
        },
        {
            (struct sockaddr*)remote_addr,
            remote_addrlen,
        },
        NULL,
    };
    ngtcp2_callbacks callbacks = {
        ngtcp2_crypto_client_initial_cb,
        NULL, /* recv_client_initial */
        ngtcp2_crypto_recv_crypto_data_cb,
        handshake_completed, /* handshake_completed */
        NULL, /* recv_version_negotiation */
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        ngtcp2_crypto_hp_mask_cb,
        recv_stream_data, /* recv_stream_data */
        NULL, /* acked_stream_data_offset */
        stream_open, /* stream_open */
        stream_close, /* stream_close */
        NULL, /* recv_stateless_reset */
        ngtcp2_crypto_recv_retry_cb,
        extend_max_local_streams_bidi,
        NULL, /* extend_max_local_streams_uni */
        rand_cb,
        get_new_connection_id_cb,
        remove_connection_id,
        ngtcp2_crypto_update_key_cb,
        NULL, /* path_validation */
        NULL, /* select_preferred_address */
        NULL, /* stream_reset */
        NULL, /* extend_max_remote_streams_bidi */
        NULL, /* extend_max_remote_streams_uni */
        NULL, /* extend_max_stream_data */
        NULL, /* dcid_status */
        handshake_confirmed, /* handshake_confirmed */
        NULL, /* recv_new_token */
        ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        recv_datagram, /* recv_datagram */
        ack_datagram, /* ack_datagram */
        lost_datagram, /* lost_datagram */
        ngtcp2_crypto_get_path_challenge_data_cb,
        NULL, /* stream_stop_sending */
        ngtcp2_crypto_version_negotiation_cb,
        NULL, /* recv_rx_key */
        NULL, /* recv_tx_key */
        NULL, /* early_data_rejected */
    };
    ngtcp2_cid dcid, scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    int rv;

    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        return -1;
    }

    // COMMENTED OUT SINCE I DONT SEE THE PURPOSE
    scid.datalen = 8;
    if (RAND_bytes(scid.data, (int)scid.datalen) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        return -1;
    }

    ngtcp2_settings_default(&settings);

    settings.initial_ts = timestamp();
    settings.log_printf = log_printf;

    ngtcp2_transport_params_default(&params);

    params.initial_max_streams_uni = 3;
    params.initial_max_stream_data_bidi_local = 128 * 1024;
    params.initial_max_data = 1024 * 1024;

    rv =
        ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
            &callbacks, &settings, &params, NULL, c);
    if (rv != 0) {
        fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

    return 0;
}


static int client_init(struct client* c) {
    struct sockaddr_storage remote_addr, local_addr;
    socklen_t remote_addrlen, local_addrlen = sizeof(local_addr);

    memset(c, 0, sizeof(*c));

    ngtcp2_ccerr_default(&c->last_error);

    c->fd = create_sock((struct sockaddr*)&remote_addr, &remote_addrlen,
        REMOTE_HOST, REMOTE_PORT);
    if (c->fd == -1) {
        printf("Failed to create socket\n");
        return -1;
    }
    if (connect_sock((struct sockaddr*)&local_addr, &local_addrlen, c->fd,
        (struct sockaddr*)&remote_addr, remote_addrlen) != 0) {
        printf("Failed to connect to socket\n");
        return -1;
    }
    else {
        printf("Connected to socket\n");
    }

    memcpy(&c->local_addr, &local_addr, sizeof(c->local_addr));
    c->local_addrlen = local_addrlen;

    if (client_ssl_init(c) != 0) {
        printf("Failed SSL init\n");
        return -1;
    }

    printf("SSL init success!\n");

    if (client_quic_init(c, (struct sockaddr*)&remote_addr, remote_addrlen,
        (struct sockaddr*)&local_addr, local_addrlen) != 0) {
        printf("Failed client_quic_ini\n");
        return -1;
    }

    printf("client_quic_init SUCCESS!\n");

    c->remote_addr = remote_addr;
    c->stream.stream_id = -1;

    c->conn_ref.get_conn = get_conn;
    c->conn_ref.user_data = c;

    // This is difference from linux
    //
    // TODO check diff. CHECK libuv!
    uv_loop_init(&c->uv_loop);

    uv_poll_init_socket(&c->uv_loop, &c->handlePoll, c->fd);
    uv_timer_init(&c->uv_loop, &c->timer);
    c->handlePoll.data = c;
    //
    uv_poll_start(&c->handlePoll, UV_READABLE, read_cb);
    //uv_poll_start(&c->handlePoll, UV_WRITABLE, write_cb);

    uv_timer_start(&c->timer, timer_cb, 0, 1000.f);
    c->timer.data = c;

    return 0;
}

/////////////////////////////////////////
//
// EXCALIBUR API
//
/////////////////////////////////////////


// EXCALIBUR API
// Interface for sending messages to Excalibur (not the initial message after which we expect UUID)
static int send_message_to_server(ngtcp2_conn* conn, void* user_data, char* message) {
    struct client* c = static_cast<struct client*>(user_data);
    int rv;
    int64_t stream_id;

    if (c->stream.stream_id != -1) {
        fprintf(debug_file, "Stream already opened %ld, not sending %s\n", c->stream.stream_id, message);
        return 0;
    }

    rv = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);
    if (rv != 0) {
        return 0;
    }

    fprintf(debug_file, "WRITING TO client uni: stream_id: %ld, message: %s, size: %ld\n", stream_id, message, strlen(message));
    c->stream.stream_id = stream_id;
    c->stream.data = (const uint8_t*)message;
    c->stream.datalen = strlen(message);
    fprintf(debug_file, "WROTE TO client uni: c->stream.stream_id %ld, c->stream.data %s, c->stream.datalen %ld\n", c->stream.stream_id, c->stream.data, c->stream.datalen);

    return 0;
}

// EXCALIBUR API
static int send_test_message_to_server(ngtcp2_conn* conn, void* user_data) {
    if (uuid.empty()) {
        fprintf(debug_file, "Can't send messages to Excalibur: still waiting to receive UUID\n");
        return 0;
    }

    char* message = "";
    if (message_index < 7) {
        message = messages[message_index];
    }
    else {
        fprintf(debug_file, "No more messages to send, sending empty buffer to terminate connection\n");
    }

    fprintf(debug_file, "CURRENT MESSAGE: %s\n", message);

    int ret = send_message_to_server(conn, user_data, message);

    if (ret == 0) {
        message_index++;
    }

    return ret;
}


// EXCALIBUR API
static int send_hello_message_to_server(ngtcp2_conn* conn, void* user_data) {

    if (!hello_message) {
        fprintf(debug_file, "HELLO MESSAGE ALREADY SENT");
        return 0;
    }
    char* message = hello_message;
    fprintf(debug_file, "HELLO MESSAGE: %s\n", message);

    struct client* c = static_cast<struct client*>(user_data);
    int rv;
    int64_t stream_id;

    fprintf(debug_file, "CB: EXTEND_MAX_LOCAL_STREAMS_BIDI, STREAM_ID %ld\n", c->stream.stream_id);

    if (c->stream.stream_id != -1) {
        fprintf(debug_file, "Stream already opened %ld, not sending %s\n", c->stream.stream_id, message);
        return 0;
    }

    rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
    if (rv != 0) {
        return 0;
    }


    fprintf(debug_file, "WRITING TO client: stream_id: %lld, message: %s, size: %zd\n", stream_id, message, strlen(message));
    c->stream.stream_id = stream_id;
    c->stream.data = (const uint8_t*)message;
    c->stream.datalen = strlen(message);
    fprintf(debug_file, "WROTE TO client: c->stream.stream_id %ld, c->stream.data %s, c->stream.datalen %ld\n", c->stream.stream_id, c->stream.data, c->stream.datalen);

    hello_message = NULL;
    return 0;
}



////////////////////////
//
// UNUSED SECTION
//
////////////////////////
#if 0

#define HELLO_WORLD "hello world\n"

// Function to send the "hello world" packet
int send_hello_world_packet(struct client* c) {
    int len = strlen(HELLO_WORLD);

    // Create a new vector to hold the "hello world" message
    std::vector<uint8_t> buf(len + 1);
    memcpy(buf.data(), HELLO_WORLD, len);
    buf[len] = '\0';

    // Call ngtcp2_conn_write_pkt to send the packet over QUIC
    ngtcp2_pkt_info pi;
    memset(&pi, 0, sizeof(pi));
    ngtcp2_ssize pdatalen = 0;
    ngtcp2_path_storage ps;

    // Call ngtcp2_conn_write_pkt to send the packet over QUIC
    ngtcp2_path_storage_zero(&ps);
    // the correct stream ID needs to go here rather than 0
    /*ngtcp2_conn_writev_stream(ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi, uint8_t *dest,
    size_t destlen, ngtcp2_ssize *pdatalen, uint32_t flags, int64_t stream_id, const ngtcp2_vec *datav, size_t datavcnt, ngtcp2_tstamp ts)
    */
    auto start = std::chrono::system_clock::now();
    int fin;
    ngtcp2_vec datav;
    size_t datavcnt;
    ngtcp2_tstamp ts = std::chrono::system_clock::to_time_t(start);
    datavcnt = client_get_message(c, &c->stream.stream_id, &fin, &datav, 1);
    uint32_t flags;

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) {
        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    /* nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf, sizeof(buf),
                                        &pdatalen, flags, c->stream.stream_id, &datav,
                                        datavcnt, ts);*/
    int rv = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf.data(), sizeof(buf), &pdatalen, flags, c->stream.stream_id, &datav, datavcnt, ts);
    //rv = ngtcp2_conn_write_stream(c->conn, &ps.path, &pi, buf.data(), len, &pdatalen, 0, c->stream.stream_id, buf.data(), len, ts);
    if (rv != 0) {
        //try it twice?
        // rv = ngtcp2_conn_write_stream(c->conn, &ps.path, &pi, buf.data(), len, &pdatalen, 0, c->stream.stream_id, buf.data(), len, ts);

        return rv;
    }

    return 0;
}
#endif

static int extend_max_local_streams_bidi(ngtcp2_conn* conn,
    uint64_t max_streams,
    void* user_data) {
#ifdef MESSAGE
    struct client* c = (struct client*)user_data;
    int rv;
    int64_t stream_id;
    (void)max_streams;

    if (c->stream.stream_id != -1) {
        return 0;
    }

    rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
    if (rv != 0) {
        return 0;
    }

    c->stream.stream_id = stream_id;
    c->stream.data = (const uint8_t*)MESSAGE;
    c->stream.datalen = sizeof(MESSAGE) - 1;

    return 0;
#else  /* !MESSAGE */
    (void)conn;
    (void)max_streams;
    (void)user_data;

    return 0;
#endif /* !MESSAGE */
}


/////////////////////////////////////
//
// MAIN SECITON
//
/////////////////////////////////////


int main(void) {

    if (init_debug_file() != 0) {
        exit(EXIT_FAILURE);
    }

  struct client c = {};

  srand((unsigned int)timestamp());

  if (client_init(&c) != 0) {
    exit(EXIT_FAILURE);
  }
  
  // THIS also initiates the handshake as it calls ngtcp2_conn_writev_stream down the line
  // which in turn initiates the handshake if it's not yet completed
  if (client_write(&c) != 0) {
    exit(EXIT_FAILURE);
  }

  /*extend_max_local_streams_bidi(c.conn,
      10,
      &c);*/
     /*c.stream.data = (const uint8_t *)HELLO_WORLD;
     c.stream.datalen = sizeof(HELLO_WORLD) - 1;*/
  //  int rv = send_hello_world_packet(&c);
 

  uv_run(&c.uv_loop, UV_RUN_DEFAULT);


  client_free(&c);

  return 0;
}
