/*
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
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <ev.h>
#include <pthread.h>

#include <inttypes.h>

#define REMOTE_HOST "localhost"
#define REMOTE_PORT "2023"

FILE *debug_file;

int message_index = 0;

char * hello_message = "HELLO Excalibur!";
uint8_t *uuid = NULL;
char *messages[] = {
"First",
"Second",
"Third",
"Fourth",
"Fifth",
"Sixth",
"Seventh"
};

struct client client;
short outgoing_message_count = 0;

static uint64_t timestamp(void) {
  struct timespec tp;

  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

// pthread_mutex_t lock;

static int create_sock(struct sockaddr *addr, socklen_t *paddrlen,
                       const char *host, const char *port) {
  struct addrinfo hints = {0};
  struct addrinfo *res, *rp;
  int rv;
  int fd = -1;

  hints.ai_flags = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

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
                        size_t remote_addrlen) {
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

struct client {
  ngtcp2_crypto_conn_ref conn_ref;
  int fd;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  ngtcp2_conn *conn;

  struct {
    int64_t stream_id;
    const uint8_t *data;
    size_t datalen;
    size_t nwrite;
  } stream;

  ngtcp2_ccerr last_error;

  ev_io rev;
  ev_timer timer;
};

static int numeric_host_family(const char *hostname, int family) {
  uint8_t dst[sizeof(struct in6_addr)];
  return inet_pton(family, hostname, dst) == 1;
}

static int numeric_host(const char *hostname) {
  return numeric_host_family(hostname, AF_INET) ||
         numeric_host_family(hostname, AF_INET6);
}

static int client_ssl_init(struct client *c) {
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

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  size_t i;
  (void)rand_ctx;

  for (i = 0; i < destlen; ++i) {
    *dest = (uint8_t)random();
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

// EXCALIBUR API
// Interface for sending messages to Excalibur (not the initial message after which we expect UUID)
static int send_message_to_server(ngtcp2_conn *conn, void * user_data, char *message){
  struct client *c = user_data;
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
  c->stream.data = (const uint8_t *) message;
  c->stream.datalen = strlen(message);
  fprintf(debug_file, "WROTE TO client uni: c->stream.stream_id %ld, c->stream.data %s, c->stream.datalen %ld\n", c->stream.stream_id, c->stream.data, c->stream.datalen);

   return 0;
}

// EXCALIBUR API
static int send_test_message_to_server(ngtcp2_conn *conn, void * user_data) {
    if(!uuid) {
        fprintf(debug_file, "Can't send messages to Excalibur: still waiting to receive UUID\n");
        return 0;
    }

    char *message = "";
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

static int extend_max_local_streams_uni(ngtcp2_conn *conn,
                                         uint64_t max_streams,
                                         void *user_data){

    struct client *c = user_data;
    fprintf(debug_file, "CB: EXTEND_MAX_LOCAL_STREAMS_UNI, STREAM_ID %ld\n", c->stream.stream_id);
    send_test_message_to_server(conn, user_data);
}

//static int extend_max_local_streams_bidi(ngtcp2_conn *conn,
//                                         uint64_t max_streams,
//                                         void *user_data) {
//
//    send_hello_message_to_server(conn, user_data);
//}

// EXCALIBUR API
static int send_hello_message_to_server (ngtcp2_conn *conn, void * user_data) {

    if (!hello_message) {
        fprintf(debug_file, "HELLO MESSAGE ALREADY SENT");
        return 0;
    }
  char *message = hello_message;
  fprintf(debug_file, "HELLO MESSAGE: %s\n", message);

  struct client *c = user_data;
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


  fprintf(debug_file, "WRITING TO client: stream_id: %ld, message: %s, size: %ld\n", stream_id, message, strlen(message));
  c->stream.stream_id = stream_id;
  c->stream.data = (const uint8_t *) message;
  c->stream.datalen = strlen(message);
  fprintf(debug_file, "WROTE TO client: c->stream.stream_id %ld, c->stream.data %s, c->stream.datalen %ld\n", c->stream.stream_id, c->stream.data, c->stream.datalen);

  hello_message = NULL;
  return 0;
}

static void log_printf(void *user_data, const char *fmt, ...) {
  va_list ap;
  (void)user_data;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  fprintf(stderr, "\n");
}

int handshake_completed(ngtcp2_conn *conn, void *user_data) {

  printf("CB: HANDSHAKE COMPLETED!\n");

  send_hello_message_to_server(conn, user_data);

  return 0;
}

int handshake_confirmed(ngtcp2_conn *conn, void *user_data) {

    printf("CB: HANDSHAKE CONFIRMED!\n");

    return 0;
}

//int extend_max_remote_streams_bidi(ngtcp2_conn *conn, uint64_t max_streams, void *user_data){
//    struct client *c = user_data;
//    printf("CB: EXTEND_MAX_REMOTE_STREAMS_BIDI STREAM_ID: %ld,  data %s and max_streams %ld\n", c->stream.stream_id, c->stream.data, max_streams);
//    return 0;
//}
//
//
//int extend_max_remote_streams_uni(ngtcp2_conn *conn, uint64_t max_streams, void *user_data){
//    struct client *c = user_data;
//    printf("CB: EXTEND_MAX_REMOTE_STREAMS_UNI, STREAM_ID %ld, data %s and max_streams %ld\n", c->stream.stream_id, c->stream.data, max_streams);
//
//    return 0;
//}


int stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data){
    fprintf(debug_file, "CB: STREAM_OPEN, stream_id: %ld\n", stream_id);
    return 0;
}


int stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_user_data){
    struct client *c = user_data;
    fprintf(debug_file, "CB: STREAM_CLOSE, closed stream_id: %ld, client stream_id: %ld, ERROR_CODE: %ld\n", stream_id, c->stream.stream_id, app_error_code);
    return 0;
}

int recv_datagram(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data, size_t datalen, void *user_data){

    fprintf(debug_file, "CB: RECV_DATAGRAM %s", data);

    return 0;
}

int ack_datagram(ngtcp2_conn *conn, uint64_t dgram_id, void *user_data){
       fprintf(debug_file, "CB: ACK_DATAGRAM!!! %ld", dgram_id);

        return 0;
}

int lost_datagram(ngtcp2_conn *conn, uint64_t dgram_id, void *user_data){
        fprintf(debug_file, "CB: LOST_DATAGRAM!!! %ld", dgram_id);

        return 0;
}

int stream_reset(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size, uint64_t app_error_code, void *user_data, void *stream_user_data){
    fprintf(debug_file, "STREAM RESET! STREAM_ID: %ld\n", stream_id);
    return 0;
}

static int client_send_packet(struct client *c, const uint8_t *data,
                              size_t datalen) {
  struct iovec iov = {(uint8_t *)data, datalen};
  struct msghdr msg = {0};
  ssize_t nwrite;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  do {
    fprintf(debug_file, "[CLIENT SENDING PACKET] while nwrite == -1 (%ld) \n", nwrite);
    nwrite = sendmsg(c->fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    fprintf(stderr, "sendmsg: %s\n", strerror(errno));

    return -1;
  }

  fprintf(debug_file, "[[[[CLIENT SENT PACKET]]]] %s (%ld) \n", data, datalen);

  return 0;
}

// ngtcp2 CALLBACK
static int recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data) {
    fprintf(debug_file, "CB: RECV_STREAM_DATA, STREAM_ID: %ld, DATA: %s\n", stream_id, data);

    // EXCALIBUR API
    if (!uuid) {
        fprintf(debug_file, "Does this look like UUID? %s len: %ld\n", data, datalen);

         fprintf(debug_file, "[");
            for (int i = 0; i < datalen; i++){ fprintf(debug_file, "%d, ", data[i]);}
         fprintf(debug_file, "]\n");

        uuid = data;


      // TODO: should be a separate thread/ev_loop sending messages on an interval
        send_test_message_to_server(conn, user_data);
    }

    else{
        fprintf(debug_file, "RECEIVED RELIABLE MESSAGE %s len: %ld\n", data, datalen);
        // do something with reliable message
    }
    return 0;
}

// NOT used
static int decrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead, const ngtcp2_crypto_aead_ctx *aead_ctx, const uint8_t *ciphertext, size_t ciphertextlen, const uint8_t *nonce, size_t noncelen, const uint8_t *aad, size_t aadlen){
    int res = ngtcp2_crypto_decrypt_cb(dest, aead, aead_ctx, ciphertext, ciphertextlen, nonce, noncelen, aad, aadlen);
    if (res == 0) {
        //char out[] = (char *) dest;
        printf("Decrypted packet (%ld):\n", sizeof(dest));
        for (int i = 0; i < sizeof(dest); i++) {
            printf("%c ", dest[i]);
        }
        printf("\n");
    }
    else {
        printf("Failed decrypting packet %s\n", ciphertext);
    }
    return res;
}

// Not used
static int encrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead, const ngtcp2_crypto_aead_ctx *aead_ctx, const uint8_t *plaintext, size_t plaintextlen, const uint8_t *nonce, size_t noncelen, const uint8_t *aad, size_t aadlen){
     printf("ENCRYPTING packet (%ld):\n", plaintextlen);
    for (int i = 0; i < plaintextlen; i++) {
        printf("%c ", plaintext[i]);
    }
    printf("\n");
    return ngtcp2_crypto_encrypt_cb(dest, aead, aead_ctx, plaintext, plaintextlen, nonce, noncelen, aad, aadlen);
}


static int client_quic_init(struct client *c,
                            const struct sockaddr *remote_addr,
                            socklen_t remote_addrlen,
                            const struct sockaddr *local_addr,
                            socklen_t local_addrlen) {
  ngtcp2_path path = {
      {
          (struct sockaddr *)local_addr,
          local_addrlen,
      },
      {
          (struct sockaddr *)remote_addr,
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
      recv_stream_data,  /* recv_stream_data */
      NULL, /* acked_stream_data_offset */
      stream_open, /* stream_open */
      stream_close, /* stream_close */
      NULL, /* recv_stateless_reset */
      ngtcp2_crypto_recv_retry_cb,
      NULL, /* extend_max_local_streams_bidi, */
      NULL, /* extend_max_local_streams_uni, */
      rand_cb,
      get_new_connection_id_cb,
      NULL, /* remove_connection_id */
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
  params.max_datagram_frame_size = 65535;


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

static int client_read(struct client *c) {
  uint8_t buf[65536];
  struct sockaddr_storage addr;
  struct iovec iov = {buf, sizeof(buf)};
  struct msghdr msg = {0};
  ssize_t nread;
  ngtcp2_path path;
  ngtcp2_pkt_info pi = {0};
  int rv;

  msg.msg_name = &addr;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  for (;;) {
    msg.msg_namelen = sizeof(addr);

    nread = recvmsg(c->fd, &msg, MSG_DONTWAIT);

    fprintf(debug_file, "[CLIENT READ] %ld\n", nread);

    if (nread == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
      }

      break;
    }

    path.local.addrlen = c->local_addrlen;
    path.local.addr = (struct sockaddr *)&c->local_addr;
    path.remote.addrlen = msg.msg_namelen;
    path.remote.addr = msg.msg_name;

    rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, (size_t)nread,
                              timestamp());
    if (rv != 0) {
      fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
      if (!c->last_error.error_code) {
        if (rv == NGTCP2_ERR_CRYPTO) {
          ngtcp2_ccerr_set_tls_alert(
              &c->last_error, ngtcp2_conn_get_tls_alert(c->conn), NULL, 0);
        } else {
          ngtcp2_ccerr_set_liberr(&c->last_error, rv, NULL, 0);
        }
      }
      return -1;
    }
    else {
        fprintf(debug_file, "[CLIENT READ] %s\n", buf);
    }

  }

  return 0;
}

static size_t client_get_message(struct client *c, int64_t *pstream_id,
                                 int *pfin, ngtcp2_vec *datav,
                                 size_t datavcnt) {
  if (datavcnt == 0) {
    return 0;
  }

  if (c->stream.stream_id != -1){
    if(c->stream.nwrite < c->stream.datalen) {
    *pstream_id = c->stream.stream_id;
    *pfin = 1;
    datav->base = (uint8_t *)c->stream.data + c->stream.nwrite;
    datav->len = c->stream.datalen - c->stream.nwrite;
    fprintf(debug_file, "CLIENT_GET_MESSAGE (FIN): GOT MESSAGE! %s stream_id %ld, c->stream.datalen %ld c->stream.nwrite %ld \n", datav->base, c->stream.stream_id, c->stream.datalen, c->stream.nwrite);
    return 1;
   }
    else {
        fprintf(debug_file, "CLIENT_GET_MESSAGE RESETTING: c->stream.nwrite (%ld) >= c->stream.datalen (%ld)\n", c->stream.nwrite, c->stream.datalen);
        c->stream.nwrite = 0;
        c->stream.datalen = 0;
        c->stream.stream_id = -1;
    }
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
  uint8_t buf[16384];
  ngtcp2_path_storage ps;
  ngtcp2_vec datav;
  size_t datavcnt;
  int64_t stream_id;
  ngtcp2_ssize wdatalen;
  uint32_t flags;
  int fin;

  // SSL_set_msg_callback(c->ssl,SSL_trace);
  // SSL_set_msg_callback_arg(c->ssl,BIO_new_fp(stdout,0));

  ngtcp2_path_storage_zero(&ps);

  // Accumulate data from socket into buf until fin = 1 (no more data)
  for (;;) {
    datavcnt = client_get_message(c, &stream_id, &fin, &datav, 1);

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

    if (fin) {
      fprintf(debug_file, "FIN ngtcp2_conn_writev_stream buf %s, size %ld, stream_id %ld\n", buf, sizeof(buf), stream_id);
      flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
    }
    else {
        fprintf(debug_file, "NO FIN! ngtcp2_conn_writev_stream buf %s, size %ld, stream_id %ld\n", buf, sizeof(buf), stream_id);
    }

    nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf, sizeof(buf),
                                       &wdatalen, flags, stream_id, &datav,
                                       datavcnt, ts);
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_WRITE_MORE:
        c->stream.nwrite += (size_t)wdatalen;
        fprintf(debug_file, "[client_write_streams]  ngtcp2_conn_writev_stream NGTCP2_ERR_WRITE_MORE c->stream.nwrite %ld\n", c->stream.nwrite);
        continue;
      default:
        fprintf(stderr, "[client_write_streams] ngtcp2_conn_writev_stream: %s\n",
                ngtcp2_strerror((int)nwrite));
        ngtcp2_ccerr_set_liberr(&c->last_error, (int)nwrite, NULL, 0);
        return -1;
      }
    }

    if (nwrite == 0) {
      fprintf(debug_file, "[client_write_streams] 0 NWRITE from ngtcp2_conn_writev_stream, c->stream.nwrite %ld\n", c->stream.nwrite );
      // c->stream.nwrite = 0;
      return 0;
    }

    if (wdatalen > 0) {
        fprintf(debug_file, "[client_write_streams] increasing  c->stream.nwrite %ld by wdatalen %ld (nwrite was %ld) \n", c->stream.nwrite, (size_t) wdatalen, nwrite);
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
  ev_tstamp t;

  if (client_write_streams(c) != 0) {
    return -1;
  }

  expiry = ngtcp2_conn_get_expiry(c->conn);
  now = timestamp();

  t = expiry < now ? 1e-9 : (ev_tstamp)(expiry - now) / NGTCP2_SECONDS;

  c->timer.repeat = t;
  ev_timer_again(EV_DEFAULT, &c->timer);

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

  printf("Client closing\n");

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
  ev_break(EV_DEFAULT, EVBREAK_ALL);
}

static void read_cb(struct ev_loop *loop, ev_io *w, int revents) {
  struct client *c = w->data;
  (void)loop;
  (void)revents;

  if (client_read(c) != 0) {
    client_close(c);
    return;
  }

  if (client_write(c) != 0) {
    client_close(c);
  }
}

static void timer_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  struct client *c = w->data;
  (void)loop;
  (void)revents;

  if (client_handle_expiry(c) != 0) {
    client_close(c);
    return;
  }

  if (client_write(c) != 0) {
    client_close(c);
  }
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
  struct client *c = conn_ref->user_data;
  return c->conn;
}

static int client_init(struct client *c) {
  struct sockaddr_storage remote_addr, local_addr;
  socklen_t remote_addrlen, local_addrlen = sizeof(local_addr);

  memset(c, 0, sizeof(*c));

  ngtcp2_ccerr_default(&c->last_error);

  c->fd = create_sock((struct sockaddr *)&remote_addr, &remote_addrlen,
                      REMOTE_HOST, REMOTE_PORT);
  if (c->fd == -1) {
    printf("Created socket\n");
    return -1;
  }

  if (connect_sock((struct sockaddr *)&local_addr, &local_addrlen, c->fd,
                   (struct sockaddr *)&remote_addr, remote_addrlen) != 0) {
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

  if (client_quic_init(c, (struct sockaddr *)&remote_addr, remote_addrlen,
                       (struct sockaddr *)&local_addr, local_addrlen) != 0) {

    printf("Failed client_quic_init");
    return -1;
  }

  printf("client_quic_init SUCCESS!");

  c->stream.stream_id = -1;

  c->conn_ref.get_conn = get_conn;
  c->conn_ref.user_data = c;

  ev_io_init(&c->rev, read_cb, c->fd, EV_READ);
  c->rev.data = c;
  ev_io_start(EV_DEFAULT, &c->rev);

  ev_timer_init(&c->timer, timer_cb, 0., 0.);
  c->timer.data = c;

  printf("Client init SUCCESS!\n");

  return 0;
}

static void client_free(struct client *c) {
  ngtcp2_conn_del(c->conn);
  SSL_free(c->ssl);
  SSL_CTX_free(c->ssl_ctx);
}


// ASYNC INPUT LOOP STUFF -- deprecated (but keeping just in case we need better test inputs here)
ev_io stdin_watcher;   // input event watcher

static void
stdin_cb (EV_P_ ev_io *w, int revents)
{
    puts("Reading input\n");

    // char buffer[100];
    uint8_t buffer[1280];
    //while(read(STDIN_FILENO, &ch, 1) > 0) {}

    int read_ret = read (STDIN_FILENO, &buffer, 1280);

    if(read_ret > 0) {

        printf("Read %s (%ld) from stdin, sending to server\n", buffer, sizeof(buffer));

        int ret = client_send_packet(&client, (const uint8_t *) &buffer, (size_t) sizeof(&buffer));
        if ( ret != 0) {
            fprintf(stderr, "Client_send_packet returned %d", read_ret);
        }
    }
    else{
        fprintf(stderr, "READ ret <= 0 %d", read_ret);
    }
}

// another callback, this time for a time-out
static void
timeout_cb (EV_P_ ev_timer *w, int revents)
{
  puts ("timeout");
  // this causes the innermost ev_run to stop iterating
  ev_break (EV_A_ EVBREAK_ONE);
}


struct ev_loop *input_loop;

void* input_loop_thread(void* user_data)
{
    while(1){
        send_test_message_to_server(client.conn, user_data);
    }
//    printf("Enter input loop\n");  // Here one could initiate another timeout watcher
//    ev_loop(input_loop, 0);        // similar to the main loop - call it say timeout_cb1
    return NULL;
}

int init_debug_file(){
    char * debug_file_name;
    if (asprintf(&debug_file_name, "debug.%ld.txt", timestamp())) {
        debug_file = fopen(debug_file_name, "w");
        if (!debug_file) {
           fprintf(stderr, "File opening failed!\n");
           return 1;
        }
    }
    else {
        printf("Couldn't allocate debug_file!");
        return 1;
    }

    return 0;
}

pthread_t start_async_input_loop(){
    // deprecated this async loop listening on the input source, stdin, a file, a random generator, etc.)
    pthread_t thread;

    // This loop sits in the pthread
    // input_loop = ev_loop_new(0);

    // ev_io_init (&stdin_watcher, stdin_cb, /*STDIN_FILENO*/ 0, EV_READ);
    // ev_io_start (input_loop, &stdin_watcher);

    //pthread_create(&thread, NULL, input_loop_thread, NULL);

    return thread;
}
int main(void) {

   if (init_debug_file() != 0){
        exit(EXIT_FAILURE);
   }

  srandom((unsigned int) timestamp());

  if (client_init(&client) != 0) {
    exit(EXIT_FAILURE);
  }

  // THIS also initiates the handshake as it calls ngtcp2_conn_writev_stream down the line
  // which in turn initiates the handshake if it's not yet completed
  if (client_write(&client) != 0) {
    exit(EXIT_FAILURE);
  }

    // TODO: implement
    // input_loop_thread = start_async_input_loop();

    // Main loop listening on the socket
    ev_run(EV_DEFAULT, 0);

    // TODO: uncomment when implemented
   // pthread_join(input_loop_thread, NULL);

    client_free(&client);

    return 0;
}
