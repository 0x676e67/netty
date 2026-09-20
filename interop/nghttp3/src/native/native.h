/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
 * Copyright (c) 2021 ngtcp2 contributors
 * Copyright (c) 2026 ngtcp2 contributors
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

/*
 * Direct C benchmark adapter for the nghttp3 library with the ngtcp2 backend.
 *
 * Its QUIC/TLS skeleton and HTTP/3 bridge follow these fixed ngtcp2 sources:
 * https://github.com/ngtcp2/ngtcp2/blob/f3af8b14670bffa2e341b2bb45da75bc3ed71c46/examples/simpleclient.c
 * https://github.com/ngtcp2/ngtcp2/blob/f3af8b14670bffa2e341b2bb45da75bc3ed71c46/examples/http3_client_proto_codec.cc
 * https://github.com/ngtcp2/ngtcp2/blob/f3af8b14670bffa2e341b2bb45da75bc3ed71c46/examples/server.cc
 * https://github.com/ngtcp2/ngtcp2/blob/f3af8b14670bffa2e341b2bb45da75bc3ed71c46/examples/http3_server_proto_codec.cc
 * https://github.com/ngtcp2/ngtcp2/blob/f3af8b14670bffa2e341b2bb45da75bc3ed71c46/examples/tls_server_context_boringssl.cc
 * Fixed source license:
 * https://github.com/ngtcp2/ngtcp2/blob/f3af8b14670bffa2e341b2bb45da75bc3ed71c46/COPYING
 *
 * Its pending-send, read/write polling, and send-quantum boundaries were
 * cross-checked against curl's fixed ngtcp2 backend sources:
 * https://github.com/curl/curl/blob/69a224d6b48edb43df29cb69881ca8edc90f1527/lib/vquic/cf-ngtcp2.c
 * https://github.com/curl/curl/blob/69a224d6b48edb43df29cb69881ca8edc90f1527/lib/vquic/cf-ngtcp2-cmn.c
 * https://github.com/curl/curl/blob/69a224d6b48edb43df29cb69881ca8edc90f1527/lib/vquic/vquic.c
 * https://github.com/curl/curl/blob/69a224d6b48edb43df29cb69881ca8edc90f1527/lib/cf-socket.c
 * curl license:
 * https://github.com/curl/curl/blob/69a224d6b48edb43df29cb69881ca8edc90f1527/COPYING
 *
 * Linux UDP batching and offload limits are aligned with the exact Quinn
 * crates used by the Rust clients:
 * https://github.com/quinn-rs/quinn/blob/a96949f6cd257c665f544626af4e8ce668a40b30/quinn-udp/src/unix.rs
 * https://github.com/quinn-rs/quinn/blob/a7499b8439e393a6299330111d9c8564cd96c464/quinn/src/connection.rs
 * https://github.com/quinn-rs/quinn/blob/a7499b8439e393a6299330111d9c8564cd96c464/quinn/src/endpoint.rs
 * https://github.com/quinn-rs/quinn/blob/a7499b8439e393a6299330111d9c8564cd96c464/quinn/src/lib.rs
 * https://github.com/quinn-rs/quinn/blob/0343120eb7ccdd067a7e975613b96190c8562bf7/quinn-proto/src/config/mod.rs
 * https://github.com/quinn-rs/quinn/blob/a96949f6cd257c665f544626af4e8ce668a40b30/LICENSE-APACHE
 * https://github.com/quinn-rs/quinn/blob/a96949f6cd257c665f544626af4e8ce668a40b30/LICENSE-MIT
 * https://github.com/quinn-rs/quinn/blob/a7499b8439e393a6299330111d9c8564cd96c464/LICENSE-APACHE
 * https://github.com/quinn-rs/quinn/blob/a7499b8439e393a6299330111d9c8564cd96c464/LICENSE-MIT
 * https://github.com/quinn-rs/quinn/blob/0343120eb7ccdd067a7e975613b96190c8562bf7/LICENSE-APACHE
 * https://github.com/quinn-rs/quinn/blob/0343120eb7ccdd067a7e975613b96190c8562bf7/LICENSE-MIT
 *
 * This benchmark replaces the example's libev socket layer with a
 * single-threaded Windows/Linux/macOS polling loop. One unconnected UDP socket
 * serves one client QUIC connection; the server routes incoming connection IDs
 * on one listening socket. Linux batches receive syscalls and uses UDP
 * GRO/GSO when the kernel supports them; all platforms retain a per-datagram
 * fallback.
 */

#ifndef HTTP3_BENCH_NATIVE_H
#define HTTP3_BENCH_NATIVE_H

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#elif defined(__linux__) || defined(__APPLE__)
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#if defined(__linux__)
#include <netinet/udp.h>
#endif
#include <poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#else
#error "The nghttp3 benchmark supports only Windows, Linux and macOS"
#endif

#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "headers.h"

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#if !defined(NGTCP2_VERSION_NUM) || NGTCP2_VERSION_NUM != 0x011900
#error "ngtcp2 1.25.0 headers are required"
#endif

#if !defined(NGHTTP3_VERSION_NUM) || NGHTTP3_VERSION_NUM != 0x011200
#error "nghttp3 1.18.0 headers are required"
#endif

#if !defined(OPENSSL_IS_AWSLC) || !defined(AWSLC_API_VERSION) ||              \
  AWSLC_API_VERSION != 35
#error "AWS-LC API version 35 headers are required"
#endif

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"
#define REQUEST_PATH "/"
#define CA_PATH "examples/ca.cert"
#define TLS_CIPHER "TLS_AES_128_GCM_SHA256"
#define MAX_TX_UDP_PAYLOAD_SIZE 1350
/* Quinn caps each transmit at 10 GSO segments even when Linux supports 64. */
#define TX_AGGREGATE_MAX_SEGMENTS 10
#define TX_DATAGRAMS_PER_TURN 20
#define RX_GRO_MAX_SEGMENTS 64
#define TX_BATCH_CAPACITY                                              \
  (TX_AGGREGATE_MAX_SEGMENTS * MAX_TX_UDP_PAYLOAD_SIZE)
#define RX_CAPACITY 65535
#define RX_BATCH_SIZE 32
#define RX_SCALAR_BURST_SIZE 256
#define RX_TIME_BOUND_NS (50ULL * NGTCP2_MICROSECONDS)
#define RX_GRO_SEGMENT_CAPACITY 1472
#define RX_MESSAGE_CAPACITY                                              \
  (RX_GRO_MAX_SEGMENTS * RX_GRO_SEGMENT_CAPACITY)
#define STREAM_RECEIVE_WINDOW (1024 * 1024)
#define CONNECTION_RECEIVE_WINDOW (10 * 1024 * 1024)
#define NO_PROGRESS_NS (30ULL * NGTCP2_SECONDS)
#define CLOSE_FLUSH_NS (100ULL * NGTCP2_MILLISECONDS)
#define POLL_CAP_NS (10ULL * NGTCP2_MILLISECONDS)
#define CLIENT_CONNECTION_ID_LENGTH 16
#define SERVER_MAX_BIDI_STREAMS 1000
#define QPACK_TABLE_CAPACITY 4096
#define QPACK_BLOCKED_STREAMS 100

_Static_assert(RX_CAPACITY >= NGTCP2_MAX_UDP_PAYLOAD_SIZE,
               "CONNECTION_CLOSE needs the ngtcp2 client minimum buffer");
_Static_assert(RX_MESSAGE_CAPACITY >= RX_CAPACITY,
               "GRO receive slots must hold a full UDP datagram");
_Static_assert(RESPONSE_HEADERS_LEN < 64,
               "response fields must fit the validation mask");
_Static_assert(REQUEST_HEADERS_LEN < 64,
               "request fields must fit the validation mask");

#if defined(_WIN32)
typedef SOCKET socket_handle;
typedef WSAPOLLFD socket_pollfd;
#define INVALID_SOCKET_HANDLE INVALID_SOCKET
#define SOCKET_CALL_ERROR SOCKET_ERROR
#define SOCKET_READ_EVENT POLLRDNORM
#define SOCKET_WRITE_EVENT POLLWRNORM
#else
typedef int socket_handle;
typedef struct pollfd socket_pollfd;
#define INVALID_SOCKET_HANDLE (-1)
#define SOCKET_CALL_ERROR (-1)
#define SOCKET_READ_EVENT POLLIN
#define SOCKET_WRITE_EVENT POLLOUT
#endif

typedef struct response_state response_state;
typedef struct client client;
typedef struct udp_endpoint udp_endpoint;
typedef struct server_state server_state;
typedef struct server_stream server_stream;
typedef struct server_cid server_cid;
typedef struct native_trace native_trace;

typedef enum rx_drain_result {
  RX_DRAIN_FAILED = -1,
  RX_DRAIN_IDLE,
  RX_DRAIN_BURST,
  RX_DRAIN_BENCHMARK_COMPLETE
} rx_drain_result;

typedef struct bench_config {
  uint64_t requests;
  uint64_t expected_body_bytes;
  size_t inflight;
  size_t request_headers;
  size_t response_headers;
  bool qpack_request;
  bool qpack_response;
  const char *qpack_mode;
} bench_config;

struct udp_endpoint {
  socket_handle fd;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  struct sockaddr_storage remote_addr;
  socklen_t remote_addrlen;
  uint8_t rxbuf[RX_CAPACITY];
#if defined(__linux__)
  uint8_t (*rx_batch_storage)[RX_MESSAGE_CAPACITY];
  bool recvmmsg_supported;
  bool gso_supported;
#endif
};

struct response_state {
  int64_t stream_id;
  uint64_t body_bytes;
  uint64_t response_headers_seen;
  bool complete;
  bool headers_begin;
  bool headers_end;
  bool status_seen;
  bool content_length_seen;
};

/* Observe only the first HEADERS prefix; nghttp3 remains the protocol parser.
   Frame type/length can span receive callbacks or accepted output vectors. */
typedef struct header_prefix {
  uint64_t value;
  uint64_t frame_type;
  uint64_t remaining;
  uint8_t stage;
  uint8_t integer_left;
  bool dynamic;
} header_prefix;

struct server_stream {
  server_stream *next;
  server_stream *previous;
  int64_t stream_id;
  uint64_t template_seen;
  uint8_t pseudo_seen;
  bool headers_begin;
  bool headers_end;
  bool request_complete;
  bool body_submitted;
  /* Local churn fixture: bounded copied header, freed with its stream. */
  char churn[320];
  header_prefix request_prefix;
  header_prefix response_prefix;
};

struct server_cid {
  server_cid *next;
  ngtcp2_cid value;
};

struct client {
  udp_endpoint *endpoint;
  server_state *server;
  client *next;
  server_stream *streams;
  server_cid *cids;
  native_trace *trace;
  ngtcp2_cid initial_dcid;
  bool closed;
  uint64_t close_deadline_ns;

  SSL *ssl;
  ngtcp2_crypto_conn_ref conn_ref;
  ngtcp2_conn *qconn;
  nghttp3_conn *nghttp3_conn;
  int64_t control_stream_id;
  int64_t qpack_encoder_stream_id;
  int64_t qpack_decoder_stream_id;
  ngtcp2_ccerr last_error;

  response_state *responses;
  uint64_t target_requests;
  uint64_t expected_body_bytes;
  uint64_t started;
  uint64_t completed;
  uint64_t received_bytes;
  size_t inflight_limit;
  size_t request_headers;
  size_t response_headers;
  bool qpack_request;
  bool qpack_response;
  size_t active;

  bool handshake_completed;
  bool nghttp3_ready;
  bool fatal;
  char fatal_reason[384];

  uint8_t txbuf[TX_BATCH_CAPACITY];
  size_t pending_tx_len;
  size_t pending_tx_offset;
  size_t pending_tx_segment_size;
  struct sockaddr_storage pending_remote_addr;
  socklen_t pending_remote_addrlen;
  bool pending_tx_needs_pacing_update;
  uint64_t last_progress_ns;
};

struct server_state {
  SSL_CTX *ssl_ctx;
  bench_config config;
  client *connections;
  uint8_t *body;
  char content_length[32];
  bool allow_cancel;
  uint64_t canceled_streams;
  uint64_t reset_requests;
  uint64_t stopped_responses;
  uint64_t requests;
  uint64_t request_dynamic_sections;
  uint64_t response_dynamic_sections;
};

/* Private interfaces shared by the three native translation units. */
void client_http3_callbacks(nghttp3_callbacks *callbacks);
rx_drain_result server_receive_packet(
  udp_endpoint *endpoint, client *listener, const uint8_t *data, size_t datalen,
  struct sockaddr *remote_addr, socklen_t remote_addrlen, uint64_t ts);
void server_http3_callbacks(nghttp3_callbacks *callbacks);
void server_quic_callbacks(ngtcp2_callbacks *callbacks);
int socket_runtime_init(void);
void socket_runtime_cleanup(void);
int socket_last_error(void);
int socket_poll_one(socket_pollfd *pfd, uint64_t timeout_ns);
int monotonic_clock_init(void);
uint64_t timestamp_ns(void);
void set_fatal(client *c, const char *fmt, ...);
int set_nghttp3_failure(client *c, const char *where, int rv);
bool bytes_equal(nghttp3_vec value, const char *literal);
int extend_flow_control(client *c, int64_t stream_id, uint64_t amount);
nghttp3_nv make_nv(const char *name, const char *value);
int drive_tx(client *c);
rx_drain_result process_received_packet(
  udp_endpoint *endpoint, client *c, const uint8_t *data, size_t datalen,
  struct sockaddr *remote_addr, socklen_t remote_addrlen, uint64_t ts,
  bool stop_at_benchmark_completion);
rx_drain_result drain_rx(udp_endpoint *endpoint, client *c,
                                bool stop_at_benchmark_completion);
int handle_expiry(client *c, uint64_t now);
uint64_t poll_timeout_ns(client *c, uint64_t now);
int send_connection_close_best_effort(client *c,
                                             uint64_t close_started);
int create_udp_endpoint(udp_endpoint *endpoint, client *error_client);
void free_udp_endpoint(udp_endpoint *endpoint);
int init_tls(client *c, SSL_CTX *ssl_ctx);
int init_quic(client *c, const ngtcp2_pkt_hd *initial,
                      const ngtcp2_path *server_path);
void client_free(client *c);
bool parse_nonnegative_u64_arg(const char *text, uint64_t *value);
int parse_modes(const char *headers, const char *qpack,
                        bench_config *config);
SSL_CTX *create_tls_context(bool server);
int check_native_versions(void);

#endif /* HTTP3_BENCH_NATIVE_H */
