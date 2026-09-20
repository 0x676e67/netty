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

/* Shared nghttp3/ngtcp2 bridge, TLS, UDP polling and GRO/GSO transport.
   Fixed source references and private state are in native.h. */
#define HTTP3_BENCH_DEFINE_HEADERS
#include "native.h"

#define NATIVE_TRACE_CAPACITY 128

typedef struct native_trace_sample {
  uint64_t turn;
  uint64_t tx_ts_ns;
  uint64_t udp_bytes;
  uint64_t udp_datagrams;
  uint64_t turn_udp_bytes;
  uint64_t expiry_before_ns;
  uint64_t expiry_after_ns;
  size_t send_quantum;
  ngtcp2_conn_info info;
} native_trace_sample;

struct native_trace {
  uint64_t initial_ts_ns;
  uint64_t turns;
  uint64_t udp_bytes;
  uint64_t udp_datagrams;
  uint64_t previous_turn_udp_bytes;
  size_t sample_count;
  native_trace_sample samples[NATIVE_TRACE_CAPACITY];
};

#if defined(_WIN32)
static LARGE_INTEGER qpc_frequency;
#elif defined(__APPLE__)
/* Match Rust Instant on Darwin. Unlike CLOCK_MONOTONIC's wall-time/boot-time
   calculation, this raw uptime clock is not adjusted and excludes sleep.
   https://github.com/rust-lang/rust/blob/31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd/library/std/src/sys/time/unix.rs#L55-L74 */
static const clockid_t benchmark_clock = CLOCK_UPTIME_RAW;
#else
static const clockid_t benchmark_clock = CLOCK_MONOTONIC;
#endif

int socket_runtime_init(void) {
#if defined(_WIN32)
  WSADATA wsa;
  return WSAStartup(MAKEWORD(2, 2), &wsa);
#else
  return 0;
#endif
}

void socket_runtime_cleanup(void) {
#if defined(_WIN32)
  WSACleanup();
#endif
}

int socket_last_error(void) {
#if defined(_WIN32)
  return WSAGetLastError();
#else
  return errno;
#endif
}

static bool socket_error_would_block(int error) {
#if defined(_WIN32)
  return error == WSAEWOULDBLOCK;
#else
  return error == EAGAIN || error == EWOULDBLOCK;
#endif
}

static int socket_close(socket_handle fd) {
#if defined(_WIN32)
  return closesocket(fd);
#else
  return close(fd);
#endif
}

static int socket_set_nonblocking(socket_handle fd) {
#if defined(_WIN32)
  u_long nonblocking = 1;
  return ioctlsocket(fd, FIONBIO, &nonblocking);
#else
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

int socket_poll_one(socket_pollfd *pfd, uint64_t timeout_ns) {
  int rv;
  /* QUIC expiry includes pacing and ACK deadlines. Rounding every positive
     sub-millisecond delay to 1 ms can stall each serial request in a batch.
     Keep the deadline precision without turning short waits into busy polls.
     https://man7.org/linux/man-pages/man2/poll.2.html
     https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-select */
#if defined(_WIN32)
  fd_set readable, writable, exceptional;
  struct timeval timeout;
  FD_ZERO(&readable);
  FD_ZERO(&writable);
  FD_ZERO(&exceptional);
  if (pfd->events & SOCKET_READ_EVENT) {
    FD_SET(pfd->fd, &readable);
  }
  if (pfd->events & SOCKET_WRITE_EVENT) {
    FD_SET(pfd->fd, &writable);
  }
  FD_SET(pfd->fd, &exceptional);
  /* Callers cap each wait at POLL_CAP_NS (10 ms). */
  timeout.tv_sec = 0;
  timeout.tv_usec = (long)((timeout_ns +
                           NGTCP2_MICROSECONDS - 1) / NGTCP2_MICROSECONDS);
  pfd->revents = 0;
  rv = select(0, &readable, &writable, &exceptional, &timeout);
  if (rv > 0) {
    if (FD_ISSET(pfd->fd, &readable)) {
      pfd->revents |= SOCKET_READ_EVENT;
    }
    if (FD_ISSET(pfd->fd, &writable)) {
      pfd->revents |= SOCKET_WRITE_EVENT;
    }
    if (FD_ISSET(pfd->fd, &exceptional)) {
      pfd->revents |= POLLERR;
    }
  }
#else
  uint64_t started = timestamp_ns();
  uint64_t remaining = timeout_ns;
  for (;;) {
    struct timespec timeout = {
      .tv_sec = (time_t)(remaining / NGTCP2_SECONDS),
      .tv_nsec = (long)(remaining % NGTCP2_SECONDS),
    };
    pfd->revents = 0;
#if defined(__APPLE__)
    /* Darwin has no ppoll. pselect preserves sub-millisecond deadlines;
       poll's millisecond timeout would change native QUIC pacing. */
    fd_set readable, writable, exceptional;
    if (pfd->fd < 0 || pfd->fd >= FD_SETSIZE) {
      errno = EINVAL;
      return SOCKET_CALL_ERROR;
    }
    FD_ZERO(&readable);
    FD_ZERO(&writable);
    FD_ZERO(&exceptional);
    if (pfd->events & SOCKET_READ_EVENT) {
      FD_SET(pfd->fd, &readable);
    }
    if (pfd->events & SOCKET_WRITE_EVENT) {
      FD_SET(pfd->fd, &writable);
    }
    FD_SET(pfd->fd, &exceptional);
    rv = pselect(pfd->fd + 1, &readable, &writable, &exceptional, &timeout, NULL);
    if (rv > 0) {
      if (FD_ISSET(pfd->fd, &readable)) {
        pfd->revents |= SOCKET_READ_EVENT;
      }
      if (FD_ISSET(pfd->fd, &writable)) {
        pfd->revents |= SOCKET_WRITE_EVENT;
      }
      if (FD_ISSET(pfd->fd, &exceptional)) {
        pfd->revents |= POLLERR;
      }
    }
#else
    rv = ppoll(pfd, 1, &timeout, NULL);
#endif
    if (rv != SOCKET_CALL_ERROR || errno != EINTR) {
      break;
    }
    /* A signal must not restart the complete QUIC delay. */
    uint64_t elapsed = timestamp_ns() - started;
    if (elapsed >= timeout_ns) {
      pfd->revents = 0;
      rv = 0;
      break;
    }
    remaining = timeout_ns - elapsed;
  }
#endif
  return rv;
}

static int socket_send_datagram(socket_handle fd, const uint8_t *data,
                                size_t datalen,
                                const struct sockaddr *remote_addr,
                                socklen_t remote_addrlen) {
  if (datalen > INT_MAX) {
#if defined(_WIN32)
    WSASetLastError(WSAEMSGSIZE);
#else
    errno = EMSGSIZE;
#endif
    return SOCKET_CALL_ERROR;
  }
#if defined(_WIN32)
  return sendto(fd, (const char *)data, (int)datalen, 0, remote_addr,
                (int)remote_addrlen);
#else
  int rv;
  do {
    rv = (int)sendto(fd, data, datalen, 0, remote_addr, remote_addrlen);
  } while (rv == SOCKET_CALL_ERROR && errno == EINTR);
  return rv;
#endif
}

#if defined(__linux__) && defined(UDP_SEGMENT)
static int socket_send_gso(socket_handle fd, const uint8_t *data,
                           size_t datalen, size_t segment_size,
                           const struct sockaddr *remote_addr,
                           socklen_t remote_addrlen) {
  struct iovec iov;
  struct msghdr msg;
  struct cmsghdr *cmsg;
  union {
    struct cmsghdr align;
    uint8_t bytes[CMSG_SPACE(sizeof(uint16_t))];
  } control;
  uint16_t segment_size_u16;
  ssize_t rv;

  if (datalen == 0 || datalen > INT_MAX || segment_size == 0 ||
      segment_size > UINT16_MAX ||
      1 + (datalen - 1) / segment_size > TX_AGGREGATE_MAX_SEGMENTS) {
    errno = EMSGSIZE;
    return SOCKET_CALL_ERROR;
  }

  memset(&msg, 0, sizeof(msg));
  memset(&control, 0, sizeof(control));
  iov.iov_base = (void *)data;
  iov.iov_len = datalen;
  msg.msg_name = (void *)remote_addr;
  msg.msg_namelen = remote_addrlen;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control.bytes;
  msg.msg_controllen = sizeof(control.bytes);
  cmsg = CMSG_FIRSTHDR(&msg);
  if (cmsg == NULL) {
    errno = EINVAL;
    return SOCKET_CALL_ERROR;
  }
  cmsg->cmsg_level = SOL_UDP;
  cmsg->cmsg_type = UDP_SEGMENT;
  cmsg->cmsg_len = CMSG_LEN(sizeof(segment_size_u16));
  segment_size_u16 = (uint16_t)segment_size;
  memcpy(CMSG_DATA(cmsg), &segment_size_u16, sizeof(segment_size_u16));

  do {
    rv = sendmsg(fd, &msg, 0);
  } while (rv == SOCKET_CALL_ERROR && errno == EINTR);
  if (rv > INT_MAX) {
    errno = EOVERFLOW;
    return SOCKET_CALL_ERROR;
  }
  return (int)rv;
}

static bool socket_error_disables_gso(int error) {
  return error == EIO || error == EINVAL || error == ENOPROTOOPT ||
      error == EOPNOTSUPP;
}

static bool socket_supports_gso(void) {
  struct sockaddr_in local_addr;
  socket_handle fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  int segment_size = 1500;
  bool supported = false;

  if (fd == INVALID_SOCKET_HANDLE) {
    return false;
  }
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sin_family = AF_INET;
  local_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, (const struct sockaddr *)&local_addr, sizeof(local_addr)) == 0 &&
      setsockopt(fd, SOL_UDP, UDP_SEGMENT, &segment_size,
                 sizeof(segment_size)) == 0) {
    supported = true;
  }
  socket_close(fd);
  return supported;
}
#endif

static int socket_receive_datagram(socket_handle fd, uint8_t *data,
                                   size_t datalen,
                                   struct sockaddr *remote_addr,
                                   socklen_t *remote_addrlen) {
  if (datalen > INT_MAX) {
#if defined(_WIN32)
    WSASetLastError(WSAEMSGSIZE);
#else
    errno = EMSGSIZE;
#endif
    return SOCKET_CALL_ERROR;
  }
#if defined(_WIN32)
  return recvfrom(fd, (char *)data, (int)datalen, 0, remote_addr,
                  (int *)remote_addrlen);
#else
  socklen_t remote_capacity = *remote_addrlen;
  int rv;
  do {
    *remote_addrlen = remote_capacity;
    rv = (int)recvfrom(fd, data, datalen, 0, remote_addr, remote_addrlen);
  } while (rv == SOCKET_CALL_ERROR && errno == EINTR);
  return rv;
#endif
}

int monotonic_clock_init(void) {
#if defined(_WIN32)
  return QueryPerformanceFrequency(&qpc_frequency) &&
      qpc_frequency.QuadPart > 0
           ? 0
           : -1;
#else
  struct timespec now;
  return clock_gettime(benchmark_clock, &now);
#endif
}

uint64_t timestamp_ns(void) {
#if defined(_WIN32)
  LARGE_INTEGER now;
  uint64_t ticks;
  uint64_t freq;
  uint64_t secs;
  uint64_t rem;

  QueryPerformanceCounter(&now);
  ticks = (uint64_t)now.QuadPart;
  freq = (uint64_t)qpc_frequency.QuadPart;
  secs = ticks / freq;
  rem = ticks % freq;
  return secs * NGTCP2_SECONDS + rem * NGTCP2_SECONDS / freq;
#else
  struct timespec now;
  if (clock_gettime(benchmark_clock, &now) != 0) {
    /* A clock error is not timestamp zero: QUIC would see time go backwards. */
    perror("benchmark clock_gettime");
    exit(EXIT_FAILURE);
  }
  return (uint64_t)now.tv_sec * NGTCP2_SECONDS + (uint64_t)now.tv_nsec;
#endif
}

void set_fatal(client *c, const char *fmt, ...) {
  va_list ap;

  if (c->fatal) {
    return;
  }
  c->fatal = true;
  va_start(ap, fmt);
  vsnprintf(c->fatal_reason, sizeof(c->fatal_reason), fmt, ap);
  va_end(ap);
}

int set_nghttp3_failure(client *c, const char *where, int rv) {
  set_fatal(c, "%s: %s (%d)", where, nghttp3_strerror(rv), rv);
  ngtcp2_ccerr_set_application_error(
    &c->last_error, nghttp3_err_infer_quic_app_error_code(rv), NULL, 0);
  return NGHTTP3_ERR_CALLBACK_FAILURE;
}

bool bytes_equal(nghttp3_vec value, const char *literal) {
  size_t n = strlen(literal);
  return value.len == n && memcmp(value.base, literal, n) == 0;
}

int extend_flow_control(client *c, int64_t stream_id, uint64_t amount) {
  int rv;
  if (amount == 0) {
    return 0;
  }
  rv = ngtcp2_conn_extend_max_stream_offset(c->qconn, stream_id, amount);
  if (rv != 0) {
    set_fatal(c, "ngtcp2_conn_extend_max_stream_offset: %s (%d)",
              ngtcp2_strerror(rv), rv);
    return -1;
  }
  ngtcp2_conn_extend_max_offset(c->qconn, amount);
  return 0;
}

static int on_nghttp3_deferred_consume(
  nghttp3_conn *conn, int64_t stream_id, size_t consumed,
  void *conn_user_data, void *stream_user_data) {
  client *c = (client *)conn_user_data;
  (void)conn;
  (void)stream_user_data;
  return extend_flow_control(c, stream_id, (uint64_t)consumed) == 0
           ? 0
           : NGHTTP3_ERR_CALLBACK_FAILURE;
}

static int on_nghttp3_stop_sending(
  nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
  void *conn_user_data, void *stream_user_data) {
  client *c = (client *)conn_user_data;
  int rv;
  (void)conn;
  (void)stream_user_data;
  rv = ngtcp2_conn_shutdown_stream_read(c->qconn, 0, stream_id,
                                        app_error_code);
  if (rv != 0) {
    set_fatal(c, "ngtcp2 shutdown stream read failed: %s", ngtcp2_strerror(rv));
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int on_nghttp3_reset_stream(
  nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
  void *conn_user_data, void *stream_user_data) {
  client *c = (client *)conn_user_data;
  int rv;
  (void)conn;
  (void)stream_user_data;
  rv = ngtcp2_conn_shutdown_stream_write(c->qconn, 0, stream_id,
                                         app_error_code);
  if (rv != 0) {
    set_fatal(c, "ngtcp2 shutdown stream write failed: %s",
              ngtcp2_strerror(rv));
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static void on_nghttp3_rand(uint8_t *dest, size_t destlen) {
  if (destlen > INT_MAX || RAND_bytes(dest, (int)destlen) != 1) {
    abort();
  }
}

static void observe_header_prefix(header_prefix *prefix, const uint8_t *data,
                                  size_t datalen) {
  while (datalen != 0 && prefix->stage != 4) {
    if (prefix->stage == 2) {
      size_t consumed = datalen;
      if ((uint64_t)consumed > prefix->remaining) {
        consumed = (size_t)prefix->remaining;
      }
      data += consumed;
      datalen -= consumed;
      prefix->remaining -= consumed;
      if (prefix->remaining == 0) {
        prefix->stage = 0;
      }
      continue;
    }
    if (prefix->stage == 3) {
      /* RFC 9204 4.5.1.1: Encoded Insert Count is zero iff RIC is zero.
         Its 8-bit-prefixed integer's first byte therefore suffices; nghttp3
         still validates the full integer and all field representations.
         https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.1 */
      prefix->dynamic = *data != 0;
      prefix->stage = 4;
      return;
    }
    if (prefix->integer_left == 0) {
      prefix->integer_left = (uint8_t)((1u << (*data >> 6)) - 1u);
      prefix->value = *data & 0x3fu;
    } else {
      prefix->value = (prefix->value << 8) | *data;
      --prefix->integer_left;
    }
    ++data;
    --datalen;
    if (prefix->integer_left != 0) {
      continue;
    }
    if (prefix->stage == 0) {
      prefix->frame_type = prefix->value;
      prefix->stage = 1;
    } else {
      prefix->remaining = prefix->value;
      prefix->stage = prefix->remaining == 0 ? 0 :
        (prefix->frame_type == 1 ? 3 : 2);
    }
  }
}

static int setup_nghttp3(client *c) {
  nghttp3_callbacks callbacks;
  nghttp3_settings settings;
  int64_t control_stream_id;
  int64_t qpack_encoder_stream_id;
  int64_t qpack_decoder_stream_id;
  int rv;

  if (c->nghttp3_ready) {
    return 0;
  }
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.deferred_consume = on_nghttp3_deferred_consume;
  callbacks.stop_sending = on_nghttp3_stop_sending;
  callbacks.reset_stream = on_nghttp3_reset_stream;
  callbacks.rand = on_nghttp3_rand;

  if (c->server != NULL) {
    server_http3_callbacks(&callbacks);
  } else {
    client_http3_callbacks(&callbacks);
  }

  nghttp3_settings_default(&settings);
  settings.max_field_section_size = 64 * 1024;
  /* Exercise table turnover for custom fields in this local fixture. */
  settings.qpack_indexing_strat = NGHTTP3_QPACK_INDEXING_STRAT_EAGER;
  settings.qpack_max_dtable_capacity =
    (c->server != NULL ? c->qpack_request : c->qpack_response) ?
      QPACK_TABLE_CAPACITY : 0;
  settings.qpack_encoder_max_dtable_capacity =
    (c->server != NULL ? c->qpack_response : c->qpack_request) ?
      QPACK_TABLE_CAPACITY : 0;
  settings.qpack_blocked_streams = settings.qpack_max_dtable_capacity == 0 ?
    0 : QPACK_BLOCKED_STREAMS;

  rv = c->server != NULL ?
    nghttp3_conn_server_new(&c->nghttp3_conn, &callbacks, &settings,
                            nghttp3_mem_default(), c) :
    nghttp3_conn_client_new(&c->nghttp3_conn, &callbacks, &settings,
                            nghttp3_mem_default(), c);
  if (rv != 0) {
    return set_nghttp3_failure(c, "nghttp3_conn_new", rv);
  }
  if (c->server != NULL) {
    nghttp3_conn_set_max_client_streams_bidi(c->nghttp3_conn,
                                            SERVER_MAX_BIDI_STREAMS);
  }

  rv = ngtcp2_conn_open_uni_stream(c->qconn, &control_stream_id, NULL);
  if (rv != 0) {
    set_fatal(c, "open HTTP/3 control stream: %s", ngtcp2_strerror(rv));
    return -1;
  }
  rv = nghttp3_conn_bind_control_stream(c->nghttp3_conn, control_stream_id);
  if (rv != 0) {
    return set_nghttp3_failure(c, "nghttp3_conn_bind_control_stream", rv);
  }
  rv = ngtcp2_conn_open_uni_stream(c->qconn, &qpack_encoder_stream_id, NULL);
  if (rv != 0) {
    set_fatal(c, "open QPACK encoder stream: %s", ngtcp2_strerror(rv));
    return -1;
  }
  rv = ngtcp2_conn_open_uni_stream(c->qconn, &qpack_decoder_stream_id, NULL);
  if (rv != 0) {
    set_fatal(c, "open QPACK decoder stream: %s", ngtcp2_strerror(rv));
    return -1;
  }
  rv = nghttp3_conn_bind_qpack_streams(c->nghttp3_conn, qpack_encoder_stream_id,
                                        qpack_decoder_stream_id);
  if (rv != 0) {
    return set_nghttp3_failure(c, "nghttp3_conn_bind_qpack_streams", rv);
  }
  c->control_stream_id = control_stream_id;
  c->qpack_encoder_stream_id = qpack_encoder_stream_id;
  c->qpack_decoder_stream_id = qpack_decoder_stream_id;
  c->nghttp3_ready = true;
  c->last_progress_ns = timestamp_ns();
  return 0;
}

static int quic_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                                 int64_t stream_id, uint64_t offset,
                                 const uint8_t *data, size_t datalen,
                                 void *user_data, void *stream_user_data) {
  client *c = (client *)user_data;
  nghttp3_ssize consumed;
  (void)conn;
  (void)offset;
  if (c->server != NULL && ngtcp2_is_bidi_stream(stream_id)) {
    server_stream *stream = (server_stream *)stream_user_data;
    if (stream == NULL) {
      set_fatal(c, "request data without stream state");
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    observe_header_prefix(&stream->request_prefix, data, datalen);
  }
  if (c->nghttp3_conn == NULL) {
    set_fatal(c, "QUIC stream data arrived before nghttp3 setup");
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  consumed = nghttp3_conn_read_stream2(
    c->nghttp3_conn, stream_id, data, datalen,
    (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0,
    ngtcp2_conn_get_timestamp(c->qconn));
  if (consumed < 0) {
    set_nghttp3_failure(c, "nghttp3_conn_read_stream2", (int)consumed);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  if (extend_flow_control(c, stream_id, (uint64_t)consumed) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int quic_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                         uint64_t offset, uint64_t datalen,
                                         void *user_data,
                                         void *stream_user_data) {
  client *c = (client *)user_data;
  int rv;
  (void)conn;
  (void)offset;
  (void)stream_user_data;
  if (c->nghttp3_conn == NULL) {
    return 0;
  }
  rv = nghttp3_conn_add_ack_offset(c->nghttp3_conn, stream_id, datalen);
  if (rv != 0) {
    set_nghttp3_failure(c, "nghttp3_conn_add_ack_offset", rv);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int quic_extend_max_stream_data(ngtcp2_conn *conn, int64_t stream_id,
                                       uint64_t max_data, void *user_data,
                                       void *stream_user_data) {
  client *c = (client *)user_data;
  int rv;
  (void)conn;
  (void)max_data;
  (void)stream_user_data;
  if (c->nghttp3_conn == NULL) {
    return 0;
  }
  rv = nghttp3_conn_unblock_stream(c->nghttp3_conn, stream_id);
  if (rv != 0) {
    set_nghttp3_failure(c, "nghttp3_conn_unblock_stream", rv);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int quic_stream_reset(ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t final_size, uint64_t app_error_code,
                             void *user_data, void *stream_user_data) {
  client *c = (client *)user_data;
  int rv;
  (void)conn;
  (void)final_size;
  (void)app_error_code;
  (void)stream_user_data;
  if (c->nghttp3_conn == NULL) {
    return 0;
  }
  rv = nghttp3_conn_shutdown_stream_read(c->nghttp3_conn, stream_id);
  if (rv != 0) {
    set_nghttp3_failure(c, "nghttp3_conn_shutdown_stream_read", rv);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  if (c->server != NULL && c->server->allow_cancel &&
      ngtcp2_is_bidi_stream(stream_id) && app_error_code == NGHTTP3_H3_REQUEST_CANCELLED) {
    ++c->server->reset_requests;
    return 0;
  }
  set_fatal(c, "response stream %" PRId64 " was reset", stream_id);
  return NGTCP2_ERR_CALLBACK_FAILURE;
}

static int quic_stream_stop_sending(ngtcp2_conn *conn, int64_t stream_id,
                                    uint64_t app_error_code, void *user_data,
                                    void *stream_user_data) {
  client *c = (client *)user_data;
  int rv;
  (void)conn;
  (void)app_error_code;
  (void)stream_user_data;
  if (c->nghttp3_conn == NULL) {
    return 0;
  }
  /* The local endpoint stopped reading.  This is distinct from receiving a
     peer STOP_SENDING for our write side; see quic_recv_stop_sending. */
  rv = nghttp3_conn_shutdown_stream_read(c->nghttp3_conn, stream_id);
  if (rv != 0) {
    set_nghttp3_failure(c, "nghttp3_conn_shutdown_stream_read", rv);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int quic_recv_stop_sending(ngtcp2_conn *conn, int64_t stream_id,
                                  uint64_t app_error_code, void *user_data,
                                  void *stream_user_data) {
  client *c = (client *)user_data;
  (void)conn;
  (void)app_error_code;
  (void)stream_user_data;
  if (c->nghttp3_conn != NULL) {
    nghttp3_conn_shutdown_stream_write(c->nghttp3_conn, stream_id);
  }
  if (c->server != NULL && c->server->allow_cancel) {
    if (!ngtcp2_is_bidi_stream(stream_id) || app_error_code != NGHTTP3_H3_REQUEST_CANCELLED) {
      set_fatal(c, "unexpected STOP_SENDING in cancellation fixture");
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    ++c->server->stopped_responses;
  }
  return 0;
}

static int quic_stream_close2(ngtcp2_conn *conn, uint32_t flags,
                              int64_t stream_id, uint64_t rx_app_error_code,
                              uint64_t tx_app_error_code, void *user_data,
                              void *stream_user_data) {
  client *c = (client *)user_data;
  uint32_t nghttp3_flags = NGHTTP3_STREAM_CLOSE_FLAG_NONE;
  response_state *response = NULL;
  int rv;
  (void)conn;
  (void)stream_user_data;
  if (c->nghttp3_conn == NULL) {
    return 0;
  }
  if (c->server == NULL && ngtcp2_is_bidi_stream(stream_id)) {
    response = (response_state *)nghttp3_conn_get_stream_user_data(c->nghttp3_conn,
                                                                   stream_id);
  }
  if (flags & NGTCP2_STREAM_CLOSE2_FLAG_RX_APP_ERROR_CODE_SET) {
    nghttp3_flags |= NGHTTP3_STREAM_CLOSE_FLAG_RX_APP_ERROR_CODE_SET;
  }
  if (flags & NGTCP2_STREAM_CLOSE2_FLAG_TX_APP_ERROR_CODE_SET) {
    nghttp3_flags |= NGHTTP3_STREAM_CLOSE_FLAG_TX_APP_ERROR_CODE_SET;
  }
  rv = nghttp3_conn_close_stream2(c->nghttp3_conn, nghttp3_flags, stream_id,
                                  rx_app_error_code, tx_app_error_code);
  if (rv != 0 && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    set_nghttp3_failure(c, "nghttp3_conn_close_stream2", rv);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  if (c->server != NULL && ngtcp2_is_bidi_stream(stream_id)) {
    server_stream *stream = (server_stream *)stream_user_data;
    bool rx_error = (flags & NGTCP2_STREAM_CLOSE2_FLAG_RX_APP_ERROR_CODE_SET) &&
      rx_app_error_code != 0;
    bool tx_error = (flags & NGTCP2_STREAM_CLOSE2_FLAG_TX_APP_ERROR_CODE_SET) &&
      tx_app_error_code != 0;
    bool canceled = c->server->allow_cancel && (rx_error || tx_error) &&
      (!rx_error || rx_app_error_code == NGHTTP3_H3_REQUEST_CANCELLED) &&
      (!tx_error || tx_app_error_code == NGHTTP3_H3_REQUEST_CANCELLED);
    if (stream == NULL || (!canceled && (!stream->request_complete ||
        stream->response_prefix.stage != 4 || rx_error || tx_error))) {
      set_fatal(c, "request stream closed before a complete response");
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    if (stream->previous != NULL) {
      stream->previous->next = stream->next;
    } else {
      c->streams = stream->next;
    }
    if (stream->next != NULL) {
      stream->next->previous = stream->previous;
    }
    c->server->canceled_streams += canceled;
    free(stream);
    ngtcp2_conn_extend_max_streams_bidi(conn, 1);
    return 0;
  }
  if (ngtcp2_is_bidi_stream(stream_id)) {
    if (response != NULL && !response->complete) {
      set_fatal(c, "response stream %" PRId64 " closed before end_stream",
                stream_id);
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    if ((flags & NGTCP2_STREAM_CLOSE2_FLAG_RX_APP_ERROR_CODE_SET) &&
        rx_app_error_code != 0) {
      set_fatal(c, "response stream %" PRId64 " closed with RX error %" PRIu64,
                stream_id, rx_app_error_code);
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    if ((flags & NGTCP2_STREAM_CLOSE2_FLAG_TX_APP_ERROR_CODE_SET) &&
        tx_app_error_code != 0) {
      set_fatal(c, "request stream %" PRId64 " closed with TX error %" PRIu64,
                stream_id, tx_app_error_code);
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static int validate_tls_connection(client *c) {
  static const uint8_t expected_alpn[] = {'h', '3'};
  const uint8_t *selected = NULL;
  unsigned selected_len = 0;
  const SSL_CIPHER *cipher;
  const char *cipher_name;
  long verify_result;

  SSL_get0_alpn_selected(c->ssl, &selected, &selected_len);
  if (selected == NULL || selected_len != sizeof(expected_alpn) ||
      memcmp(selected, expected_alpn, sizeof(expected_alpn)) != 0) {
    set_fatal(c, "TLS negotiated an unexpected ALPN");
    return -1;
  }
  verify_result = SSL_get_verify_result(c->ssl);
  if (c->server == NULL && verify_result != X509_V_OK) {
    set_fatal(c, "TLS certificate verification failed: %ld", verify_result);
    return -1;
  }
  cipher = SSL_get_current_cipher(c->ssl);
  cipher_name = cipher != NULL ? SSL_CIPHER_get_name(cipher) : NULL;
  if (cipher_name == NULL || strcmp(cipher_name, TLS_CIPHER) != 0) {
    set_fatal(c, "TLS negotiated unexpected cipher %s",
              cipher_name != NULL ? cipher_name : "(null)");
    return -1;
  }
  if (SSL_get_group_id(c->ssl) != SSL_GROUP_X25519) {
    set_fatal(c, "TLS negotiated an unexpected key exchange group");
    return -1;
  }
  return 0;
}

static int quic_handshake_completed(ngtcp2_conn *conn, void *user_data) {
  client *c = (client *)user_data;
  (void)conn;
  if (validate_tls_connection(c) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  c->handshake_completed = true;
  return 0;
}

static int quic_recv_rx_key(ngtcp2_conn *conn, ngtcp2_encryption_level level,
                            void *user_data) {
  client *c = (client *)user_data;
  (void)conn;
  if (level != NGTCP2_ENCRYPTION_LEVEL_1RTT) {
    return 0;
  }
  return setup_nghttp3(c) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static void quic_rand(uint8_t *dest, size_t destlen,
                      const ngtcp2_rand_ctx *rand_ctx) {
  (void)rand_ctx;
  if (destlen > INT_MAX || RAND_bytes(dest, (int)destlen) != 1) {
    abort();
  }
}

static int quic_get_new_connection_id(
  ngtcp2_conn *conn, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *token,
  size_t cidlen, void *user_data) {
  client *c = (client *)user_data;
  (void)conn;
  if (cidlen != CLIENT_CONNECTION_ID_LENGTH || cidlen > INT_MAX ||
      RAND_bytes(cid->data, (int)cidlen) != 1 ||
      RAND_bytes(token->data, (int)sizeof(token->data)) != 1) {
    set_fatal(c, "could not create fixed-length local QUIC connection ID");
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;
  if (c->server != NULL) {
    server_cid *entry = malloc(sizeof(*entry));
    if (entry == NULL) {
      set_fatal(c, "could not register server connection ID");
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    entry->value = *cid;
    entry->next = c->cids;
    c->cids = entry;
  }
  return 0;
}

static int quic_remove_connection_id(ngtcp2_conn *conn,
                                     const ngtcp2_cid *cid,
                                     void *user_data) {
  (void)conn;
  client *c = (client *)user_data;
  server_cid **entry = &c->cids;
  while (*entry != NULL) {
    if (ngtcp2_cid_eq(&(*entry)->value, cid)) {
      server_cid *removed = *entry;
      *entry = removed->next;
      free(removed);
      break;
    }
    entry = &(*entry)->next;
  }
  return 0;
}

static int quic_extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                               uint64_t max_streams,
                                               void *user_data) {
  (void)conn;
  (void)max_streams;
  (void)user_data;
  return 0;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
  client *c = (client *)conn_ref->user_data;
  return c->qconn;
}

nghttp3_nv make_nv(const char *name, const char *value) {
  nghttp3_nv nv;
  nv.name = (uint8_t *)name;
  nv.value = (uint8_t *)value;
  nv.namelen = strlen(name);
  nv.valuelen = strlen(value);
  nv.flags = NGHTTP3_NV_FLAG_NONE;
  return nv;
}

static ngtcp2_ssize write_nghttp3_packet(
  ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi, uint8_t *dest,
  size_t destlen, ngtcp2_tstamp ts, void *user_data) {
  client *c = (client *)user_data;
  nghttp3_vec nghttp3_vecs[16];
  ngtcp2_vec qvec[16];
  size_t i;

  for (;;) {
    int64_t stream_id = -1;
    int fin = 0;
    nghttp3_ssize nghttp3_vec_count = 0;
    ngtcp2_ssize datalen = -1;
    ngtcp2_ssize nwrite;
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

    if (c->nghttp3_conn != NULL && ngtcp2_conn_get_max_data_left2(conn) != 0) {
      nghttp3_vec_count = nghttp3_conn_writev_stream(
        c->nghttp3_conn, &stream_id, &fin, nghttp3_vecs,
        sizeof(nghttp3_vecs) / sizeof(nghttp3_vecs[0]));
      if (nghttp3_vec_count < 0) {
        set_nghttp3_failure(c, "nghttp3_conn_writev_stream",
                            (int)nghttp3_vec_count);
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
    }
    for (i = 0; i < (size_t)nghttp3_vec_count; ++i) {
      qvec[i].base = nghttp3_vecs[i].base;
      qvec[i].len = nghttp3_vecs[i].len;
    }
    if (fin) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }
    nwrite = ngtcp2_conn_writev_stream(conn, path, pi, dest, destlen, &datalen,
                                       flags, stream_id, qvec,
                                       (size_t)nghttp3_vec_count, ts);
    if (c->server != NULL && datalen > 0 && ngtcp2_is_bidi_stream(stream_id) &&
        (nwrite >= 0 || nwrite == NGTCP2_ERR_WRITE_MORE)) {
      server_stream *stream = nghttp3_conn_get_stream_user_data(
        c->nghttp3_conn, stream_id);
      size_t remaining = (size_t)datalen;
      if (stream == NULL) {
        set_fatal(c, "response write without stream state");
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
      if (stream->response_prefix.stage != 4) {
        for (i = 0; i < (size_t)nghttp3_vec_count && remaining != 0; ++i) {
          size_t consumed = qvec[i].len < remaining ? qvec[i].len : remaining;
          observe_header_prefix(&stream->response_prefix, qvec[i].base, consumed);
          remaining -= consumed;
        }
        if (stream->response_prefix.stage == 4) {
          c->server->response_dynamic_sections += stream->response_prefix.dynamic;
        }
      }
    }
    if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
      nghttp3_conn_block_stream(c->nghttp3_conn, stream_id);
      continue;
    }
    if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
      nghttp3_conn_shutdown_stream_write(c->nghttp3_conn, stream_id);
      continue;
    }
    if (nwrite == NGTCP2_ERR_WRITE_MORE) {
      if (datalen < 0) {
        set_fatal(c, "NGTCP2_ERR_WRITE_MORE without accepted bytes");
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
      if (nghttp3_conn_add_write_offset(c->nghttp3_conn, stream_id,
                                        (uint64_t)datalen) != 0) {
        set_fatal(c, "nghttp3_conn_add_write_offset failed");
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
      continue;
    }
    if (nwrite < 0) {
      set_fatal(c, "ngtcp2_conn_writev_stream: %s (%d)",
                ngtcp2_strerror((int)nwrite), (int)nwrite);
      ngtcp2_ccerr_set_liberr(&c->last_error, (int)nwrite, NULL, 0);
      return nwrite;
    }
    if (datalen >= 0 && c->nghttp3_conn != NULL) {
      int rv = nghttp3_conn_add_write_offset(c->nghttp3_conn, stream_id,
                                              (uint64_t)datalen);
      if (rv != 0) {
        set_nghttp3_failure(c, "nghttp3_conn_add_write_offset", rv);
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
    }
    return nwrite;
  }
}

static int send_pending(client *c) {
  if (c->pending_tx_len == 0) {
    return 0;
  }

  if (c->pending_tx_offset > c->pending_tx_len ||
      c->pending_tx_segment_size == 0) {
    set_fatal(c, "invalid pending UDP batch state");
    return -1;
  }

  while (c->pending_tx_offset < c->pending_tx_len) {
    size_t remaining = c->pending_tx_len - c->pending_tx_offset;
    size_t datalen = remaining < c->pending_tx_segment_size
        ? remaining
        : c->pending_tx_segment_size;
    int nwrite;
    int socket_error;

#if defined(__linux__) && defined(UDP_SEGMENT)
    if (c->endpoint->gso_supported && c->pending_tx_offset == 0 &&
        remaining > c->pending_tx_segment_size) {
      nwrite = socket_send_gso(
        c->endpoint->fd, c->txbuf, remaining, c->pending_tx_segment_size,
        (const struct sockaddr *)&c->pending_remote_addr,
        c->pending_remote_addrlen);
      if (nwrite == SOCKET_CALL_ERROR) {
        socket_error = socket_last_error();
        if (socket_error_would_block(socket_error)) {
          return 1;
        }
        if (socket_error_disables_gso(socket_error)) {
          c->endpoint->gso_supported = false;
          continue;
        }
        set_fatal(c, "GSO send: socket error %d", socket_error);
        return -1;
      }
      if ((size_t)nwrite != remaining) {
        set_fatal(c, "partial UDP GSO send: %d/%zu", nwrite, remaining);
        return -1;
      }
      c->pending_tx_offset = c->pending_tx_len;
    } else
#endif
    {
      nwrite = socket_send_datagram(
        c->endpoint->fd, c->txbuf + c->pending_tx_offset, datalen,
        (const struct sockaddr *)&c->pending_remote_addr,
        c->pending_remote_addrlen);
      if (nwrite == SOCKET_CALL_ERROR) {
        socket_error = socket_last_error();
        if (socket_error_would_block(socket_error)) {
          return 1;
        }
        set_fatal(c, "send: socket error %d", socket_error);
        return -1;
      }
      if ((size_t)nwrite != datalen) {
        set_fatal(c, "partial UDP send: %d/%zu", nwrite, datalen);
        return -1;
      }
      c->pending_tx_offset += datalen;
    }
    if (c->trace != NULL && c->trace->sample_count < NATIVE_TRACE_CAPACITY) {
      /* Count accepted UDP sends, not packets only generated by QUIC. Stop
         counting with the bounded sample window, including resumed sends. */
      c->trace->udp_bytes += (uint64_t)nwrite;
      c->trace->udp_datagrams +=
        1 + ((uint64_t)nwrite - 1) / c->pending_tx_segment_size;
    }
  }

  c->pending_tx_len = 0;
  c->pending_tx_offset = 0;
  c->pending_tx_segment_size = 0;
  return 0;
}

static void finish_tx_turn(client *c) {
  if (c->pending_tx_needs_pacing_update) {
    native_trace *trace = c->trace;
    native_trace_sample *sample = NULL;
    uint64_t tx_ts;
    if (trace != NULL && trace->sample_count < NATIVE_TRACE_CAPACITY) {
      ++trace->turns;
      if (trace->turns <= 16 || trace->turns % 64 == 0) {
        sample = &trace->samples[trace->sample_count++];
        sample->expiry_before_ns = ngtcp2_conn_get_expiry2(c->qconn);
      }
    }
    /* Preserve the original clock read immediately before the pacing update.
       Diagnostics must not perform an extra write or pacing update. */
    tx_ts = timestamp_ns();
    ngtcp2_conn_update_pkt_tx_time(c->qconn, tx_ts);
    c->pending_tx_needs_pacing_update = false;
    if (sample != NULL) {
      sample->expiry_after_ns = ngtcp2_conn_get_expiry2(c->qconn);
      sample->turn = trace->turns;
      sample->tx_ts_ns = tx_ts;
      sample->udp_bytes = trace->udp_bytes;
      sample->udp_datagrams = trace->udp_datagrams;
      sample->turn_udp_bytes = trace->udp_bytes - trace->previous_turn_udp_bytes;
      sample->send_quantum = ngtcp2_conn_get_send_quantum2(c->qconn);
      ngtcp2_conn_get_conn_info2(c->qconn, &sample->info);
    }
    if (trace != NULL) {
      trace->previous_turn_udp_bytes = trace->udp_bytes;
    }
  }
}

int drive_tx(client *c) {
  size_t datagrams_sent = 0;
  size_t send_quantum_remaining;
  bool had_pending = c->pending_tx_len != 0;
  int rv = send_pending(c);
  if (rv != 0) {
    return rv < 0 ? -1 : 0;
  }
  if (had_pending) {
    finish_tx_turn(c);
    /* A resumed syscall finishes the prior send quantum. Start fresh packet
       generation on the next event-loop turn. */
    return 1;
  }
  send_quantum_remaining = ngtcp2_conn_get_send_quantum2(c->qconn);
  if (send_quantum_remaining == 0) {
    return 0;
  }

  for (;;) {
    ngtcp2_path_storage path_storage;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite;
    uint64_t batch_ts;
    size_t batch_capacity;
    size_t batch_datagrams;
    size_t max_aggregate_packets = 1;
    size_t path_max_udp_payload_size;
    size_t segment_size = 0;
#if defined(__linux__) && defined(UDP_SEGMENT)
    if (c->endpoint->gso_supported) {
      max_aggregate_packets = TX_AGGREGATE_MAX_SEGMENTS;
    }
#endif
    if (max_aggregate_packets > TX_DATAGRAMS_PER_TURN - datagrams_sent) {
      max_aggregate_packets = TX_DATAGRAMS_PER_TURN - datagrams_sent;
    }
    path_max_udp_payload_size =
      ngtcp2_conn_get_path_max_tx_udp_payload_size2(c->qconn);
    batch_capacity = sizeof(c->txbuf);
    if (batch_capacity > send_quantum_remaining) {
      batch_capacity = send_quantum_remaining;
    }
    if (batch_capacity < path_max_udp_payload_size) {
      batch_capacity = path_max_udp_payload_size;
    }
    if (batch_capacity > sizeof(c->txbuf)) {
      set_fatal(c, "QUIC path payload size exceeds the UDP batch buffer");
      return -1;
    }

    batch_ts = timestamp_ns();
    memset(&pi, 0, sizeof(pi));
    ngtcp2_path_storage_zero(&path_storage);
    nwrite = ngtcp2_conn_write_aggregate_pkt2(
      c->qconn, &path_storage.path, &pi, c->txbuf, batch_capacity,
      &segment_size, write_nghttp3_packet, max_aggregate_packets, batch_ts);
    if (nwrite < 0) {
      if (!c->fatal) {
        set_fatal(c, "ngtcp2_conn_write_aggregate_pkt2: %s (%d)",
                  ngtcp2_strerror((int)nwrite), (int)nwrite);
      }
      return -1;
    }
    if (nwrite == 0) {
      finish_tx_turn(c);
      return 0;
    }
    if (segment_size == 0 || segment_size > (size_t)nwrite) {
      set_fatal(c, "ngtcp2 returned an invalid UDP segment size");
      return -1;
    }
    batch_datagrams = 1 + ((size_t)nwrite - 1) / segment_size;
    if (batch_datagrams > max_aggregate_packets) {
      set_fatal(c, "ngtcp2 exceeded the UDP aggregate segment limit");
      return -1;
    }
    if (path_storage.path.remote.addr == NULL ||
        path_storage.path.remote.addrlen <= 0 ||
        (size_t)path_storage.path.remote.addrlen >
          sizeof(c->pending_remote_addr)) {
      set_fatal(c, "ngtcp2 returned an invalid UDP destination address");
      return -1;
    }
    memcpy(&c->pending_remote_addr, path_storage.path.remote.addr,
           (size_t)path_storage.path.remote.addrlen);
    c->pending_remote_addrlen = (socklen_t)path_storage.path.remote.addrlen;
    c->pending_tx_len = (size_t)nwrite;
    c->pending_tx_offset = 0;
    c->pending_tx_segment_size = segment_size;
    c->pending_tx_needs_pacing_update = true;
    rv = send_pending(c);
    if (rv < 0) {
      return -1;
    }
    if (rv > 0) {
      return 0;
    }
    datagrams_sent += batch_datagrams;
    if ((size_t)nwrite >= send_quantum_remaining) {
      send_quantum_remaining = 0;
    } else {
      send_quantum_remaining -= (size_t)nwrite;
    }
    if (datagrams_sent == TX_DATAGRAMS_PER_TURN ||
        send_quantum_remaining == 0) {
      finish_tx_turn(c);
      return 1;
    }
  }
}

rx_drain_result process_received_packet(
  udp_endpoint *endpoint, client *c, const uint8_t *data, size_t datalen,
  struct sockaddr *remote_addr, socklen_t remote_addrlen, uint64_t ts,
  bool stop_at_benchmark_completion) {
  ngtcp2_path path;
  ngtcp2_pkt_info pi;
  int rv;

  if (remote_addrlen == 0 ||
      (size_t)remote_addrlen > sizeof(struct sockaddr_storage)) {
    set_fatal(c, "received UDP datagram with an invalid source address");
    return RX_DRAIN_FAILED;
  }
  if (c->server != NULL && c->qconn == NULL) {
    return server_receive_packet(endpoint, c, data, datalen, remote_addr,
                                  remote_addrlen, ts);
  }

  memset(&path, 0, sizeof(path));
  path.local.addr = (struct sockaddr *)&endpoint->local_addr;
  path.local.addrlen = (socklen_t)endpoint->local_addrlen;
  path.remote.addr = remote_addr;
  path.remote.addrlen = remote_addrlen;
  path.user_data = c;
  memset(&pi, 0, sizeof(pi));
  rv = ngtcp2_conn_read_pkt(c->qconn, &path, &pi, data, datalen, ts);
  if (c->server != NULL && rv == NGTCP2_ERR_DRAINING) {
    const ngtcp2_ccerr *error = ngtcp2_conn_get_ccerr2(c->qconn);
    if ((error->type == NGTCP2_CCERR_TYPE_APPLICATION &&
         error->error_code == NGHTTP3_H3_NO_ERROR) ||
        (error->type == NGTCP2_CCERR_TYPE_TRANSPORT && error->error_code == 0)) {
      c->closed = true;
      c->close_deadline_ns = ts + CLOSE_FLUSH_NS;
      return RX_DRAIN_BURST;
    }
  }
  if (rv != 0) {
    if (!c->last_error.error_code) {
      if (rv == NGTCP2_ERR_CRYPTO) {
        ngtcp2_ccerr_set_tls_alert(
          &c->last_error, ngtcp2_conn_get_tls_alert2(c->qconn), NULL, 0);
      } else {
        ngtcp2_ccerr_set_liberr(&c->last_error, rv, NULL, 0);
      }
    }
    set_fatal(c,
              "ngtcp2_conn_read_pkt: %s (%d), started=%" PRIu64
              " completed=%" PRIu64 " active=%zu",
              ngtcp2_strerror(rv), rv, c->started, c->completed, c->active);
    return RX_DRAIN_FAILED;
  }
  c->last_progress_ns = ts;
  if (stop_at_benchmark_completion && c->completed == c->target_requests) {
    return RX_DRAIN_BENCHMARK_COMPLETE;
  }
  return RX_DRAIN_BURST;
}

static rx_drain_result drain_rx_scalar(udp_endpoint *endpoint, client *c,
                                       bool stop_at_benchmark_completion) {
  size_t packet_count;
  for (packet_count = 0; packet_count < RX_SCALAR_BURST_SIZE;
       ++packet_count) {
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen = (socklen_t)sizeof(remote_addr);
    int nread = socket_receive_datagram(
      endpoint->fd, endpoint->rxbuf, sizeof(endpoint->rxbuf),
      (struct sockaddr *)&remote_addr, &remote_addrlen);
    int socket_error;
    rx_drain_result result;

    if (nread == SOCKET_CALL_ERROR) {
      socket_error = socket_last_error();
      if (socket_error_would_block(socket_error)) {
        return RX_DRAIN_IDLE;
      }
      set_fatal(c, "recvfrom: socket error %d", socket_error);
      return RX_DRAIN_FAILED;
    }
    if (nread == 0) {
      continue;
    }
    result = process_received_packet(
      endpoint, c, endpoint->rxbuf, (size_t)nread,
      (struct sockaddr *)&remote_addr, remote_addrlen, timestamp_ns(),
      stop_at_benchmark_completion);
    if (result != RX_DRAIN_BURST) {
      return result;
    }
  }
  return RX_DRAIN_BURST;
}

#if defined(__linux__)
typedef union udp_control_buffer {
  struct cmsghdr align;
  uint8_t bytes[CMSG_SPACE(sizeof(int))];
} udp_control_buffer;

static int udp_gro_segment_size(client *c, struct msghdr *msg,
                                size_t message_len, size_t *segment_size) {
  struct cmsghdr *cmsg;
  *segment_size = message_len;
#if defined(UDP_GRO)
  for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
       cmsg = CMSG_NXTHDR(msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO) {
      int value;
      if (cmsg->cmsg_len < CMSG_LEN(sizeof(value))) {
        set_fatal(c, "UDP_GRO control message was truncated");
        return -1;
      }
      memcpy(&value, CMSG_DATA(cmsg), sizeof(value));
      if (value <= 0) {
        set_fatal(c, "UDP_GRO returned an invalid segment size");
        return -1;
      }
      *segment_size = (size_t)value;
      break;
    }
  }
#else
  (void)cmsg;
  (void)c;
#endif
  return 0;
}

static rx_drain_result drain_rx_batch(udp_endpoint *endpoint, client *c,
                                      bool stop_at_benchmark_completion) {
  struct mmsghdr messages[RX_BATCH_SIZE];
  struct iovec vectors[RX_BATCH_SIZE];
  struct sockaddr_storage remote_addrs[RX_BATCH_SIZE];
  udp_control_buffer controls[RX_BATCH_SIZE];
  uint64_t ts;
  int message_count;
  size_t i;

  memset(messages, 0, sizeof(messages));
  memset(vectors, 0, sizeof(vectors));
  memset(remote_addrs, 0, sizeof(remote_addrs));
  memset(controls, 0, sizeof(controls));
  for (i = 0; i < RX_BATCH_SIZE; ++i) {
    vectors[i].iov_base = endpoint->rx_batch_storage[i];
    vectors[i].iov_len = RX_MESSAGE_CAPACITY;
    messages[i].msg_hdr.msg_name = &remote_addrs[i];
    messages[i].msg_hdr.msg_namelen = sizeof(remote_addrs[i]);
    messages[i].msg_hdr.msg_iov = &vectors[i];
    messages[i].msg_hdr.msg_iovlen = 1;
    messages[i].msg_hdr.msg_control = controls[i].bytes;
    messages[i].msg_hdr.msg_controllen = sizeof(controls[i].bytes);
  }

  do {
    message_count = recvmmsg(endpoint->fd, messages, RX_BATCH_SIZE,
                             MSG_DONTWAIT, NULL);
  } while (message_count == SOCKET_CALL_ERROR && errno == EINTR);
  if (message_count == SOCKET_CALL_ERROR) {
    int socket_error = socket_last_error();
    if (socket_error_would_block(socket_error)) {
      return RX_DRAIN_IDLE;
    }
    if (socket_error == ENOSYS) {
      endpoint->recvmmsg_supported = false;
      return drain_rx_scalar(endpoint, c, stop_at_benchmark_completion);
    }
    set_fatal(c, "recvmmsg: socket error %d", socket_error);
    return RX_DRAIN_FAILED;
  }

  ts = timestamp_ns();
  for (i = 0; i < (size_t)message_count; ++i) {
    size_t message_len = messages[i].msg_len;
    size_t segment_size;
    size_t offset;

    if ((messages[i].msg_hdr.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
      set_fatal(c, "recvmmsg truncated a UDP datagram or its control data");
      return RX_DRAIN_FAILED;
    }
    if (message_len == 0) {
      continue;
    }
    if (message_len > RX_MESSAGE_CAPACITY ||
        udp_gro_segment_size(c, &messages[i].msg_hdr, message_len,
                             &segment_size) != 0) {
      return RX_DRAIN_FAILED;
    }

    for (offset = 0; offset < message_len; offset += segment_size) {
      size_t packet_len = message_len - offset;
      rx_drain_result result;
      if (packet_len > segment_size) {
        packet_len = segment_size;
      }
      result = process_received_packet(
        endpoint, c, endpoint->rx_batch_storage[i] + offset, packet_len,
        (struct sockaddr *)&remote_addrs[i],
        messages[i].msg_hdr.msg_namelen, ts, stop_at_benchmark_completion);
      if (result != RX_DRAIN_BURST) {
        return result;
      }
    }
  }
  return message_count == RX_BATCH_SIZE ? RX_DRAIN_BURST : RX_DRAIN_IDLE;
}
#endif

rx_drain_result drain_rx(udp_endpoint *endpoint, client *c,
                                bool stop_at_benchmark_completion) {
#if defined(__linux__)
  if (endpoint->recvmmsg_supported) {
    uint64_t started = timestamp_ns();
    for (;;) {
      rx_drain_result result =
        drain_rx_batch(endpoint, c, stop_at_benchmark_completion);
      if (result != RX_DRAIN_BURST || !endpoint->recvmmsg_supported) {
        return result;
      }
      if (timestamp_ns() - started >= RX_TIME_BOUND_NS) {
        return RX_DRAIN_BURST;
      }
    }
  }
#endif
  return drain_rx_scalar(endpoint, c, stop_at_benchmark_completion);
}

int handle_expiry(client *c, uint64_t now) {
  uint64_t expiry = ngtcp2_conn_get_expiry2(c->qconn);
  int rv;
  if (expiry > now) {
    return 0;
  }
  rv = ngtcp2_conn_handle_expiry(c->qconn, now);
  if (rv != 0) {
    set_fatal(c, "ngtcp2_conn_handle_expiry: %s (%d)", ngtcp2_strerror(rv), rv);
    return -1;
  }
  return 0;
}

uint64_t poll_timeout_ns(client *c, uint64_t now) {
  uint64_t expiry = ngtcp2_conn_get_expiry2(c->qconn);
  uint64_t delta;
  if (expiry <= now) {
    return 0;
  }
  delta = expiry - now;
  return delta < POLL_CAP_NS ? delta : POLL_CAP_NS;
}

int send_connection_close_best_effort(client *c,
                                             uint64_t close_started) {
  udp_endpoint *endpoint = c->endpoint;
  ngtcp2_ccerr close_error;
  ngtcp2_path_storage path_storage;
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;

  if (c->qconn == NULL || ngtcp2_conn_in_closing_period2(c->qconn) ||
      ngtcp2_conn_in_draining_period2(c->qconn)) {
    return 0;
  }

  ngtcp2_ccerr_default(&close_error);
  ngtcp2_ccerr_set_application_error(&close_error, NGHTTP3_H3_NO_ERROR, NULL,
                                     0);
  memset(&pi, 0, sizeof(pi));
  ngtcp2_path_storage_zero(&path_storage);
  nwrite = ngtcp2_conn_write_connection_close(
    c->qconn, &path_storage.path, &pi, endpoint->rxbuf,
    sizeof(endpoint->rxbuf), &close_error, timestamp_ns());
  if (nwrite <= 0) {
    fprintf(stderr, "warning: could not generate CONNECTION_CLOSE: %s (%d)\n",
            nwrite < 0 ? ngtcp2_strerror((int)nwrite) : "empty packet",
            (int)nwrite);
    return -1;
  }
  if (path_storage.path.remote.addr == NULL ||
      path_storage.path.remote.addrlen <= 0 ||
      (size_t)path_storage.path.remote.addrlen >
        sizeof(struct sockaddr_storage)) {
    fprintf(stderr,
            "warning: ngtcp2 returned an invalid CONNECTION_CLOSE path\n");
    return -1;
  }

  for (;;) {
    int sent = socket_send_datagram(
      endpoint->fd, endpoint->rxbuf, (size_t)nwrite,
      path_storage.path.remote.addr,
      (socklen_t)path_storage.path.remote.addrlen);
    int socket_error;
    uint64_t elapsed;
    uint64_t remaining;
    uint64_t timeout_ns;
    socket_pollfd pfd;
    int poll_result;

    if (sent == (int)nwrite) {
      return 0;
    }
    if (sent != SOCKET_CALL_ERROR) {
      fprintf(stderr,
              "warning: partial CONNECTION_CLOSE UDP send: %d/%d bytes\n",
              sent, (int)nwrite);
      return -1;
    }
    socket_error = socket_last_error();
    if (!socket_error_would_block(socket_error)) {
      fprintf(stderr,
              "warning: CONNECTION_CLOSE send failed: socket error %d\n",
              socket_error);
      return -1;
    }

    elapsed = timestamp_ns() - close_started;
    if (elapsed >= CLOSE_FLUSH_NS) {
      fprintf(stderr,
              "warning: CONNECTION_CLOSE send timed out after 100 ms\n");
      return -1;
    }
    remaining = CLOSE_FLUSH_NS - elapsed;
    timeout_ns = remaining < POLL_CAP_NS ? remaining : POLL_CAP_NS;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = endpoint->fd;
    pfd.events = SOCKET_WRITE_EVENT;
    poll_result = socket_poll_one(&pfd, timeout_ns);
    if (poll_result == SOCKET_CALL_ERROR) {
      fprintf(stderr,
              "warning: CONNECTION_CLOSE poll failed: socket error %d\n",
              socket_last_error());
      return -1;
    }
    if (poll_result > 0 &&
        (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      fprintf(stderr,
              "warning: CONNECTION_CLOSE poll returned flags 0x%x\n",
              (unsigned int)(unsigned short)pfd.revents);
      return -1;
    }
  }
}

int create_udp_endpoint(udp_endpoint *endpoint, client *error_client) {
  struct addrinfo hints;
  struct addrinfo *addresses = NULL;
  struct addrinfo *ai;
  int last_error = 0;
  int rv;

  memset(endpoint, 0, sizeof(*endpoint));
  endpoint->fd = INVALID_SOCKET_HANDLE;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  rv = getaddrinfo(SERVER_HOST, SERVER_PORT, &hints, &addresses);
  if (rv != 0) {
    set_fatal(error_client, "getaddrinfo: %d", rv);
    return -1;
  }
  for (ai = addresses; ai != NULL; ai = ai->ai_next) {
    struct sockaddr_in local_addr;
    endpoint->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (endpoint->fd == INVALID_SOCKET_HANDLE) {
      last_error = socket_last_error();
      continue;
    }
    memcpy(&local_addr, ai->ai_addr, sizeof(local_addr));
    if (error_client->server == NULL) {
      local_addr.sin_port = 0;
    }
    if (bind(endpoint->fd, (const struct sockaddr *)&local_addr,
             sizeof(local_addr)) == 0) {
      memcpy(&endpoint->remote_addr, ai->ai_addr, ai->ai_addrlen);
      endpoint->remote_addrlen = (socklen_t)ai->ai_addrlen;
      break;
    }
    last_error = socket_last_error();
    socket_close(endpoint->fd);
    endpoint->fd = INVALID_SOCKET_HANDLE;
  }
  freeaddrinfo(addresses);
  if (endpoint->fd == INVALID_SOCKET_HANDLE) {
    set_fatal(error_client, "could not create UDP endpoint: %d", last_error);
    return -1;
  }
  endpoint->local_addrlen = (socklen_t)sizeof(endpoint->local_addr);
  if (getsockname(endpoint->fd, (struct sockaddr *)&endpoint->local_addr,
                   &endpoint->local_addrlen) != 0) {
    set_fatal(error_client, "getsockname: socket error %d",
              socket_last_error());
    return -1;
  }
  if (socket_set_nonblocking(endpoint->fd) != 0) {
    set_fatal(error_client, "could not make UDP endpoint nonblocking: %d",
              socket_last_error());
    return -1;
  }
#if defined(_WIN32)
  if (error_client->server != NULL) {
    BOOL report_resets = FALSE;
    DWORD returned;
    /* A previous batch's closed client port can send ICMP errors for late
       ACKs. Those must not fail the shared listening socket's next batch. */
    if (WSAIoctl(endpoint->fd, SIO_UDP_CONNRESET, &report_resets,
                   sizeof(report_resets), NULL, 0, &returned, NULL, NULL) != 0) {
      set_fatal(error_client, "could not disable UDP connection-reset reports: %d",
                socket_last_error());
      return -1;
    }
  }
#endif
#if defined(__linux__)
  endpoint->rx_batch_storage =
    malloc(RX_BATCH_SIZE * sizeof(*endpoint->rx_batch_storage));
  if (endpoint->rx_batch_storage == NULL) {
    set_fatal(error_client, "could not allocate the UDP receive batch");
    return -1;
  }
  endpoint->recvmmsg_supported = true;
#if defined(UDP_SEGMENT)
  endpoint->gso_supported = socket_supports_gso();
#endif
#if defined(UDP_GRO)
  {
    int one = 1;
    /* Quinn also treats GRO as opportunistic. If the actual socket rejects
       the option, recvmmsg safely continues with one datagram per message. */
    (void)setsockopt(endpoint->fd, SOL_UDP, UDP_GRO, &one, sizeof(one));
  }
#endif
#endif
  return 0;
}

void free_udp_endpoint(udp_endpoint *endpoint) {
#if defined(__linux__)
  free(endpoint->rx_batch_storage);
  endpoint->rx_batch_storage = NULL;
#endif
  if (endpoint->fd != INVALID_SOCKET_HANDLE) {
    socket_close(endpoint->fd);
    endpoint->fd = INVALID_SOCKET_HANDLE;
  }
}

int init_tls(client *c, SSL_CTX *ssl_ctx) {
  static const uint8_t alpn[] = {2, 'h', '3'};
  c->ssl = SSL_new(ssl_ctx);
  if (c->ssl == NULL) {
    set_fatal(c, "SSL_new: %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }
  c->conn_ref.get_conn = get_conn;
  c->conn_ref.user_data = c;
  SSL_set_app_data(c->ssl, &c->conn_ref);
  if (c->server != NULL) {
    SSL_set_accept_state(c->ssl);
    return 0;
  }
  SSL_set_connect_state(c->ssl);
  if (SSL_set_alpn_protos(c->ssl, alpn, sizeof(alpn)) != 0) {
    set_fatal(c, "SSL_set_alpn_protos failed");
    return -1;
  }
  if (SSL_set_tlsext_host_name(c->ssl, SERVER_NAME) != 1 ||
      SSL_set1_host(c->ssl, SERVER_NAME) != 1) {
    set_fatal(c, "TLS SNI/hostname verification setup failed");
    return -1;
  }
  return 0;
}

int init_quic(client *c, const ngtcp2_pkt_hd *initial,
                      const ngtcp2_path *server_path) {
  ngtcp2_callbacks callbacks;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid dcid;
  ngtcp2_cid scid;
  ngtcp2_path path;
  int rv;

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
  callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  callbacks.handshake_completed = quic_handshake_completed;
  callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks.recv_stream_data = quic_recv_stream_data;
  callbacks.acked_stream_data_offset = quic_acked_stream_data_offset;
  callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
  callbacks.extend_max_local_streams_bidi = quic_extend_max_local_streams_bidi;
  callbacks.rand = quic_rand;
  callbacks.update_key = ngtcp2_crypto_update_key_cb;
  callbacks.stream_reset = quic_stream_reset;
  callbacks.extend_max_stream_data = quic_extend_max_stream_data;
  callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks.stream_stop_sending = quic_stream_stop_sending;
  callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  callbacks.recv_rx_key = quic_recv_rx_key;
  callbacks.get_new_connection_id2 = quic_get_new_connection_id;
  callbacks.remove_connection_id = quic_remove_connection_id;
  callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
  callbacks.recv_stop_sending = quic_recv_stop_sending;
  callbacks.stream_close2 = quic_stream_close2;
  if (c->server != NULL) {
    callbacks.client_initial = NULL;
    callbacks.recv_retry = NULL;
    callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    server_quic_callbacks(&callbacks);
    callbacks.recv_rx_key = NULL;
    callbacks.recv_tx_key = quic_recv_rx_key;
  }

  dcid.datalen = CLIENT_CONNECTION_ID_LENGTH;
  scid.datalen = CLIENT_CONNECTION_ID_LENGTH;
  if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1 ||
      RAND_bytes(scid.data, (int)scid.datalen) != 1) {
    set_fatal(c, "RAND_bytes for connection IDs failed");
    return -1;
  }

  ngtcp2_settings_default(&settings);
  /* A newly accepted server connection must start at this packet's receive
     timestamp. Taking a newer clock reading here would then pass an older
     timestamp to read_pkt, especially within a recvmmsg batch. */
  settings.initial_ts = c->server != NULL ? c->last_progress_ns : timestamp_ns();
  settings.max_tx_udp_payload_size = MAX_TX_UDP_PAYLOAD_SIZE;

  ngtcp2_transport_params_default(&params);
  params.initial_max_stream_data_bidi_local = STREAM_RECEIVE_WINDOW;
  params.initial_max_stream_data_bidi_remote = STREAM_RECEIVE_WINDOW;
  params.initial_max_stream_data_uni = STREAM_RECEIVE_WINDOW;
  params.initial_max_data = CONNECTION_RECEIVE_WINDOW;
  params.initial_max_streams_bidi = 100;
  params.initial_max_streams_uni = 100;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  params.active_connection_id_limit = 8;
  if (c->server != NULL) {
    server_cid *entry = malloc(sizeof(*entry));
    if (entry == NULL) {
      set_fatal(c, "could not register initial server connection ID");
      return -1;
    }
    entry->value = scid;
    entry->next = c->cids;
    c->cids = entry;
    params.initial_max_streams_bidi = SERVER_MAX_BIDI_STREAMS;
    params.original_dcid = initial->dcid;
    params.original_dcid_present = 1;
    c->initial_dcid = initial->dcid;
    dcid = initial->scid;
  }

  memset(&path, 0, sizeof(path));
  path.local.addr = (struct sockaddr *)&c->endpoint->local_addr;
  path.local.addrlen = (socklen_t)c->endpoint->local_addrlen;
  path.remote.addr = (struct sockaddr *)&c->endpoint->remote_addr;
  path.remote.addrlen = (socklen_t)c->endpoint->remote_addrlen;
  path.user_data = c;
  if (server_path != NULL) {
    path = *server_path;
    path.user_data = c;
  }
  rv = c->server != NULL ?
    ngtcp2_conn_server_new(&c->qconn, &dcid, &scid, &path,
                            initial->version, &callbacks, &settings,
                            &params, NULL, c) :
    ngtcp2_conn_client_new(&c->qconn, &dcid, &scid, &path,
                            NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                            &params, NULL, c);
  if (rv != 0) {
    set_fatal(c, "ngtcp2_conn_new: %s (%d)", ngtcp2_strerror(rv), rv);
    return -1;
  }
  ngtcp2_conn_set_tls_native_handle(c->qconn, c->ssl);
  {
    const char *enabled = getenv("HTTP3_BENCH_NATIVE_TRACE");
    if (enabled != NULL && strcmp(enabled, "1") == 0) {
      c->trace = calloc(1, sizeof(*c->trace));
      if (c->trace == NULL) {
        set_fatal(c, "could not allocate native trace state");
        return -1;
      }
      c->trace->initial_ts_ns = settings.initial_ts;
    }
  }
  return 0;
}

void client_free(client *c) {
  if (c->trace != NULL) {
    native_trace *trace = c->trace;
    size_t i;
    fprintf(stderr, "NATIVE_TRACE_BEGIN role=%s initial_ts_ns=%" PRIu64
            " samples=%zu\n", c->server != NULL ? "server" : "client",
            trace->initial_ts_ns, trace->sample_count);
    for (i = 0; i < trace->sample_count; ++i) {
      const native_trace_sample *sample = &trace->samples[i];
      fprintf(stderr, "NATIVE_TRACE turn=%" PRIu64 " tx_ts_ns=%" PRIu64
              " udp_bytes=%" PRIu64 " udp_datagrams=%" PRIu64
              " turn_udp_bytes=%" PRIu64
              " expiry_before_ns=%" PRIu64 " expiry_after_ns=%" PRIu64
              " latest_rtt_ns=%" PRIu64 " min_rtt_ns=%" PRIu64
              " smoothed_rtt_ns=%" PRIu64 " cwnd=%" PRIu64
              " bytes_in_flight=%" PRIu64 " pkt_lost=%" PRIu64
              " send_quantum=%zu\n", sample->turn, sample->tx_ts_ns,
              sample->udp_bytes, sample->udp_datagrams,
              sample->turn_udp_bytes,
              sample->expiry_before_ns, sample->expiry_after_ns,
              sample->info.latest_rtt, sample->info.min_rtt,
              sample->info.smoothed_rtt, sample->info.cwnd,
              sample->info.bytes_in_flight, sample->info.pkt_lost,
              sample->send_quantum);
    }
    fprintf(stderr, "NATIVE_TRACE_END\n");
    free(trace);
    c->trace = NULL;
  }
  if (c->nghttp3_conn != NULL) {
    nghttp3_conn_del(c->nghttp3_conn);
  }
  if (c->qconn != NULL) {
    ngtcp2_conn_del(c->qconn);
  }
  if (c->ssl != NULL) {
    SSL_free(c->ssl);
  }
  free(c->responses);
  while (c->streams != NULL) {
    server_stream *next = c->streams->next;
    free(c->streams);
    c->streams = next;
  }
  while (c->cids != NULL) {
    server_cid *next = c->cids->next;
    free(c->cids);
    c->cids = next;
  }
}

bool parse_nonnegative_u64_arg(const char *text, uint64_t *value) {
  char *end = NULL;
  unsigned long long parsed;
  if (text == NULL || *text == '\0' || *text == '-') {
    return false;
  }
  parsed = strtoull(text, &end, 10);
  if (end == text || *end != '\0') {
    return false;
  }
  *value = (uint64_t)parsed;
  return true;
}

static bool parse_mode(const char *text, bool *request, bool *response) {
  *request = strcmp(text, "request") == 0 || strcmp(text, "both") == 0;
  *response = strcmp(text, "response") == 0 || strcmp(text, "both") == 0;
  return *request || *response || strcmp(text, "none") == 0;
}

int parse_modes(const char *headers, const char *qpack,
                        bench_config *config) {
  bool request;
  bool response;
  if (!parse_mode(headers, &request, &response)) {
    fprintf(stderr, "unsupported header mode: %s\n", headers);
    return -1;
  }
  config->request_headers = request ? REQUEST_HEADERS_LEN : 0;
  config->response_headers = response ? RESPONSE_HEADERS_LEN : 0;
  if (!parse_mode(qpack, &config->qpack_request, &config->qpack_response)) {
    fprintf(stderr, "unsupported qpack mode: %s\n", qpack);
    return -1;
  }
  config->qpack_mode = qpack;
  return 0;
}

static int load_test_ca(SSL_CTX *ssl_ctx) {
  BIO *bio = NULL;
  X509 *certificate = NULL;
  X509_STORE *store;
  int result = -1;

  bio = BIO_new_file(CA_PATH, "rb");
  if (bio == NULL) {
    fprintf(stderr, "could not open %s: %s\n", CA_PATH,
            ERR_error_string(ERR_get_error(), NULL));
    goto cleanup;
  }
  certificate = d2i_X509_bio(bio, NULL);
  if (certificate == NULL) {
    fprintf(stderr, "could not parse DER CA %s: %s\n", CA_PATH,
            ERR_error_string(ERR_get_error(), NULL));
    goto cleanup;
  }
  store = SSL_CTX_get_cert_store(ssl_ctx);
  if (store == NULL || X509_STORE_add_cert(store, certificate) != 1 ||
      X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN) != 1) {
    fprintf(stderr, "could not install benchmark CA: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    goto cleanup;
  }
  result = 0;

cleanup:
  X509_free(certificate);
  BIO_free(bio);
  return result;
}

static int server_select_alpn(SSL *ssl, const uint8_t **out,
                              uint8_t *outlen, const uint8_t *in,
                              unsigned inlen, void *arg) {
  (void)ssl;
  (void)arg;
  while (inlen != 0) {
    unsigned len = *in++;
    --inlen;
    if (len > inlen) {
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    if (len == 2 && memcmp(in, "h3", 2) == 0) {
      *out = in;
      *outlen = 2;
      return SSL_TLSEXT_ERR_OK;
    }
    in += len;
    inlen -= len;
  }
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

SSL_CTX *create_tls_context(bool server) {
  SSL_CTX *ssl_ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
  int rv;
  if (ssl_ctx == NULL) {
    fprintf(stderr, "SSL_CTX_new failed: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }
  rv = server ? ngtcp2_crypto_boringssl_configure_server_context(ssl_ctx) :
    ngtcp2_crypto_boringssl_configure_client_context(ssl_ctx);
  /* Handshakes are timed. Match rustls rather than AWS-LC's hybrid PQ default. */
  if (rv != 0 ||
      SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_ciphersuites(ssl_ctx, TLS_CIPHER) != 1 ||
      SSL_CTX_set1_groups_list(ssl_ctx, "X25519") != 1) {
    fprintf(stderr, "TLS 1.3/QUIC/cipher/group configuration failed: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    SSL_CTX_free(ssl_ctx);
    return NULL;
  }
  if (server) {
    SSL_CTX_set_alpn_select_cb(ssl_ctx, server_select_alpn, NULL);
    if (SSL_CTX_use_certificate_file(ssl_ctx, "examples/server.cert",
                                      SSL_FILETYPE_ASN1) != 1 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, "examples/server.key",
                                     SSL_FILETYPE_ASN1) != 1 ||
        SSL_CTX_check_private_key(ssl_ctx) != 1) {
      fprintf(stderr, "could not load DER server identity: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
      SSL_CTX_free(ssl_ctx);
      return NULL;
    }
    return ssl_ctx;
  }
  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
  if (load_test_ca(ssl_ctx) != 0) {
    SSL_CTX_free(ssl_ctx);
    return NULL;
  }
  return ssl_ctx;
}

int check_native_versions(void) {
  const ngtcp2_info *qver;
  const nghttp3_info *hver;
  const char *aws_lc_runtime_version;
  qver = ngtcp2_version(0);
  if (qver == NULL || qver->version_num != NGTCP2_VERSION_NUM) {
    fprintf(stderr, "ngtcp2 runtime version mismatch: expected 1.25.0\n");
    return EXIT_FAILURE;
  }
  hver = nghttp3_version(0);
  if (hver == NULL || hver->version_num != NGHTTP3_VERSION_NUM) {
    fprintf(stderr, "nghttp3 runtime version mismatch: expected 1.18.0\n");
    return EXIT_FAILURE;
  }
  aws_lc_runtime_version = OpenSSL_version(OPENSSL_VERSION);
  if (aws_lc_runtime_version == NULL ||
      strcmp(aws_lc_runtime_version,
             AWSLC_VERSION_NAME " " AWSLC_VERSION_NUMBER_STRING) != 0) {
    fprintf(stderr,
            "AWS-LC runtime version mismatch: expected %s %s, got %s\n",
            AWSLC_VERSION_NAME, AWSLC_VERSION_NUMBER_STRING,
            aws_lc_runtime_version != NULL ? aws_lc_runtime_version : "null");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
