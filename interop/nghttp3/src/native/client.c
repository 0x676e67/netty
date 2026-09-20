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

/* Client requests, response validation and complete-batch timing.
   Shared transport configuration and fixed source references are in native.h. */
#include "native.h"

typedef enum run_phase {
  RUN_PHASE_READY,
  RUN_PHASE_BENCHMARK
} run_phase;

static bool parse_u64(nghttp3_vec value, uint64_t *result) {
  uint64_t n = 0;
  size_t i;

  if (value.len == 0) {
    return false;
  }
  for (i = 0; i < value.len; ++i) {
    uint8_t ch = value.base[i];
    uint64_t digit;
    if (ch < '0' || ch > '9') {
      return false;
    }
    digit = (uint64_t)(ch - '0');
    if (n > (UINT64_MAX - digit) / 10) {
      return false;
    }
    n = n * 10 + digit;
  }
  *result = n;
  return true;
}

static response_state *checked_response(client *c, int64_t stream_id,
                                        void *stream_user_data) {
  response_state *r = (response_state *)stream_user_data;
  if (r == NULL || r->stream_id != stream_id) {
    set_fatal(c, "event for unknown response stream %" PRId64, stream_id);
    return NULL;
  }
  return r;
}

static int on_nghttp3_recv_data(
  nghttp3_conn *conn, int64_t stream_id, const uint8_t *data, size_t datalen,
  void *conn_user_data, void *stream_user_data) {
  client *c = (client *)conn_user_data;
  response_state *r = checked_response(c, stream_id, stream_user_data);
  (void)conn;
  (void)data;

  if (r == NULL) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (!r->headers_end || r->complete) {
    set_fatal(c, "DATA outside response body on stream %" PRId64, stream_id);
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (r->body_bytes > c->expected_body_bytes ||
      datalen > c->expected_body_bytes - r->body_bytes) {
    set_fatal(c, "response body exceeded expected length on stream %" PRId64,
              stream_id);
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  r->body_bytes += (uint64_t)datalen;
  if (extend_flow_control(c, stream_id, (uint64_t)datalen) != 0) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int on_nghttp3_begin_headers(
  nghttp3_conn *conn, int64_t stream_id, void *conn_user_data,
  void *stream_user_data) {
  client *c = (client *)conn_user_data;
  response_state *r = checked_response(c, stream_id, stream_user_data);
  (void)conn;
  if (r == NULL) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (r->headers_begin || r->headers_end) {
    set_fatal(c, "duplicate response header block on stream %" PRId64,
              stream_id);
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  r->headers_begin = true;
  return 0;
}

static int on_nghttp3_recv_header(
  nghttp3_conn *conn, int64_t stream_id, int32_t token, nghttp3_rcbuf *name,
  nghttp3_rcbuf *value, uint8_t flags, void *conn_user_data,
  void *stream_user_data) {
  client *c = (client *)conn_user_data;
  response_state *r = checked_response(c, stream_id, stream_user_data);
  nghttp3_vec val;
  uint64_t content_length;
  size_t i;
  (void)conn;
  (void)flags;

  if (r == NULL) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (!r->headers_begin || r->headers_end) {
    set_fatal(c, "header outside initial block on stream %" PRId64, stream_id);
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  val = nghttp3_rcbuf_get_buf(value);
  if (token == NGHTTP3_QPACK_TOKEN__STATUS) {
    if (r->status_seen || !bytes_equal(val, "200")) {
      set_fatal(c, "response status was not exactly one 200 on stream %" PRId64,
                stream_id);
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    r->status_seen = true;
  } else if (token == NGHTTP3_QPACK_TOKEN_CONTENT_LENGTH) {
    if (r->content_length_seen || !parse_u64(val, &content_length) ||
        content_length != c->expected_body_bytes) {
      set_fatal(c, "invalid content-length on stream %" PRId64, stream_id);
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    r->content_length_seen = true;
  } else {
    nghttp3_vec field = nghttp3_rcbuf_get_buf(name);
    for (i = 0; i < RESPONSE_HEADERS_LEN; ++i) {
      if (bytes_equal(field, RESPONSE_HEADERS[i].name)) {
        uint64_t bit = UINT64_C(1) << i;
        if (c->response_headers == 0 || (r->response_headers_seen & bit) != 0 ||
            !bytes_equal(val, RESPONSE_HEADERS[i].value)) {
          set_fatal(c, "invalid response template field on stream %" PRId64,
                    stream_id);
          return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        r->response_headers_seen |= bit;
        break;
      }
    }
  }
  return 0;
}

static int on_nghttp3_end_headers(
  nghttp3_conn *conn, int64_t stream_id, int fin, void *conn_user_data,
  void *stream_user_data) {
  client *c = (client *)conn_user_data;
  response_state *r = checked_response(c, stream_id, stream_user_data);
  (void)conn;
  if (r == NULL) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (!r->headers_begin || r->headers_end || !r->status_seen ||
      !r->content_length_seen ||
      r->response_headers_seen != (UINT64_C(1) << c->response_headers) - 1 ||
      (fin && c->expected_body_bytes != 0)) {
    set_fatal(c, "invalid response header end on stream %" PRId64, stream_id);
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  r->headers_end = true;
  return 0;
}

static int on_nghttp3_begin_trailers(
  nghttp3_conn *conn, int64_t stream_id, void *conn_user_data,
  void *stream_user_data) {
  client *c = (client *)conn_user_data;
  response_state *r = checked_response(c, stream_id, stream_user_data);
  (void)conn;
  if (r == NULL) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  set_fatal(c, "unexpected response trailers on stream %" PRId64, stream_id);
  return NGHTTP3_ERR_CALLBACK_FAILURE;
}

static int on_nghttp3_end_stream(
  nghttp3_conn *conn, int64_t stream_id, void *conn_user_data,
  void *stream_user_data) {
  client *c = (client *)conn_user_data;
  response_state *r = checked_response(c, stream_id, stream_user_data);
  (void)conn;
  if (r == NULL) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (r->complete || !r->headers_end ||
      r->body_bytes != c->expected_body_bytes) {
    set_fatal(c, "incomplete response at end_stream on stream %" PRId64,
              stream_id);
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  r->complete = true;
  --c->active;
  ++c->completed;
  c->received_bytes += r->body_bytes;
  return 0;
}

static int fill_request_window(client *c) {
  while (c->started < c->target_requests && c->active < c->inflight_limit) {
    response_state *r;
    nghttp3_nv headers[4 + REQUEST_HEADERS_LEN];
    int64_t stream_id;
    int rv;
    size_t i;

    rv = ngtcp2_conn_open_bidi_stream(c->qconn, &stream_id, NULL);
    if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
      break;
    }
    if (rv != 0) {
      set_fatal(c, "ngtcp2_conn_open_bidi_stream: %s (%d)",
                ngtcp2_strerror(rv), rv);
      return -1;
    }

    r = &c->responses[c->started];
    memset(r, 0, sizeof(*r));
    r->stream_id = stream_id;
    headers[0] = make_nv(":method", "GET");
    headers[1] = make_nv(":scheme", "https");
    headers[2] = make_nv(":authority", "localhost:4433");
    headers[3] = make_nv(":path", REQUEST_PATH);
    for (i = 0; i < c->request_headers; ++i) {
      headers[4 + i] = make_nv(REQUEST_HEADERS[i].name, REQUEST_HEADERS[i].value);
    }
    rv = nghttp3_conn_submit_request(c->nghttp3_conn, stream_id, headers,
                                     4 + c->request_headers, NULL, r);
    if (rv != 0) {
      set_nghttp3_failure(c, "nghttp3_conn_submit_request", rv);
      return -1;
    }
    ++c->started;
    ++c->active;
  }
  return 0;
}

static bool local_http3_setup_flushed(const client *c) {
  if (!c->nghttp3_ready || c->control_stream_id < 0 ||
      c->qpack_encoder_stream_id < 0 || c->qpack_decoder_stream_id < 0) {
    return false;
  }

  /* Match the Rust builder boundary: the current control and QPACK bytes have
     been accepted by QUIC, without waiting for UDP transmission or ACKs. */
  return nghttp3_conn_is_stream_flushed(c->nghttp3_conn,
                                        c->control_stream_id) != 0 &&
         nghttp3_conn_is_stream_flushed(c->nghttp3_conn,
                                        c->qpack_encoder_stream_id) != 0 &&
         nghttp3_conn_is_stream_flushed(c->nghttp3_conn,
                                        c->qpack_decoder_stream_id) != 0;
}

static bool client_phase_done(const client *c, run_phase phase) {
  switch (phase) {
  case RUN_PHASE_READY:
    return c->handshake_completed && local_http3_setup_flushed(c);
  case RUN_PHASE_BENCHMARK:
    return c->completed == c->target_requests;
  }
  return false;
}

static int run_until_phase(client *c, run_phase phase) {
  udp_endpoint *endpoint = c->endpoint;
  socket_pollfd pfd;
  bool force_zero_timeout = false;
  bool benchmark = phase == RUN_PHASE_BENCHMARK;

  for (;;) {
    uint64_t now = timestamp_ns();
    uint64_t timeout = force_zero_timeout ? 0 : POLL_CAP_NS;
    int poll_result;
    bool pending_tx = false;
    force_zero_timeout = false;

    if (c->fatal) {
      return -1;
    }
    if (client_phase_done(c, phase)) {
      return 0;
    }
    if (now - c->last_progress_ns >= NO_PROGRESS_NS) {
      set_fatal(c, "connection made no protocol progress for 30 seconds");
      return -1;
    }
    if (handle_expiry(c, now) != 0 ||
        (benchmark && fill_request_window(c) != 0)) {
      return -1;
    }
    {
      int tx_result = drive_tx(c);
      if (tx_result < 0) {
        return -1;
      }
      if (tx_result > 0) {
        force_zero_timeout = true;
        timeout = 0;
      }
      pending_tx = c->pending_tx_len != 0;
      if (!force_zero_timeout) {
        uint64_t client_timeout = poll_timeout_ns(c, timestamp_ns());
        if (client_timeout < timeout) {
          timeout = client_timeout;
        }
      }
    }
    if (client_phase_done(c, phase)) {
      return 0;
    }

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = endpoint->fd;
    pfd.events = SOCKET_READ_EVENT;
    if (pending_tx) {
      pfd.events |= SOCKET_WRITE_EVENT;
    }
    poll_result = socket_poll_one(&pfd, timeout);
    if (poll_result == SOCKET_CALL_ERROR) {
      set_fatal(c, "poll: socket error %d", socket_last_error());
      return -1;
    }
    if (poll_result > 0) {
      if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        set_fatal(c, "poll returned socket error flags 0x%x",
                  (unsigned int)(unsigned short)pfd.revents);
        return -1;
      }
      if (pfd.revents & SOCKET_READ_EVENT) {
        rx_drain_result drain_result = drain_rx(endpoint, c, benchmark);
        if (drain_result == RX_DRAIN_FAILED) {
          return -1;
        }
        if (drain_result == RX_DRAIN_BENCHMARK_COMPLETE) {
          return 0;
        }
        if (drain_result == RX_DRAIN_BURST) {
          force_zero_timeout = true;
        }
      }
      if (pfd.revents & SOCKET_WRITE_EVENT) {
        if (c->pending_tx_len != 0) {
          int drive_result = drive_tx(c);
          if (drive_result < 0) {
            return -1;
          }
          if (drive_result > 0) {
            force_zero_timeout = true;
          }
        }
      }
    }
  }
}

static int client_prepare(client *c, udp_endpoint *endpoint,
                          const bench_config *config) {
  memset(c, 0, sizeof(*c));
  c->control_stream_id = -1;
  c->qpack_encoder_stream_id = -1;
  c->qpack_decoder_stream_id = -1;
  c->endpoint = endpoint;
  c->target_requests = config->requests;
  c->expected_body_bytes = config->expected_body_bytes;
  c->inflight_limit = config->inflight;
  c->request_headers = config->request_headers;
  c->response_headers = config->response_headers;
  c->qpack_request = config->qpack_request;
  c->qpack_response = config->qpack_response;
  ngtcp2_ccerr_default(&c->last_error);

  if (config->requests > SIZE_MAX / sizeof(response_state)) {
    set_fatal(c, "response state allocation overflow");
    return -1;
  }
  c->responses = (response_state *)malloc(
    (size_t)config->requests * sizeof(response_state));
  if (c->responses == NULL) {
    set_fatal(c, "could not allocate response state");
    return -1;
  }
  return 0;
}

static bool parse_positive_u64_arg(const char *text, uint64_t *value) {
  char *end = NULL;
  unsigned long long parsed;
  if (text == NULL || *text == '\0' || *text == '-') {
    return false;
  }
  parsed = strtoull(text, &end, 10);
  if (end == text || *end != '\0' || parsed == 0) {
    return false;
  }
  *value = (uint64_t)parsed;
  return true;
}

static int parse_args(int argc, char **argv, bench_config *config) {
  uint64_t inflight;
  if (argc != 6 || !parse_positive_u64_arg(argv[1], &config->requests) ||
      config->requests > SIZE_MAX ||
      !parse_nonnegative_u64_arg(argv[2], &config->expected_body_bytes) ||
      !parse_positive_u64_arg(argv[3], &inflight) || inflight > SIZE_MAX) {
    fprintf(stderr,
            "usage: %s <requests> <expected-body-bytes> <inflight> "
            "<headers:none|request|response|both> "
            "<qpack:none|request|response|both>\n",
            argv[0]);
    return -1;
  }
  if (inflight > config->requests) {
    fprintf(stderr, "inflight cannot exceed requests\n");
    return -1;
  }
  config->inflight = (size_t)inflight;
  return parse_modes(argv[4], argv[5], config);
}

int http3_bench_nghttp3_main(int argc, char **argv) {
  bench_config config;
  udp_endpoint endpoint;
  client c;
  SSL_CTX *ssl_ctx = NULL;
  uint64_t benchmark_started;
  uint64_t benchmark_finished;
  uint64_t expected_total_bytes;
  size_t path_max_udp_payload_size;
  uint64_t elapsed_ns;
  int exit_code = EXIT_FAILURE;

  if (parse_args(argc, argv, &config) != 0 ||
      check_native_versions() != EXIT_SUCCESS) {
    return EXIT_FAILURE;
  }

  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.fd = INVALID_SOCKET_HANDLE;
  memset(&c, 0, sizeof(c));

  if (monotonic_clock_init() != 0) {
    fprintf(stderr, "monotonic clock initialization failed\n");
    return EXIT_FAILURE;
  }
  if (config.expected_body_bytes != 0 &&
      config.requests > UINT64_MAX / config.expected_body_bytes) {
    fprintf(stderr, "expected total response byte count overflow\n");
    return EXIT_FAILURE;
  }
  expected_total_bytes = config.requests * config.expected_body_bytes;
  if (socket_runtime_init() != 0) {
    fprintf(stderr, "socket runtime initialization failed\n");
    return EXIT_FAILURE;
  }

  ssl_ctx = create_tls_context(false);
  if (ssl_ctx == NULL) {
    goto cleanup_socket_runtime;
  }

  if (create_udp_endpoint(&endpoint, &c) != 0) {
    fprintf(stderr, "UDP endpoint init failed: %s\n", c.fatal_reason);
    goto cleanup_client;
  }
  /* Exclude reusable TLS configuration, trust loading and socket preparation.
     Include this batch's response storage, TLS/QUIC creation and handshake,
     requests and normal event-loop return, like the Rust request task join. */
  benchmark_started = timestamp_ns();
  if (client_prepare(&c, &endpoint, &config) != 0) {
    fprintf(stderr, "client init failed: %s\n", c.fatal_reason);
    goto cleanup_client;
  }
  c.last_progress_ns = benchmark_started;
  if (init_tls(&c, ssl_ctx) != 0 || init_quic(&c, NULL, NULL) != 0) {
    fprintf(stderr, "client init failed: %s\n", c.fatal_reason);
    goto cleanup_client;
  }
  if (run_until_phase(&c, RUN_PHASE_READY) != 0) {
    if (c.fatal) {
      fprintf(stderr, "client handshake failed: %s\n", c.fatal_reason);
    }
    goto cleanup_client;
  }
  c.last_progress_ns = timestamp_ns();
  if (run_until_phase(&c, RUN_PHASE_BENCHMARK) != 0) {
    if (c.fatal) {
      fprintf(stderr, "client benchmark failed: %s\n", c.fatal_reason);
    }
    goto cleanup_client;
  }
  /* The loop returns once every response is validated, without draining extra
     datagrams. Keep its normal unwinding in the batch, but not connection close. */
  benchmark_finished = timestamp_ns();
  path_max_udp_payload_size =
    ngtcp2_conn_get_path_max_tx_udp_payload_size2(c.qconn);
  (void)send_connection_close_best_effort(&c, timestamp_ns());

  if (c.started != config.requests || c.completed != config.requests ||
      c.active != 0 ||
      c.received_bytes != expected_total_bytes ||
      benchmark_finished <= benchmark_started) {
    fprintf(stderr,
            "client final validation failed: started=%" PRIu64
            " completed=%" PRIu64 " active=%zu bytes=%" PRIu64 "\n",
            c.started, c.completed, c.active, c.received_bytes);
    goto cleanup_client;
  }

  elapsed_ns = benchmark_finished - benchmark_started;
  printf("{\"schema\":\"http3-client-bench-v15\","
         "\"http3_library\":\"nghttp3\","
         "\"quic_backend\":\"ngtcp2\","
         "\"transport_profile\":"
         "\"ngtcp2-1350b-1mib-stream-10mib-connection\","
         "\"measurement_profile\":"
         "\"connect-to-batch-complete\","
         "\"requests\":%" PRIu64 ","
         "\"in_flight\":%zu,"
         "\"request_headers\":%zu,"
         "\"response_headers\":%zu,"
         "\"qpack\":\"%s\","
         "\"response_body_bytes\":%" PRIu64 ","
         "\"completed\":%" PRIu64 ",\"received_bytes\":%" PRIu64 ","
         "\"elapsed_ns\":%" PRIu64 ","
         "\"path_max_udp_payload_size\":%zu}\n",
         config.requests, config.inflight, config.request_headers,
         config.response_headers, config.qpack_mode,
         config.expected_body_bytes, c.completed,
         c.received_bytes, elapsed_ns, path_max_udp_payload_size);
  exit_code = EXIT_SUCCESS;

cleanup_client:
  client_free(&c);
  free_udp_endpoint(&endpoint);
  SSL_CTX_free(ssl_ctx);
cleanup_socket_runtime:
  socket_runtime_cleanup();
  return exit_code;
}

void client_http3_callbacks(nghttp3_callbacks *callbacks) {
  callbacks->recv_data = on_nghttp3_recv_data;
  callbacks->begin_headers = on_nghttp3_begin_headers;
  callbacks->recv_header = on_nghttp3_recv_header;
  callbacks->end_headers = on_nghttp3_end_headers;
  callbacks->begin_trailers = on_nghttp3_begin_trailers;
  callbacks->end_stream = on_nghttp3_end_stream;
}
