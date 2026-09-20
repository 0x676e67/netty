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

/* Native Server request validation, response generation and accept loop.
   Shared transport configuration and fixed source references are in native.h. */
#include "native.h"

static int server_stream_open(ngtcp2_conn *conn, int64_t stream_id,
                              void *user_data) {
  client *c = (client *)user_data;
  server_stream *stream;
  if (!ngtcp2_is_bidi_stream(stream_id)) {
    return 0;
  }
  stream = calloc(1, sizeof(*stream));
  if (stream == NULL) {
    set_fatal(c, "could not allocate request stream");
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  stream->stream_id = stream_id;
  stream->next = c->streams;
  if (c->streams != NULL) {
    c->streams->previous = stream;
  }
  c->streams = stream;
  if (ngtcp2_conn_set_stream_user_data(conn, stream_id, stream) != 0) {
    set_fatal(c, "could not attach request stream state");
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int server_begin_headers(nghttp3_conn *conn, int64_t stream_id,
                                void *user_data, void *stream_user_data) {
  client *c = (client *)user_data;
  server_stream *stream = ngtcp2_conn_get_stream_user_data2(c->qconn, stream_id);
  (void)stream_user_data;
  if (stream == NULL || stream->headers_begin ||
      nghttp3_conn_set_stream_user_data(conn, stream_id, stream) != 0) {
    set_fatal(c, "invalid initial request HEADERS on stream %" PRId64, stream_id);
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  stream->headers_begin = true;
  return 0;
}

static int server_recv_header(nghttp3_conn *conn, int64_t stream_id,
                              int32_t token, nghttp3_rcbuf *name,
                              nghttp3_rcbuf *value, uint8_t flags,
                              void *user_data, void *stream_user_data) {
  client *c = (client *)user_data;
  server_stream *stream = (server_stream *)stream_user_data;
  nghttp3_vec val = nghttp3_rcbuf_get_buf(value);
  const char *expected = NULL;
  uint8_t bit = 0;
  size_t i;
  (void)conn;
  (void)flags;
  if (stream == NULL || !stream->headers_begin || stream->headers_end) {
    set_fatal(c, "request header outside initial block");
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  switch (token) {
  case NGHTTP3_QPACK_TOKEN__METHOD: bit = 1; expected = "GET"; break;
  case NGHTTP3_QPACK_TOKEN__SCHEME: bit = 2; expected = "https"; break;
  case NGHTTP3_QPACK_TOKEN__AUTHORITY: bit = 4; expected = "localhost:4433"; break;
  case NGHTTP3_QPACK_TOKEN__PATH: bit = 8; expected = REQUEST_PATH; break;
  default: break;
  }
  if (expected != NULL) {
    if ((stream->pseudo_seen & bit) != 0 || !bytes_equal(val, expected)) {
      set_fatal(c, "invalid request pseudo-header on stream %" PRId64, stream_id);
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    stream->pseudo_seen |= bit;
    return 0;
  }
  if (bytes_equal(nghttp3_rcbuf_get_buf(name), "x-churn")) {
    if (stream->churn[0] != '\0' || val.len == 0 ||
        val.len >= sizeof(stream->churn) || memchr(val.base, '\0', val.len) != NULL) {
      set_fatal(c, "invalid churn field");
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    memcpy(stream->churn, val.base, val.len);
    stream->churn[val.len] = '\0';
    return 0;
  }
  for (i = 0; i < REQUEST_HEADERS_LEN; ++i) {
    if (bytes_equal(nghttp3_rcbuf_get_buf(name), REQUEST_HEADERS[i].name)) {
      uint64_t field_bit = UINT64_C(1) << i;
      if (c->request_headers == 0 || (stream->template_seen & field_bit) != 0 ||
          !bytes_equal(val, REQUEST_HEADERS[i].value)) {
        set_fatal(c, "invalid request template field on stream %" PRId64,
                  stream_id);
        return NGHTTP3_ERR_CALLBACK_FAILURE;
      }
      stream->template_seen |= field_bit;
      break;
    }
  }
  return 0;
}

static int server_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                              void *user_data, void *stream_user_data) {
  client *c = (client *)user_data;
  server_stream *stream = (server_stream *)stream_user_data;
  (void)conn;
  (void)fin;
  if (stream == NULL || stream->headers_end || stream->pseudo_seen != 15 || stream->churn[0] == '\0' ||
      stream->template_seen != (UINT64_C(1) << c->request_headers) - 1) {
    set_fatal(c, "incomplete request headers on stream %" PRId64, stream_id);
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  stream->headers_end = true;
  return 0;
}

static int server_recv_data(nghttp3_conn *conn, int64_t stream_id,
                            const uint8_t *data, size_t datalen,
                            void *user_data, void *stream_user_data) {
  client *c = (client *)user_data;
  (void)conn;
  (void)data;
  (void)stream_user_data;
  if (datalen != 0) {
    set_fatal(c, "unexpected request body on stream %" PRId64, stream_id);
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int server_begin_trailers(nghttp3_conn *conn, int64_t stream_id,
                                 void *user_data, void *stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  set_fatal((client *)user_data, "unexpected request trailers on stream %" PRId64,
            stream_id);
  return NGHTTP3_ERR_CALLBACK_FAILURE;
}

static nghttp3_ssize server_read_body(nghttp3_conn *conn, int64_t stream_id,
                                     nghttp3_vec *vec, size_t veccnt,
                                     uint32_t *flags, void *user_data,
                                     void *stream_user_data) {
  client *c = (client *)user_data;
  server_stream *stream = (server_stream *)stream_user_data;
  (void)conn;
  (void)stream_id;
  if (veccnt == 0 || stream == NULL || stream->body_submitted) {
    set_fatal(c, "invalid response body reader state");
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  /* The immutable body belongs to the server and outlives every connection,
     including all nghttp3/ngtcp2 unacknowledged vectors. */
  vec[0].base = c->server->body;
  vec[0].len = (size_t)c->expected_body_bytes;
  *flags |= NGHTTP3_DATA_FLAG_EOF;
  stream->body_submitted = true;
  return 1;
}

static int server_end_stream(nghttp3_conn *conn, int64_t stream_id,
                             void *user_data, void *stream_user_data) {
  client *c = (client *)user_data;
  server_stream *stream = (server_stream *)stream_user_data;
  nghttp3_nv headers[3 + RESPONSE_HEADERS_LEN];
  nghttp3_data_reader reader = {server_read_body};
  size_t i;
  int rv;
  if (stream == NULL || !stream->headers_end || stream->request_complete ||
      stream->request_prefix.stage != 4 || c->server->requests == UINT64_MAX) {
    set_fatal(c, "incomplete request at FIN on stream %" PRId64, stream_id);
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  /* FIN is observed before success, just as for the Rust server baseline.
     https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1 */
  stream->request_complete = true;
  ++c->server->requests;
  c->server->request_dynamic_sections += stream->request_prefix.dynamic;
  headers[0] = make_nv(":status", "200");
  headers[1] = make_nv("content-length", c->server->content_length);
  if (c->server->allow_cancel) {
    /* Only the changing x-churn field should need a dynamic value reference. */
    headers[1].flags = NGHTTP3_NV_FLAG_NEVER_INDEX;
  }
  for (i = 0; i < c->response_headers; ++i) {
    headers[2 + i] = make_nv(RESPONSE_HEADERS[i].name, RESPONSE_HEADERS[i].value);
  }
  headers[2 + c->response_headers] = make_nv("x-churn", stream->churn);
  rv = nghttp3_conn_submit_response(conn, stream_id, headers,
                                   3 + c->response_headers,
                                   c->expected_body_bytes == 0 ? NULL : &reader);
  if (rv != 0) {
    set_nghttp3_failure(c, "nghttp3_conn_submit_response", rv);
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int server_extend_max_remote_streams_bidi(ngtcp2_conn *conn,
                                                 uint64_t max_streams,
                                                 void *user_data) {
  client *c = (client *)user_data;
  (void)conn;
  if (c->nghttp3_conn != NULL) {
    /* This is a cumulative stream-ID limit, not the concurrent limit. */
    nghttp3_conn_set_max_client_streams_bidi(c->nghttp3_conn, max_streams);
  }
  return 0;
}

rx_drain_result server_receive_packet(
  udp_endpoint *endpoint, client *listener, const uint8_t *data, size_t datalen,
  struct sockaddr *remote_addr, socklen_t remote_addrlen, uint64_t ts) {
  server_state *server = listener->server;
  ngtcp2_version_cid version_cid;
  client *c;
  int rv = ngtcp2_pkt_decode_version_cid(&version_cid, data, datalen,
                                         CLIENT_CONNECTION_ID_LENGTH);
  if (rv != 0) {
    return RX_DRAIN_BURST;
  }
  for (c = server->connections; c != NULL; c = c->next) {
    server_cid *entry;
    bool matches = c->initial_dcid.datalen == version_cid.dcidlen &&
      memcmp(c->initial_dcid.data, version_cid.dcid, version_cid.dcidlen) == 0;
    for (entry = c->cids; !matches && entry != NULL; entry = entry->next) {
      matches = entry->value.datalen == version_cid.dcidlen &&
        memcmp(entry->value.data, version_cid.dcid, version_cid.dcidlen) == 0;
    }
    if (matches) {
      break;
    }
  }
  if (c == NULL) {
    ngtcp2_pkt_hd initial;
    ngtcp2_path path;
    /* Late packets for old connections must not enter a new connection.
       Only a validated v1 Initial can create new server state. The small
       live connection list also permits a new batch during old teardown. */
    if (ngtcp2_accept(&initial, data, datalen) != 0 ||
        initial.version != NGTCP2_PROTO_VER_V1) {
      return RX_DRAIN_BURST;
    }
    c = calloc(1, sizeof(*c));
    if (c == NULL) {
      set_fatal(listener, "could not allocate server connection");
      return RX_DRAIN_FAILED;
    }
    c->server = server;
    c->endpoint = endpoint;
    c->control_stream_id = -1;
    c->qpack_encoder_stream_id = -1;
    c->qpack_decoder_stream_id = -1;
    c->expected_body_bytes = server->config.expected_body_bytes;
    c->request_headers = server->config.request_headers;
    c->response_headers = server->config.response_headers;
    c->qpack_request = server->config.qpack_request;
    c->qpack_response = server->config.qpack_response;
    c->last_progress_ns = ts;
    ngtcp2_ccerr_default(&c->last_error);
    memset(&path, 0, sizeof(path));
    path.local.addr = (struct sockaddr *)&endpoint->local_addr;
    path.local.addrlen = endpoint->local_addrlen;
    path.remote.addr = remote_addr;
    path.remote.addrlen = remote_addrlen;
    if (init_tls(c, server->ssl_ctx) != 0 || init_quic(c, &initial, &path) != 0) {
      set_fatal(listener, "server connection setup: %s", c->fatal_reason);
      client_free(c);
      free(c);
      return RX_DRAIN_FAILED;
    }
    c->next = server->connections;
    server->connections = c;
  }
  if (c->closed) {
    return RX_DRAIN_BURST;
  }
  {
    rx_drain_result result = process_received_packet(
      endpoint, c, data, datalen, remote_addr, remote_addrlen, ts, false);
    if (result == RX_DRAIN_FAILED) {
      set_fatal(listener, "server connection receive: %s", c->fatal_reason);
    }
    return result;
  }
}

static int server_stdin_command(void) {
  char byte;
#if defined(_WIN32)
  HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  DWORD available;
  DWORD consumed;
  if (!PeekNamedPipe(input, NULL, 0, NULL, &available, NULL)) {
    return GetLastError() == ERROR_BROKEN_PIPE ? 1 : -1;
  }
  if (available == 0) {
    return 0;
  }
  if (!ReadFile(input, &byte, 1, &consumed, NULL)) {
    return GetLastError() == ERROR_BROKEN_PIPE ? 1 : -1;
  }
  return consumed == 0 ? 1 : (byte == '?' ? 2 : 0);
#else
  struct pollfd input;
  int rv;
  memset(&input, 0, sizeof(input));
  input.fd = STDIN_FILENO;
  input.events = POLLIN;
  do {
    rv = poll(&input, 1, 0);
  } while (rv < 0 && errno == EINTR);
  if (rv <= 0) {
    return rv;
  }
  if (input.revents & (POLLERR | POLLNVAL)) {
    return -1;
  }
  if (input.revents & (POLLIN | POLLHUP)) {
    ssize_t consumed;
    do {
      consumed = read(STDIN_FILENO, &byte, 1);
    } while (consumed < 0 && errno == EINTR);
    return consumed == 0 ? 1 : (consumed < 0 ? -1 : (byte == '?' ? 2 : 0));
  }
  return 0;
#endif
}

/* Read-only snapshot on the native event loop, before any connection teardown. */
static void server_snapshot(server_state *server) {
  uint64_t active = 0;
  uint64_t connections = 0;
  client *c;
  for (c = server->connections; c != NULL; c = c->next) {
    server_stream *stream;
    connections += !c->closed;
    for (stream = c->streams; stream != NULL; stream = stream->next) {
      ++active;
    }
  }
  printf("{\"schema\":\"http3-live-v1\",\"active_streams\":%" PRIu64
         ",\"live_connections\":%" PRIu64 ",\"requests\":%" PRIu64
         ",\"canceled_streams\":%" PRIu64 ",\"reset_requests\":%" PRIu64
         ",\"stopped_responses\":%" PRIu64 "}\n",
         active, connections, server->requests, server->canceled_streams,
         server->reset_requests, server->stopped_responses);
  fflush(stdout);
}

static int run_server(client *listener) {
  server_state *server = listener->server;
  bool force_zero_timeout = false;
  for (;;) {
    uint64_t now = timestamp_ns();
    uint64_t timeout = force_zero_timeout ? 0 : POLL_CAP_NS;
    bool pending_tx = false;
    client **entry = &server->connections;
    socket_pollfd pfd;
    int rv = server_stdin_command();
    if (rv == 2) {
      server_snapshot(server);
    } else if (rv != 0) {
      if (rv < 0) {
        set_fatal(listener, "could not read server shutdown pipe");
      }
      return rv > 0 ? 0 : -1;
    }
    force_zero_timeout = false;
    while (*entry != NULL) {
      client *c = *entry;
      if (c->closed) {
        if (now >= c->close_deadline_ns) {
          *entry = c->next;
          client_free(c);
          free(c);
          continue;
        }
      } else {
        int tx_result;
        if (handle_expiry(c, now) != 0 || c->fatal) {
          set_fatal(listener, "server connection expiry: %s", c->fatal_reason);
          return -1;
        }
        tx_result = drive_tx(c);
        if (tx_result < 0 || c->fatal) {
          set_fatal(listener, "server connection send: %s", c->fatal_reason);
          return -1;
        }
        if (tx_result > 0) {
          timeout = 0;
        }
        pending_tx |= c->pending_tx_len != 0;
        uint64_t connection_timeout = poll_timeout_ns(c, timestamp_ns());
        if (connection_timeout < timeout) {
          timeout = connection_timeout;
        }
      }
      entry = &c->next;
    }
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = listener->endpoint->fd;
    pfd.events = SOCKET_READ_EVENT | (pending_tx ? SOCKET_WRITE_EVENT : 0);
    rv = socket_poll_one(&pfd, timeout);
    if (rv == SOCKET_CALL_ERROR ||
        (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      set_fatal(listener, "server socket poll failed: %d", socket_last_error());
      return -1;
    }
    if (pfd.revents & SOCKET_READ_EVENT) {
      rx_drain_result result = drain_rx(listener->endpoint, listener, false);
      if (result == RX_DRAIN_FAILED) {
        return -1;
      }
      force_zero_timeout = result == RX_DRAIN_BURST;
    }
  }
}

/* argv strings are borrowed until return; all connection/TLS/socket state is
   owned and freed here. No worker thread or Rust callback enters this loop. */
int http3_bench_nghttp3_server_main(int argc, char **argv) {
  server_state server;
  udp_endpoint endpoint;
  client listener;
  int exit_code = EXIT_FAILURE;
  if (argc != 4 && !(argc == 5 && strcmp(argv[4], "allow-cancel") == 0)) {
    fprintf(stderr, "usage: %s <body-bytes> <headers-mode> <qpack-mode>\n", argv[0]);
    return EXIT_FAILURE;
  }
  memset(&server, 0, sizeof(server));
  server.allow_cancel = argc == 5;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.fd = INVALID_SOCKET_HANDLE;
  memset(&listener, 0, sizeof(listener));
  listener.endpoint = &endpoint;
  listener.server = &server;
  if (!parse_nonnegative_u64_arg(argv[1], &server.config.expected_body_bytes) ||
      parse_modes(argv[2], argv[3], &server.config) != 0 ||
      server.config.expected_body_bytes > SIZE_MAX ||
      check_native_versions() != EXIT_SUCCESS) {
    return EXIT_FAILURE;
  }
  if (monotonic_clock_init() != 0 || socket_runtime_init() != 0) {
    fprintf(stderr, "server runtime initialization failed\n");
    return EXIT_FAILURE;
  }
  snprintf(server.content_length, sizeof(server.content_length), "%" PRIu64,
             server.config.expected_body_bytes);
  if (server.config.expected_body_bytes != 0) {
    server.body = malloc((size_t)server.config.expected_body_bytes);
    if (server.body == NULL) {
      fprintf(stderr, "could not allocate server response body\n");
      goto cleanup;
    }
    memset(server.body, 'A', (size_t)server.config.expected_body_bytes);
  }
  server.ssl_ctx = create_tls_context(true);
  if (server.ssl_ctx == NULL || create_udp_endpoint(&endpoint, &listener) != 0) {
    fprintf(stderr, "native server setup failed: %s\n", listener.fatal_reason);
    goto cleanup;
  }
  printf("http3-bench-server-v7 library=nghttp3 address=127.0.0.1:4433 "
         "body_bytes=%" PRIu64 " headers=%s qpack=%s "
         "max_concurrent_bidi_streams=1000 transport=ngtcp2 runtime=native workers=1\n",
         server.config.expected_body_bytes, argv[2], argv[3]);
  fflush(stdout);
  if (run_server(&listener) != 0) {
    fprintf(stderr, "native server failed: %s\n", listener.fatal_reason);
    goto cleanup;
  }
  printf("{\"schema\":\"http3-server-bench-v1\",\"requests\":%" PRIu64
         ",\"request_dynamic_sections\":%" PRIu64
         ",\"response_dynamic_sections\":%" PRIu64
         ",\"canceled_streams\":%" PRIu64
         ",\"reset_requests\":%" PRIu64
         ",\"stopped_responses\":%" PRIu64 "}\n",
         server.requests, server.request_dynamic_sections,
         server.response_dynamic_sections, server.canceled_streams,
         server.reset_requests, server.stopped_responses);
  fflush(stdout);
  exit_code = EXIT_SUCCESS;
cleanup:
  while (server.connections != NULL) {
    client *next = server.connections->next;
    client_free(server.connections);
    free(server.connections);
    server.connections = next;
  }
  free_udp_endpoint(&endpoint);
  SSL_CTX_free(server.ssl_ctx);
  free(server.body);
  socket_runtime_cleanup();
  return exit_code;
}

void server_http3_callbacks(nghttp3_callbacks *callbacks) {
  callbacks->recv_data = server_recv_data;
  callbacks->begin_headers = server_begin_headers;
  callbacks->recv_header = server_recv_header;
  callbacks->end_headers = server_end_headers;
  callbacks->begin_trailers = server_begin_trailers;
  callbacks->end_stream = server_end_stream;
}

void server_quic_callbacks(ngtcp2_callbacks *callbacks) {
  callbacks->stream_open = server_stream_open;
  callbacks->extend_max_remote_streams_bidi = server_extend_max_remote_streams_bidi;
}
