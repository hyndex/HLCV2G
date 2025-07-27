// SPDX-License-Identifier: Apache-2.0
#include <connection/tls_connection.hpp>
#include <connection/connection.hpp>
#include "esp_log.h"
#include "v2g.hpp"
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>

static const char* TAG = "tls_conn";

namespace tls {

bool build_config(config_t& config, struct v2g_context* ctx) {
    config.socket = ctx->tls_socket.fd;
    config.io_timeout_ms = static_cast<int>(ctx->network_read_timeout_tls);
    return true;
}

int connection_init(struct v2g_context* ctx) {
    if (!ctx || !ctx->tls_server)
        return -1;
    mbedtls_ssl_init(ctx->tls_server);
    return 0;
}

int connection_start_server(struct v2g_context* ctx) {
    (void)ctx;
    return 0;
}

ssize_t connection_read(struct v2g_connection* /*conn*/, unsigned char* /*buf*/, std::size_t /*count*/) {
    return -1;
}

ssize_t connection_write(struct v2g_connection* /*conn*/, unsigned char* /*buf*/, std::size_t /*count*/) {
    return -1;
}

} // namespace tls
