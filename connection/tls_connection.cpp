#include "tls_connection.hpp"
#include "connection.hpp"
#include "log.hpp"
#include "v2g.hpp"

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

#include <cstring>
#include <thread>
#include <cassert>

namespace tls {

struct TLSConnection {
    mbedtls_ssl_context ssl;
    mbedtls_net_context client;
};

static int ssl_read(void* ctx, unsigned char* buf, size_t len) {
    auto* c = static_cast<TLSConnection*>(ctx);
    return mbedtls_ssl_read(&c->ssl, buf, len);
}

static int ssl_write(void* ctx, const unsigned char* buf, size_t len) {
    auto* c = static_cast<TLSConnection*>(ctx);
    return mbedtls_ssl_write(&c->ssl, buf, len);
}

ssize_t connection_read(struct v2g_connection* conn, unsigned char* buf, std::size_t count) {
    auto* c = static_cast<TLSConnection*>(conn->tls_connection);
    int ret = mbedtls_ssl_read(&c->ssl, buf, count);
    if (ret <= 0) {
        return -1;
    }
    return ret;
}

ssize_t connection_write(struct v2g_connection* conn, unsigned char* buf, std::size_t count) {
    auto* c = static_cast<TLSConnection*>(conn->tls_connection);
    int ret = mbedtls_ssl_write(&c->ssl, buf, count);
    if (ret <= 0) {
        return -1;
    }
    return ret;
}

int connection_init(struct v2g_context* /*ctx*/) { return 0; }
int connection_start_server(struct v2g_context* /*ctx*/) { return -1; }
bool build_config(int&, struct v2g_context* /*ctx*/) { return false; }

} // namespace tls
