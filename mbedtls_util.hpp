#ifndef MBEDTLS_UTIL_HPP
#define MBEDTLS_UTIL_HPP

#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pem.h>
#include <mbedtls/ecdsa.h>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <array>

namespace mbedtls_util {

struct x509_deleter {
    void operator()(mbedtls_x509_crt* crt) const noexcept {
        if (crt) {
            mbedtls_x509_crt_free(crt);
            delete crt;
        }
    }
};
using certificate_ptr = std::unique_ptr<mbedtls_x509_crt, x509_deleter>;
using certificate_list = std::vector<certificate_ptr>;

struct pk_deleter {
    void operator()(mbedtls_pk_context* pk) const noexcept {
        if (pk) {
            mbedtls_pk_free(pk);
            delete pk;
        }
    }
};
using pkey_ptr = std::unique_ptr<mbedtls_pk_context, pk_deleter>;

enum class verify_result_t {
    Verified,
    CertificateExpired,
    CertificateRevoked,
    NoCertificateAvailable,
    CertificateNotAllowed,
    CertChainError,
};

enum class log_level_t { debug, info, warning, error };
using log_handler_t = void (*)(log_level_t, const std::string&);
void set_log_handler(log_handler_t handler);

using sha_256_digest_t = std::array<uint8_t, 32>;
constexpr size_t sha_256_digest_size = 32;
constexpr size_t signature_size = 64;

std::string base64_encode(const uint8_t* data, size_t len);
std::vector<uint8_t> base64_decode(const char* data, size_t len);

bool sha_256(const uint8_t* data, size_t len, sha_256_digest_t& out);

certificate_ptr der_to_certificate(const uint8_t* data, size_t len);
certificate_list load_certificates(const char* file);
std::string certificate_to_pem(const mbedtls_x509_crt* crt);
std::map<std::string, std::string> certificate_subject(const mbedtls_x509_crt* crt);

bool verify(const mbedtls_pk_context* key, const uint8_t* r, const uint8_t* s, const sha_256_digest_t& digest);
verify_result_t verify_certificate(const mbedtls_x509_crt* cert, const certificate_list& trust_anchors, const certificate_list& chain);

std::vector<uint8_t> bn_to_signature(const uint8_t* r, const uint8_t* s);

} // namespace mbedtls_util

#endif // MBEDTLS_UTIL_HPP
