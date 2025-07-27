#ifndef MBEDTLS_UTIL_HPP_
#define MBEDTLS_UTIL_HPP_

#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pem.h>
#include <mbedtls/error.h>
#include <array>
#include <vector>
#include <string>
#include <memory>
#include <map>

namespace mbedtls_util {

enum class verify_result_t {
    Verified,
    CertificateExpired,
    CertificateRevoked,
    CertificateNotAllowed,
    NoCertificateAvailable,
    CertChainError,
};

using certificate_ptr = std::unique_ptr<mbedtls_x509_crt>;
using certificate_list = std::vector<certificate_ptr>;
using pkey_ptr = std::unique_ptr<mbedtls_pk_context>;

constexpr std::size_t sha_256_digest_size = 32;
using sha_256_digest_t = std::array<unsigned char, sha_256_digest_size>;
constexpr std::size_t signature_size = 64;

std::string base64_encode(const unsigned char* data, size_t len);
std::vector<unsigned char> base64_decode(const char* data, size_t len);

bool sha_256(const uint8_t* data, size_t len, sha_256_digest_t& digest);

bool verify(mbedtls_pk_context* key, const uint8_t* r, const uint8_t* s, const sha_256_digest_t& digest);

certificate_ptr der_to_certificate(const uint8_t* der, size_t len);

certificate_list load_certificates(const char* path);

std::string certificate_to_pem(const mbedtls_x509_crt* crt);

std::map<std::string,std::string> certificate_subject(const mbedtls_x509_crt* crt);

verify_result_t verify_certificate(const mbedtls_x509_crt* cert, const certificate_list& chain,
                                   const certificate_list& trust);

} // namespace mbedtls_util

#endif
