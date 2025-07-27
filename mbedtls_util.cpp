#include "mbedtls_util.hpp"
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <cstdio>
#include <cstring>

namespace mbedtls_util {

static log_handler_t g_log_handler = nullptr;

void set_log_handler(log_handler_t handler) {
    g_log_handler = handler;
}

std::string base64_encode(const uint8_t* data, size_t len) {
    size_t out_len = 0;
    std::string out((len + 2) / 3 * 4 + 4, '\0');
    if (mbedtls_base64_encode(reinterpret_cast<unsigned char*>(out.data()), out.size(), &out_len, data, len) != 0) {
        return {};
    }
    out.resize(out_len);
    return out;
}

std::vector<uint8_t> base64_decode(const char* data, size_t len) {
    size_t out_len = 0;
    std::vector<uint8_t> out(len);
    if (mbedtls_base64_decode(out.data(), out.size(), &out_len, reinterpret_cast<const unsigned char*>(data), len) != 0) {
        return {};
    }
    out.resize(out_len);
    return out;
}

bool sha_256(const uint8_t* data, size_t len, sha_256_digest_t& out) {
    return mbedtls_sha256_ret(data, len, out.data(), 0) == 0;
}

certificate_ptr der_to_certificate(const uint8_t* data, size_t len) {
    auto crt = certificate_ptr(new mbedtls_x509_crt{}, x509_deleter{});
    mbedtls_x509_crt_init(crt.get());
    if (mbedtls_x509_crt_parse_der(crt.get(), data, len) != 0) {
        return nullptr;
    }
    return crt;
}

certificate_list load_certificates(const char* file) {
    certificate_list list;
    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    if (mbedtls_x509_crt_parse_file(&chain, file) == 0) {
        for (mbedtls_x509_crt* c = &chain; c != nullptr; c = c->next) {
            auto crt = certificate_ptr(new mbedtls_x509_crt{}, x509_deleter{});
            mbedtls_x509_crt_init(crt.get());
            mbedtls_x509_crt_parse_der(crt.get(), c->raw.p, c->raw.len);
            list.emplace_back(std::move(crt));
        }
    }
    mbedtls_x509_crt_free(&chain);
    return list;
}

std::string certificate_to_pem(const mbedtls_x509_crt* crt) {
    char buf[4096];
    size_t len = 0;
    if (mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n", crt->raw.p, crt->raw.len, reinterpret_cast<unsigned char*>(buf), sizeof(buf), &len) != 0) {
        return {};
    }
    return std::string(buf, len);
}

std::map<std::string, std::string> certificate_subject(const mbedtls_x509_crt* crt) {
    char buf[512];
    mbedtls_x509_dn_gets(buf, sizeof(buf), &crt->subject);
    std::map<std::string, std::string> result;
    char* token = std::strtok(buf, ",");
    while (token) {
        char* eq = std::strchr(token, '=');
        if (eq) {
            std::string key(token, eq - token);
            std::string value(eq + 1);
            if (!key.empty() && !value.empty()) {
                result[key] = value;
            }
        }
        token = std::strtok(nullptr, ",");
    }
    return result;
}

bool verify(const mbedtls_pk_context* key, const uint8_t* r, const uint8_t* s, const sha_256_digest_t& digest) {
    if (!mbedtls_pk_can_do(key, MBEDTLS_PK_ECKEY)) {
        return false;
    }
    const mbedtls_ecp_keypair* ec = mbedtls_pk_ec(*key);
    mbedtls_mpi R, S;
    mbedtls_mpi_init(&R);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_read_binary(&R, r, 32);
    mbedtls_mpi_read_binary(&S, s, 32);
    int ret = mbedtls_ecdsa_verify(&ec->grp, digest.data(), digest.size(), &ec->Q, &R, &S);
    mbedtls_mpi_free(&R);
    mbedtls_mpi_free(&S);
    return ret == 0;
}

verify_result_t verify_certificate(const mbedtls_x509_crt* cert, const certificate_list& trust_anchors, const certificate_list& chain) {
    mbedtls_x509_crt trust;
    mbedtls_x509_crt_init(&trust);
    for (const auto& ca : trust_anchors) {
        mbedtls_x509_crt_parse_der(&trust, ca->raw.p, ca->raw.len);
    }
    mbedtls_x509_crt intermediates;
    mbedtls_x509_crt_init(&intermediates);
    for (const auto& c : chain) {
        mbedtls_x509_crt_parse_der(&intermediates, c->raw.p, c->raw.len);
    }
    uint32_t flags = 0;
    int ret = mbedtls_x509_crt_verify(cert, &trust, &intermediates, nullptr, &flags, nullptr, nullptr);
    mbedtls_x509_crt_free(&trust);
    mbedtls_x509_crt_free(&intermediates);
    if (ret == 0) {
        return verify_result_t::Verified;
    }
    if (flags & MBEDTLS_X509_BADCERT_EXPIRED) {
        return verify_result_t::CertificateExpired;
    }
    return verify_result_t::CertChainError;
}

std::vector<uint8_t> bn_to_signature(const uint8_t* r, const uint8_t* s) {
    std::vector<uint8_t> sig(signature_size);
    std::memcpy(sig.data(), r, 32);
    std::memcpy(sig.data() + 32, s, 32);
    return sig;
}

} // namespace mbedtls_util

