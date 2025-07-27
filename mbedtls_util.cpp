#include "mbedtls_util.hpp"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <cstdio>
#include <cstring>

namespace mbedtls_util {

std::string base64_encode(const unsigned char* data, size_t len) {
    size_t out_len = 0;
    mbedtls_base64_encode(nullptr, 0, &out_len, data, len);
    std::string out(out_len, '\0');
    if (mbedtls_base64_encode(reinterpret_cast<unsigned char*>(&out[0]), out_len, &out_len, data, len) != 0)
        return {};
    out.resize(out_len);
    return out;
}

std::vector<unsigned char> base64_decode(const char* data, size_t len) {
    size_t out_len = 0;
    mbedtls_base64_decode(nullptr, 0, &out_len, reinterpret_cast<const unsigned char*>(data), len);
    std::vector<unsigned char> out(out_len);
    if (mbedtls_base64_decode(out.data(), out_len, &out_len, reinterpret_cast<const unsigned char*>(data), len) != 0)
        return {};
    out.resize(out_len);
    return out;
}

bool sha_256(const uint8_t* data, size_t len, sha_256_digest_t& digest) {
    return mbedtls_sha256_ret(data, len, digest.data(), 0) == 0;
}

bool verify(mbedtls_pk_context* key, const uint8_t* r, const uint8_t* s, const sha_256_digest_t& digest) {
    if (!key)
        return false;
    if (mbedtls_pk_get_type(key) != MBEDTLS_PK_ECKEY)
        return false;
    const mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(*key);
    mbedtls_mpi R, S;
    mbedtls_mpi_init(&R);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_read_binary(&R, r, 32);
    mbedtls_mpi_read_binary(&S, s, 32);
    int ret = mbedtls_ecdsa_verify(&ecp->grp, digest.data(), digest.size(), &ecp->Q, &R, &S);
    mbedtls_mpi_free(&R);
    mbedtls_mpi_free(&S);
    return ret == 0;
}

certificate_ptr der_to_certificate(const uint8_t* der, size_t len) {
    auto crt = std::make_unique<mbedtls_x509_crt>();
    mbedtls_x509_crt_init(crt.get());
    if (mbedtls_x509_crt_parse_der(crt.get(), der, len) != 0)
        return nullptr;
    return crt;
}

certificate_list load_certificates(const char* path) {
    certificate_list list;
    if (!path)
        return list;
    auto crt = std::make_unique<mbedtls_x509_crt>();
    mbedtls_x509_crt_init(crt.get());
    if (mbedtls_x509_crt_parse_file(crt.get(), path) == 0)
        list.push_back(std::move(crt));
    return list;
}

std::string certificate_to_pem(const mbedtls_x509_crt* crt) {
    if (!crt)
        return {};
    size_t buf_len = crt->raw.len * 2 + 100;
    std::string pem(buf_len, '\0');
    size_t olen = 0;
    if (mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
                                crt->raw.p, crt->raw.len,
                                reinterpret_cast<unsigned char*>(&pem[0]), pem.size(), &olen) != 0)
        return {};
    pem.resize(olen);
    return pem;
}

std::map<std::string,std::string> certificate_subject(const mbedtls_x509_crt* crt) {
    std::map<std::string,std::string> res;
    if (!crt)
        return res;
    char buf[512];
    mbedtls_x509_dn_gets(buf, sizeof(buf), &crt->subject);
    std::string subject(buf);
    size_t pos = 0;
    while ((pos = subject.find("=")) != std::string::npos) {
        size_t start = subject.rfind('/', pos);
        start = (start == std::string::npos) ? 0 : start + 1;
        std::string key = subject.substr(start, pos - start);
        size_t end = subject.find('/', pos);
        std::string value = subject.substr(pos+1, end-pos-1);
        res[key] = value;
        if (end == std::string::npos) break;
        subject = subject.substr(end+1);
    }
    return res;
}

verify_result_t verify_certificate(const mbedtls_x509_crt* cert, const certificate_list& chain,
                                   const certificate_list& trust) {
    if (!cert)
        return verify_result_t::NoCertificateAvailable;
    mbedtls_x509_crt ca_chain;
    mbedtls_x509_crt_init(&ca_chain);
    for (const auto& c : chain) {
        mbedtls_x509_crt_append(&ca_chain, c.get());
    }
    mbedtls_x509_crt trust_chain;
    mbedtls_x509_crt_init(&trust_chain);
    for (const auto& c : trust) {
        mbedtls_x509_crt_append(&trust_chain, c.get());
    }
    uint32_t flags = 0;
    int ret = mbedtls_x509_crt_verify(cert, &trust_chain, &ca_chain, nullptr, &flags, nullptr, nullptr);
    mbedtls_x509_crt_free(&ca_chain);
    mbedtls_x509_crt_free(&trust_chain);
    if (ret == 0)
        return verify_result_t::Verified;
    if (flags & MBEDTLS_X509_BADCERT_EXPIRED)
        return verify_result_t::CertificateExpired;
    if (flags & MBEDTLS_X509_BADCERT_REVOKED)
        return verify_result_t::CertificateRevoked;
    return verify_result_t::CertChainError;
}

} // namespace mbedtls_util
