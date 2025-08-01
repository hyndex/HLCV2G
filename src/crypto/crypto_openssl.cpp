// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 - 2023 Pionix GmbH and Contributors to EVerest

#include <array>
#include <cassert>

#include <crypto/crypto_openssl.hpp>
#include <mbedtls_util.hpp>
#include <iso_server.hpp>
#include "esp_log.h"

#include <cbv2g/common/exi_bitstream.h>

static const char* TAG = "crypto";
#include <cbv2g/exi_v2gtp.h> //for V2GTP_HEADER_LENGTHs
#include <cbv2g/iso_2/iso2_msgDefDatatypes.h>
#include <cbv2g/iso_2/iso2_msgDefDecoder.h>
#include <cbv2g/iso_2/iso2_msgDefEncoder.h>


#include <mbedtls/pk.h>

namespace crypto ::mbedtls {
using mbedtls_util::sha_256;
using mbedtls_util::sha_256_digest_t;
using mbedtls_util::verify;

bool check_iso2_signature(const struct iso2_SignatureType* iso2_signature, mbedtls_pk_context* pkey,
                          struct iso2_exiFragment* iso2_exi_fragment) {
    assert(pkey != nullptr);
    assert(iso2_signature != nullptr);
    assert(iso2_exi_fragment != nullptr);

    bool bRes{true};

    // signature information
    const struct iso2_ReferenceType* req_ref = &iso2_signature->SignedInfo.Reference.array[0];
    const auto signature_len = iso2_signature->SignatureValue.CONTENT.bytesLen;
    const auto* signature = &iso2_signature->SignatureValue.CONTENT.bytes[0];

    // build data to check signature against
    std::array<std::uint8_t, MAX_EXI_SIZE> exi_buffer{};
    exi_bitstream_t stream;
    exi_bitstream_init(&stream, exi_buffer.data(), MAX_EXI_SIZE, 0, NULL);

    auto err = encode_iso2_exiFragment(&stream, iso2_exi_fragment);
    if (err != 0) {
        ESP_LOGE(TAG, "Unable to encode fragment, error code = %d", err);
        bRes = false;
    }

    sha_256_digest_t digest;

    // calculate hash of data
    if (bRes) {
        const auto frag_data_len = exi_bitstream_get_length(&stream);
        bRes = sha_256(exi_buffer.data(), frag_data_len, digest);
    }

    // check hash matches the value in the message
    if (bRes) {
        if (req_ref->DigestValue.bytesLen != digest.size()) {
            ESP_LOGE(TAG, "Invalid digest length %u in signature", req_ref->DigestValue.bytesLen);
            bRes = false;
        }
    }
    if (bRes) {
        if (std::memcmp(req_ref->DigestValue.bytes, digest.data(), digest.size()) != 0) {
            ESP_LOGE(TAG, "Invalid digest in signature");
            bRes = false;
        }
    }

    // verify the signature
    if (bRes) {
        struct iso2_xmldsigFragment sig_fragment {};
        init_iso2_xmldsigFragment(&sig_fragment);
        sig_fragment.SignedInfo_isUsed = 1;
        sig_fragment.SignedInfo = iso2_signature->SignedInfo;

        /** \req [V2G2-771] Don't use following fields */
        sig_fragment.SignedInfo.Id_isUsed = 0;
        sig_fragment.SignedInfo.CanonicalizationMethod.ANY_isUsed = 0;
        sig_fragment.SignedInfo.SignatureMethod.HMACOutputLength_isUsed = 0;
        sig_fragment.SignedInfo.SignatureMethod.ANY_isUsed = 0;
        for (auto* ref = sig_fragment.SignedInfo.Reference.array;
             ref != (sig_fragment.SignedInfo.Reference.array + sig_fragment.SignedInfo.Reference.arrayLen); ++ref) {
            ref->Type_isUsed = 0;
            ref->Transforms.Transform.ANY_isUsed = 0;
            ref->Transforms.Transform.XPath_isUsed = 0;
            ref->DigestMethod.ANY_isUsed = 0;
        }

        stream.byte_pos = 0;
        stream.bit_count = 0;
        err = encode_iso2_xmldsigFragment(&stream, &sig_fragment);

        if (err != 0) {
            ESP_LOGE(TAG, "Unable to encode XML signature fragment, error code = %d", err);
            bRes = false;
        }
    }

    if (bRes) {
        // hash again (different data) buffer_pos has been updated ...
        const auto frag_data_len = exi_bitstream_get_length(&stream);
        bRes = sha_256(exi_buffer.data(), frag_data_len, digest);
    }

    if (bRes) {
        /* Validate the ecdsa signature using the public key */
        if (signature_len != mbedtls_util::signature_size) {
            ESP_LOGE(TAG, "Signature len is invalid (%i)", signature_len);
            bRes = false;
        }
    }

    if (bRes) {
        const std::uint8_t* r = &signature[0];
        const std::uint8_t* s = &signature[32];
        bRes = verify(pkey, r, s, digest);
    }

    return bRes;
}

bool load_contract_root_cert(mbedtls_util::certificate_list& trust_anchors, const char* V2G_pem,
                             const char* MO_pem) {
    trust_anchors.clear();

    auto mo_certs = mbedtls_util::load_certificates_pem(MO_pem);
    trust_anchors = std::move(mo_certs);

    auto v2g_certs = mbedtls_util::load_certificates_pem(V2G_pem);
    trust_anchors.insert(trust_anchors.end(), std::make_move_iterator(v2g_certs.begin()),
                         std::make_move_iterator(v2g_certs.end()));

    if (trust_anchors.empty()) {
        ESP_LOGE(TAG, "Unable to load any MO or V2G root(s)");
    }

    return !trust_anchors.empty();
}

int load_certificate(mbedtls_util::certificate_list* chain, const std::uint8_t* bytes, std::uint16_t bytesLen) {
    assert(chain != nullptr);
    int result{-1};

    auto tmp_cert = mbedtls_util::der_to_certificate(bytes, bytesLen);
    if (tmp_cert != nullptr) {
        chain->push_back(std::move(tmp_cert));
        result = 0;
    }

    return result;
}

int parse_contract_certificate(mbedtls_util::certificate_ptr& crt, const std::uint8_t* buf, std::size_t buflen) {
    crt = mbedtls_util::der_to_certificate(buf, buflen);
    return (crt == nullptr) ? -1 : 0;
}

std::string getEmaidFromContractCert(const mbedtls_util::certificate_ptr& crt) {
    std::string cert_emaid;
    const auto subject = mbedtls_util::certificate_subject(crt.get());
    if (auto itt = subject.find("CN"); itt != subject.end()) {
        cert_emaid = itt->second;
    }

    return cert_emaid;
}

std::string chain_to_pem(const mbedtls_util::certificate_ptr& cert, const mbedtls_util::certificate_list* chain) {
    assert(chain != nullptr);

    std::string contract_cert_chain_pem(mbedtls_util::certificate_to_pem(cert.get()));
    for (const auto& crt : *chain) {
        const auto pem = mbedtls_util::certificate_to_pem(crt.get());
        if (pem.empty()) {
            ESP_LOGE(TAG, "Unable to encode certificate chain");
            break;
        }
        contract_cert_chain_pem.append(pem);
    }

    return contract_cert_chain_pem;
}

verify_result_t verify_certificate(const mbedtls_util::certificate_ptr& cert, const mbedtls_util::certificate_list* chain,
                                   const char* v2g_root_pem, const char* mo_root_pem,
                                   bool /* debugMode */) {
    assert(chain != nullptr);

    verify_result_t result{verify_result_t::Verified};
    mbedtls_util::certificate_list trust_anchors;

    if (!load_contract_root_cert(trust_anchors, v2g_root_pem, mo_root_pem)) {
        result = verify_result_t::NoCertificateAvailable;
    } else {
        result = mbedtls_util::verify_certificate(cert.get(), *chain, trust_anchors);
    }

    return result;
}

} // namespace crypto::mbedtls
