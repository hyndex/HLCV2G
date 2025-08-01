// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 - 2023 Pionix GmbH and Contributors to EVerest

#ifndef CRYPTO_OPENSSL_HPP_
#define CRYPTO_OPENSSL_HPP_

#include <cstddef>
#include <string>

#include "crypto_common.hpp"
#include <mbedtls_util.hpp>

/**
 * \file OpenSSL implementation
 */

struct mbedtls_pk_context;
struct iso2_SignatureType;
struct iso2_exiFragment;
struct mbedtls_x509_crt;
struct v2g_connection;

namespace crypto::mbedtls {

/**
 * \brief check the signature of a signed 15118 message
 * \param iso2_signature the signature to check
 * \param public_key the public key from the contract certificate
 * \param iso2_exi_fragment the signed data
 * \return true when the signature is valid
 */
bool check_iso2_signature(const struct iso2_SignatureType* iso2_signature, mbedtls_pk_context* pkey,
                          struct iso2_exiFragment* iso2_exi_fragment);

/**
 * \brief load the trust anchor for the contract certificate.
 *        Use the mobility operator certificate if it exists otherwise
 *        the V2G certificate
 * \param contract_root_crt the retrieved trust anchor
 * \param V2G_pem the V2G trust anchor in PEM format
 * \param MO_pem the mobility operator trust anchor in PEM format
 * \return true when a certificate was found
 */
bool load_contract_root_cert(mbedtls_util::certificate_list& trust_anchors, const char* V2G_pem,
                             const char* MO_pem);

/**
 * \brief clear certificate and public key from previous connection
 * \param conn the V2G connection data
 * \note not needed for the OpenSSL implementation
 */
constexpr void free_connection_crypto_data(v2g_connection* conn) {
}

/**
 * \brief load a contract certificate's certification path certificate from the V2G message as DER bytes
 * \param chain the certificate path certificates (this certificate is added to the list)
 * \param bytes the DER (ASN.1) X509v3 certificate in the V2G message
 * \param bytesLen the length of the DER encoded certificate
 * \return 0 when certificate successfully loaded
 */
int load_certificate(mbedtls_util::certificate_list* chain, const std::uint8_t* bytes, std::uint16_t bytesLen);

/**
 * \brief load the contract certificate from the V2G message as DER bytes
 * \param crt the certificate
 * \param bytes the DER (ASN.1) X509v3 certificate in the V2G message
 * \param bytesLen the length of the DER encoded certificate
 * \return 0 when certificate successfully loaded
 */
int parse_contract_certificate(mbedtls_util::certificate_ptr& crt, const std::uint8_t* buf, std::size_t buflen);

/**
 * \brief get the EMAID from the certificate (CommonName from the SubjectName)
 * \param crt the certificate
 * \return the EMAD or empty on error
 */
std::string getEmaidFromContractCert(const mbedtls_util::certificate_ptr& crt);

/**
 * \brief convert a list of certificates into a PEM string starting with the contract certificate
 * \param contract_crt the contract certificate (when not the first certificate in the chain)
 * \param chain the certification path chain (might include the contract certificate as the first item)
 * \return PEM string or empty on error
 */
std::string chain_to_pem(const mbedtls_util::certificate_ptr& cert, const mbedtls_util::certificate_list* chain);

/**
 * \brief verify certification path of the contract certificate through to a trust anchor
 * \param contract_crt (single certificate or chain with the contract certificate as the first item)
 * \param chain intermediate certificates (may be nullptr)
 * \param v2g_root_pem V2G trust anchor PEM string
 * \param mo_root_pem mobility operator trust anchor PEM string
 * \param debugMode additional information on verification failures
 * \result a subset of possible verification failures where known or 'verified' on success
 */
verify_result_t verify_certificate(const mbedtls_util::certificate_ptr& cert, const mbedtls_util::certificate_list* chain,
                                   const char* v2g_root_pem, const char* mo_root_pem, bool debugMode);

} // namespace crypto::mbedtls

#endif // CRYPTO_OPENSSL_HPP_
