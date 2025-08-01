// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 chargebyte GmbH
// Copyright (C) 2022-2023 Contributors to EVerest
#include "tools.hpp"
#include "esp_log.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <iomanip>
#include <math.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>

static const char* TAG = "tools";
#include <time.h>
#include <unistd.h>
#ifdef ESP_PLATFORM
#include "esp_netif.h"
#endif

static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context ctr_drbg_ctx;
static bool rng_initialized = false;

static int init_random() {
    if (rng_initialized)
        return 0;

    mbedtls_entropy_init(&entropy_ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg_ctx);

    const char pers[] = "HLCV2G";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx,
                                    reinterpret_cast<const unsigned char*>(pers),
                                    sizeof(pers) - 1);

    if (ret == 0) {
        rng_initialized = true;
    } else {
        mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
        mbedtls_entropy_free(&entropy_ctx);
    }
    return ret;
}

ssize_t safe_read(int fd, void* buf, size_t count) {
    for (;;) {
        ssize_t result = read(fd, buf, count);

        if (result >= 0)
            return result;
        else if (errno == EINTR)
            continue;
        else
            return result;
    }
}

int generate_random_data(void* dest, size_t dest_len) {
    if (init_random() != 0)
        return -1;

    int ret = mbedtls_ctr_drbg_random(&ctr_drbg_ctx, reinterpret_cast<unsigned char*>(dest), dest_len);
    return (ret == 0) ? 0 : -1;
}

const char* choose_first_ipv6_interface() {
#ifdef ESP_PLATFORM
#ifdef CONFIG_V2G_IPV6_NETIF
    return CONFIG_V2G_IPV6_NETIF;
#else
    /* Default to WiFi station interface if nothing configured */
    return "WIFI_STA_DEF";
#endif
#else
    struct ifaddrs *ifaddr, *ifa;
    char buffer[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1)
        return NULL;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET6) {
            inet_ntop(AF_INET6, &ifa->ifa_addr->sa_data, buffer, sizeof(buffer));
            if (strstr(buffer, "fe80") != NULL) {
                return ifa->ifa_name;
            }
        }
    }
    ESP_LOGE(TAG, "No necessary IPv6 link-local address was found!");
    return NULL;
#endif
}

int get_interface_ipv6_address(const char* if_name, enum Addr6Type type, struct sockaddr_in6* addr) {
#ifdef ESP_PLATFORM
    esp_netif_t* netif = esp_netif_get_handle_from_ifkey(if_name);
    if (!netif) {
        ESP_LOGE(TAG, "esp_netif %s not found", if_name);
        return -1;
    }

    esp_ip6_addr_t ip6;
    esp_err_t err;

    switch (type) {
    case ADDR6_TYPE_LINKLOCAL:
        err = esp_netif_get_ip6_linklocal(netif, &ip6);
        break;
    case ADDR6_TYPE_GLOBAL:
        err = esp_netif_get_ip6_global(netif, &ip6);
        break;
    default:
        err = esp_netif_get_ip6_global(netif, &ip6);
        if (err != ESP_OK) {
            err = esp_netif_get_ip6_linklocal(netif, &ip6);
        }
        break;
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get IPv6 address for %s", if_name);
        return -1;
    }

    memset(addr, 0, sizeof(*addr));
    addr->sin6_family = AF_INET6;
    memcpy(&addr->sin6_addr, ip6.addr, sizeof(ip6.addr));
    addr->sin6_scope_id = ip6.zone ? ip6.zone : esp_netif_get_netif_impl_index(netif);
    return 0;
#else
    struct ifaddrs *ifaddr, *ifa;
    int rv = -1;

    // If using loopback device, accept any address
    // (lo usually does not have a link local address)
    if (strcmp(if_name, "lo") == 0) {
        type = ADDR6_TYPE_UNPSEC;
    }

    if (getifaddrs(&ifaddr) == -1)
        return -1;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        if (ifa->ifa_addr->sa_family != AF_INET6)
            continue;

        if (strcmp(ifa->ifa_name, if_name) != 0)
            continue;

        /* on Linux the scope_id is interface index for link-local addresses */
        switch (type) {
        case ADDR6_TYPE_GLOBAL: /* no link-local address requested */
            if ((reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr))->sin6_scope_id != 0)
                continue;
            break;

        case ADDR6_TYPE_LINKLOCAL: /* link-local address requested */
            if ((reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr))->sin6_scope_id == 0)
                continue;
            break;

        default: /* any address of the interface requested */
            /* use first found */
            break;
        }

        memcpy(addr, ifa->ifa_addr, sizeof(*addr));

        rv = 0;
        goto out;
    }

out:
    freeifaddrs(ifaddr);
    return rv;
#endif
}

#define NSEC_PER_SEC 1000000000L

void set_normalized_timespec(struct timespec* ts, time_t sec, int64_t nsec) {
    while (nsec >= NSEC_PER_SEC) {
        nsec -= NSEC_PER_SEC;
        ++sec;
    }
    while (nsec < 0) {
        nsec += NSEC_PER_SEC;
        --sec;
    }
    ts->tv_sec = sec;
    ts->tv_nsec = nsec;
}

struct timespec timespec_add(struct timespec lhs, struct timespec rhs) {
    struct timespec ts_delta;

    set_normalized_timespec(&ts_delta, lhs.tv_sec + rhs.tv_sec, lhs.tv_nsec + rhs.tv_nsec);

    return ts_delta;
}

struct timespec timespec_sub(struct timespec lhs, struct timespec rhs) {
    struct timespec ts_delta;

    set_normalized_timespec(&ts_delta, lhs.tv_sec - rhs.tv_sec, lhs.tv_nsec - rhs.tv_nsec);

    return ts_delta;
}

void timespec_add_ms(struct timespec* ts, long long msec) {
    long long sec = msec / 1000;

    set_normalized_timespec(ts, ts->tv_sec + sec, ts->tv_nsec + (msec - sec * 1000) * 1000 * 1000);
}

long long timespec_to_ms(struct timespec ts) {
    return ((long long)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

long long int getmonotonictime() {
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

double calc_physical_value(const int16_t& value, const int8_t& multiplier) {
    return static_cast<double>(value * pow(10.0, multiplier));
}

types::iso15118::HashAlgorithm convert_to_hash_algorithm(const types::evse_security::HashAlgorithm hash_algorithm) {
    switch (hash_algorithm) {
    case types::evse_security::HashAlgorithm::SHA256:
        return types::iso15118::HashAlgorithm::SHA256;
    case types::evse_security::HashAlgorithm::SHA384:
        return types::iso15118::HashAlgorithm::SHA384;
    case types::evse_security::HashAlgorithm::SHA512:
        return types::iso15118::HashAlgorithm::SHA512;
    default:
        throw std::runtime_error(
            "Could not convert types::evse_security::HashAlgorithm to types::iso15118::HashAlgorithm");
    }
}

std::vector<types::iso15118::CertificateHashDataInfo>
convert_to_certificate_hash_data_info_vector(const types::evse_security::OCSPRequestDataList& ocsp_request_data_list) {
    std::vector<types::iso15118::CertificateHashDataInfo> certificate_hash_data_info_vec;
    for (const auto& ocsp_request_data : ocsp_request_data_list.ocsp_request_data_list) {
        if (ocsp_request_data.responder_url.has_value() and ocsp_request_data.certificate_hash_data.has_value()) {
            types::iso15118::CertificateHashDataInfo certificate_hash_data;
            certificate_hash_data.hashAlgorithm =
                convert_to_hash_algorithm(ocsp_request_data.certificate_hash_data.value().hash_algorithm);
            certificate_hash_data.issuerNameHash = ocsp_request_data.certificate_hash_data.value().issuer_name_hash;
            certificate_hash_data.issuerKeyHash = ocsp_request_data.certificate_hash_data.value().issuer_key_hash;
            certificate_hash_data.serialNumber = ocsp_request_data.certificate_hash_data.value().serial_number;
            certificate_hash_data.responderURL = ocsp_request_data.responder_url.value();
            certificate_hash_data_info_vec.push_back(certificate_hash_data);
        }
    }
    return certificate_hash_data_info_vec;
}
