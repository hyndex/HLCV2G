// SPDX-License-Identifier: Apache-2.0
#ifdef ESP_PLATFORM

#include <platform/network_adapter.hpp>
#include <logging.hpp>

#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <esp_netif.h>
#include <esp_event.h>
#include <cstring>

namespace network_adapter {

int create_socket(int domain, int type, int protocol) {
    return ::socket(domain, type, protocol);
}

int bind(int sockfd, const struct sockaddr* addr, std::size_t addrlen) {
    return ::bind(sockfd, addr, static_cast<socklen_t>(addrlen));
}

int listen(int sockfd, int backlog) {
    return ::listen(sockfd, backlog);
}

int join_multicast(int sockfd, const struct ipv6_mreq* mreq) {
    return ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, mreq, sizeof(*mreq));
}

uint32_t get_interface_index(const char* if_name) {
    esp_netif_t* netif = esp_netif_get_handle_from_ifkey(if_name);
    if (!netif) {
        LOGE("network_adapter", "esp_netif %s not found", if_name);
        return 0;
    }
    return esp_netif_get_netif_impl_index(netif);
}

const char* choose_first_ipv6_interface() {
#ifdef CONFIG_V2G_IPV6_NETIF
    return CONFIG_V2G_IPV6_NETIF;
#else
    return "WIFI_STA_DEF";
#endif
}

int get_interface_ipv6_address(const char* if_name, enum Addr6Type type, struct sockaddr_in6* addr) {
    esp_netif_t* netif = esp_netif_get_handle_from_ifkey(if_name);
    if (!netif) {
        LOGE("network_adapter", "esp_netif %s not found", if_name);
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
        LOGE("network_adapter", "Failed to get IPv6 address for %s", if_name);
        return -1;
    }

    memset(addr, 0, sizeof(*addr));
    addr->sin6_family = AF_INET6;
    memcpy(&addr->sin6_addr, ip6.addr, sizeof(ip6.addr));
    addr->sin6_scope_id = ip6.zone ? ip6.zone : esp_netif_get_netif_impl_index(netif);
    return 0;
}

} // namespace network_adapter

#endif // ESP_PLATFORM

