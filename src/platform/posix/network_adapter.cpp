// SPDX-License-Identifier: Apache-2.0
#ifndef ESP_PLATFORM

#include <platform/network_adapter.hpp>
#include <logging.hpp>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstring>
#include <string.h>
#include <unistd.h>

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
    return if_nametoindex(if_name);
}

const char* choose_first_ipv6_interface() {
    struct ifaddrs* ifaddr;
    struct ifaddrs* ifa;
    char buffer[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1)
        return nullptr;

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET6) {
            inet_ntop(AF_INET6, &ifa->ifa_addr->sa_data, buffer, sizeof(buffer));
            if (strstr(buffer, "fe80") != nullptr) {
                return ifa->ifa_name;
            }
        }
    }
    LOGE("network_adapter", "No necessary IPv6 link-local address was found!");
    return nullptr;
}

int get_interface_ipv6_address(const char* if_name, enum Addr6Type type, struct sockaddr_in6* addr) {
    struct ifaddrs *ifaddr, *ifa;
    int rv = -1;

    if (strcmp(if_name, "lo") == 0) {
        type = ADDR6_TYPE_UNPSEC;
    }

    if (getifaddrs(&ifaddr) == -1)
        return -1;

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        if (ifa->ifa_addr->sa_family != AF_INET6)
            continue;

        if (strcmp(ifa->ifa_name, if_name) != 0)
            continue;

        switch (type) {
        case ADDR6_TYPE_GLOBAL:
            if ((reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr))->sin6_scope_id != 0)
                continue;
            break;

        case ADDR6_TYPE_LINKLOCAL:
            if ((reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr))->sin6_scope_id == 0)
                continue;
            break;

        default:
            break;
        }

        memcpy(addr, ifa->ifa_addr, sizeof(*addr));
        rv = 0;
        break;
    }

    freeifaddrs(ifaddr);
    return rv;
}

} // namespace network_adapter

#endif // ESP_PLATFORM

