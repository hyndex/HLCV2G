// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>

struct sockaddr;
struct sockaddr_in6;
struct ipv6_mreq;
enum Addr6Type;

namespace network_adapter {

int create_socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr* addr, std::size_t addrlen);
int listen(int sockfd, int backlog);
int join_multicast(int sockfd, const struct ipv6_mreq* mreq);
uint32_t get_interface_index(const char* if_name);
const char* choose_first_ipv6_interface();
int get_interface_ipv6_address(const char* if_name, enum Addr6Type type, struct sockaddr_in6* addr);

} // namespace network_adapter

