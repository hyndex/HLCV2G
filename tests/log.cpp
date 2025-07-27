// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 - 2023 Pionix GmbH and Contributors to EVerest

#include "utest_log.hpp"

#include <cstdarg>
#include <cstdio>

#include <algorithm>
#include <array>
#include <map>

namespace {
std::map<dloglevel_t, std::vector<std::string>> logged_events;

void add_log(dloglevel_t loglevel, const std::string& event) {
    logged_events[loglevel].push_back(event);
}
} // namespace

namespace module::stub {
std::vector<std::string>& get_logs(dloglevel_t loglevel) {
    return logged_events[loglevel];
}

void clear_logs() {
    logged_events.clear();
}

} // namespace module::stub

extern "C" void esp_log_impl(int level, const char* tag, const char* format, ...) {
    va_list ap;
    std::array<char, 256> buffer;
    va_start(ap, format);
    std::size_t len = std::vsnprintf(buffer.data(), buffer.size(), format, ap);
    va_end(ap);
    if (len > 0) {
        auto s_len = std::min(len, buffer.size());
        std::string event{buffer.data(), s_len};
        (void)std::fprintf(stderr, "%s: %s\n", tag, event.c_str());
        add_log(static_cast<dloglevel_t>(level), event);
    }
}
