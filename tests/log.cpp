// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 - 2023 Pionix GmbH and Contributors to EVerest

#include "utest_log.hpp"
#include "logging.hpp"

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

extern "C" void test_log_writer(int level, const char* tag, const char* format, va_list ap) {
    std::array<char, 256> buffer;
    std::size_t len = std::vsnprintf(buffer.data(), buffer.size(), format, ap);
    if (len > 0) {
        auto s_len = std::min(len, buffer.size());
        std::string event{buffer.data(), s_len};
        (void)std::fprintf(stderr, "%s: %s\n", tag, event.c_str());
        add_log(static_cast<dloglevel_t>(level), event);
    }
}
static log_write_fn current_writer = test_log_writer;

extern "C" void log_set_backend(log_write_fn fn) {
    current_writer = fn ? fn : test_log_writer;
}

extern "C" void log_message(int level, const char* tag, const char* format, ...) {
    va_list ap;
    va_start(ap, format);
    current_writer(level, tag, format, ap);
    va_end(ap);
}
