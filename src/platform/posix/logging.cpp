// SPDX-License-Identifier: Apache-2.0
#ifndef ESP_PLATFORM

#include <logging.hpp>
#include <cstdio>

static void stderr_log_write(int level, const char* tag, const char* fmt, va_list args) {
    (void)level;
    std::fprintf(stderr, "%s: ", tag);
    std::vfprintf(stderr, fmt, args);
    std::fprintf(stderr, "\n");
}

void log_init() {
    log_set_backend(stderr_log_write);
}

#endif // ESP_PLATFORM
