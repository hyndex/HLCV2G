#include "logging.hpp"
#include <cstdio>

static void default_log_write(int level, const char* tag, const char* fmt, va_list args) {
    (void)level;
    std::fprintf(stderr, "%s: ", tag);
    std::vfprintf(stderr, fmt, args);
    std::fprintf(stderr, "\n");
}

log_write_fn log_write = default_log_write;

void log_message(int level, const char* tag, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_write(level, tag, fmt, args);
    va_end(args);
}
