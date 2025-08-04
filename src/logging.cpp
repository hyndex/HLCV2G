#include "logging.hpp"

static void null_log_write(int, const char*, const char*, va_list) {}

static log_write_fn current_backend = null_log_write;

void log_set_backend(log_write_fn fn) {
    current_backend = fn ? fn : null_log_write;
}

void log_message(int level, const char* tag, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    current_backend(level, tag, fmt, args);
    va_end(args);
}
