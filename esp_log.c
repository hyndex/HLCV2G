#include "esp_log.h"
#include <stdarg.h>
#include <stdio.h>

void esp_log_impl(int level, const char* tag, const char* fmt, ...) {
    (void)level;
    fprintf(stderr, "%s: ", tag);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}
