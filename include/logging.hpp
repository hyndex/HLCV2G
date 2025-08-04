#pragma once
#include <cstdarg>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*log_write_fn)(int level, const char* tag, const char* fmt, va_list args);
// Register a custom backend. Passing nullptr disables logging.
void log_set_backend(log_write_fn fn);

// Initialize logging with the platform's default backend.
void log_init();

void log_message(int level, const char* tag, const char* fmt, ...);

#define LOGE(tag, fmt, ...) log_message(1, tag, fmt, ##__VA_ARGS__)
#define LOGW(tag, fmt, ...) log_message(2, tag, fmt, ##__VA_ARGS__)
#define LOGI(tag, fmt, ...) log_message(3, tag, fmt, ##__VA_ARGS__)
#define LOGD(tag, fmt, ...) log_message(4, tag, fmt, ##__VA_ARGS__)
#define LOGV(tag, fmt, ...) log_message(5, tag, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
