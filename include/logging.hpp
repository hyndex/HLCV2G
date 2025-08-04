#pragma once
#include <cstdarg>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*log_write_fn)(int level, const char* tag, const char* fmt, va_list args);

extern log_write_fn log_write;

void log_message(int level, const char* tag, const char* fmt, ...);

#define LOGE(tag, fmt, ...) log_message(1, tag, fmt, ##__VA_ARGS__)
#define LOGW(tag, fmt, ...) log_message(2, tag, fmt, ##__VA_ARGS__)
#define LOGI(tag, fmt, ...) log_message(3, tag, fmt, ##__VA_ARGS__)
#define LOGD(tag, fmt, ...) log_message(4, tag, fmt, ##__VA_ARGS__)
#define LOGV(tag, fmt, ...) log_message(5, tag, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
