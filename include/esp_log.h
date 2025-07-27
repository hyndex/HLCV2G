#pragma once
#include <stdio.h>
#include <stdarg.h>
#ifdef __cplusplus
extern "C" {
#endif
void esp_log_impl(int level, const char* tag, const char* fmt, ...);
#define ESP_LOGE(tag, fmt, ...) esp_log_impl(1, tag, fmt, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) esp_log_impl(2, tag, fmt, ##__VA_ARGS__)
#define ESP_LOGI(tag, fmt, ...) esp_log_impl(3, tag, fmt, ##__VA_ARGS__)
#define ESP_LOGD(tag, fmt, ...) esp_log_impl(4, tag, fmt, ##__VA_ARGS__)
#define ESP_LOGV(tag, fmt, ...) esp_log_impl(5, tag, fmt, ##__VA_ARGS__)
#ifdef __cplusplus
}
#endif
