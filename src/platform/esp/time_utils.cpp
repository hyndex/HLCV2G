// SPDX-License-Identifier: Apache-2.0
#ifdef ESP_PLATFORM

#include <platform/time_utils.hpp>

#include <esp_timer.h>
#include <lwip/sockets.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

namespace time_utils {

int64_t get_monotonic_time_ms() {
    return esp_timer_get_time() / 1000LL;
}

void get_monotonic_time(struct timespec* ts) {
    ms_to_timespec(get_monotonic_time_ms(), ts);
}

int64_t timespec_to_ms(const struct timespec& ts) {
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

void ms_to_timespec(int64_t ms, struct timespec* ts) {
    ts->tv_sec = ms / 1000;
    ts->tv_nsec = (ms % 1000) * 1000000LL;
}

void delay_ms(int64_t ms) {
    vTaskDelay(pdMS_TO_TICKS(ms));
}

int wait_for_read(int fd, int timeout_ms) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return ::select(fd + 1, &set, nullptr, nullptr, timeout_ms >= 0 ? &tv : nullptr);
}

} // namespace time_utils

#endif // ESP_PLATFORM

