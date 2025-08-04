// SPDX-License-Identifier: Apache-2.0
#ifndef ESP_PLATFORM

#include <platform/time_utils.hpp>

#include <poll.h>
#include <time.h>
#include <unistd.h>

namespace time_utils {

int64_t get_monotonic_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

void get_monotonic_time(struct timespec* ts) {
    clock_gettime(CLOCK_MONOTONIC, ts);
}

int64_t timespec_to_ms(const struct timespec& ts) {
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

void ms_to_timespec(int64_t ms, struct timespec* ts) {
    ts->tv_sec = ms / 1000;
    ts->tv_nsec = (ms % 1000) * 1000000LL;
}

void delay_ms(int64_t ms) {
    if (ms <= 0) return;
    ::poll(nullptr, 0, static_cast<int>(ms));
}

int wait_for_read(int fd, int timeout_ms) {
    struct pollfd pfd { fd, POLLIN, 0 };
    int ret = ::poll(&pfd, 1, timeout_ms);
    if (ret <= 0) return ret;
    if (pfd.revents & POLLIN) return 1;
    return -1;
}

} // namespace time_utils

#endif // ESP_PLATFORM

