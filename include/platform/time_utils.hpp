#pragma once

#include <cstdint>
#include <ctime>

namespace time_utils {

// Return current monotonic time in milliseconds
int64_t get_monotonic_time_ms();

// Fill ts with current monotonic time
void get_monotonic_time(struct timespec* ts);

// Convert timespec to milliseconds
int64_t timespec_to_ms(const struct timespec& ts);

// Convert milliseconds to timespec
void ms_to_timespec(int64_t ms, struct timespec* ts);

// Sleep for the given number of milliseconds
void delay_ms(int64_t ms);

// Wait until fd becomes readable or timeout (ms). Returns >0 if ready, 0 on timeout, -1 on error
int wait_for_read(int fd, int timeout_ms);

} // namespace time_utils

