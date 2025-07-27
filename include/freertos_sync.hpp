#ifndef FREERTOS_SYNC_HPP
#define FREERTOS_SYNC_HPP

#include <freertos_shim.hpp>
#include <cerrno>
#include <ctime>

struct FrtMutex {
    SemaphoreHandle_t sem;
};

struct FrtCond {
    SemaphoreHandle_t sem;
};

inline void frt_mutex_init(FrtMutex* m) { m->sem = xSemaphoreCreateMutex(); }
inline void frt_mutex_destroy(FrtMutex* m) { vSemaphoreDelete(m->sem); }
inline void frt_mutex_lock(FrtMutex* m) { xSemaphoreTake(m->sem, portMAX_DELAY); }
inline void frt_mutex_unlock(FrtMutex* m) { xSemaphoreGive(m->sem); }

inline void frt_cond_init(FrtCond* c) { c->sem = xSemaphoreCreateBinary(); }
inline void frt_cond_destroy(FrtCond* c) { vSemaphoreDelete(c->sem); }
inline void frt_cond_signal(FrtCond* c) { xSemaphoreGive(c->sem); }

inline int frt_cond_timedwait(FrtCond* c, FrtMutex* m, const struct timespec* abs) {
    frt_mutex_unlock(m);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t now_ms = now.tv_sec * 1000LL + now.tv_nsec / 1000000;
    int64_t abs_ms = abs->tv_sec * 1000LL + abs->tv_nsec / 1000000;
    int64_t diff_ms = abs_ms - now_ms;
    if (diff_ms < 0) diff_ms = 0;
    bool ok = xSemaphoreTake(c->sem, (TickType_t)diff_ms);
    frt_mutex_lock(m);
    return ok ? 0 : ETIMEDOUT;
}

#endif // FREERTOS_SYNC_HPP
