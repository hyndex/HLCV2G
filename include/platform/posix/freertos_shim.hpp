#ifndef FREERTOS_SHIM_HPP
#define FREERTOS_SHIM_HPP

#include <thread>
#include <chrono>
#include <semaphore>
#include <ctime>
#include <platform/time_utils.hpp>

using TaskHandle_t = std::thread*;
using TickType_t = uint32_t;
using UBaseType_t = unsigned int;
using BaseType_t = int;
using TaskFunction_t = void (*)(void*);

#define pdPASS 1
#define pdFAIL 0
#define portMAX_DELAY 0xffffffffUL

inline BaseType_t xTaskCreate(TaskFunction_t func, const char* /*name*/, uint16_t /*stack*/,
                              void* param, UBaseType_t /*prio*/, TaskHandle_t* out) {
    try {
        *out = new std::thread(func, param);
    } catch (...) {
        return pdFAIL;
    }
    return pdPASS;
}

inline void vTaskDelete(TaskHandle_t task) {
    if (task) {
        if (task->joinable())
            task->join();
        delete task;
    }
}

inline void vTaskDelay(TickType_t ms) { time_utils::delay_ms(ms); }

using SemaphoreHandle_t = std::binary_semaphore*;

inline SemaphoreHandle_t xSemaphoreCreateMutex() { return new std::binary_semaphore(1); }
inline SemaphoreHandle_t xSemaphoreCreateBinary() { return new std::binary_semaphore(0); }
inline void vSemaphoreDelete(SemaphoreHandle_t sem) { delete sem; }

inline bool xSemaphoreTake(SemaphoreHandle_t sem, TickType_t timeout) {
    if (timeout == portMAX_DELAY) {
        sem->acquire();
        return true;
    }
    return sem->try_acquire_for(std::chrono::milliseconds(timeout));
}

inline void xSemaphoreGive(SemaphoreHandle_t sem) { sem->release(); }

#endif // FREERTOS_SHIM_HPP
