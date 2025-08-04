#pragma once

#if defined(ESP_PLATFORM)
#include "esp/freertos_shim.hpp"
#elif defined(POSIX_PLATFORM)
#include "posix/freertos_shim.hpp"
#else
#error "Unsupported platform for FreeRTOS shim"
#endif

