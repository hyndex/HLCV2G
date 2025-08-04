// SPDX-License-Identifier: Apache-2.0
#ifdef ESP_PLATFORM

#include <logging.hpp>
#include <esp_log.h>
#include <cstdio>

static void esp32_log_write(int level, const char* tag, const char* fmt, va_list args) {
    char buffer[256];
    std::vsnprintf(buffer, sizeof(buffer), fmt, args);
    switch (level) {
    case 1:
        ESP_LOGE(tag, "%s", buffer);
        break;
    case 2:
        ESP_LOGW(tag, "%s", buffer);
        break;
    case 3:
        ESP_LOGI(tag, "%s", buffer);
        break;
    case 4:
        ESP_LOGD(tag, "%s", buffer);
        break;
    default:
        ESP_LOGV(tag, "%s", buffer);
        break;
    }
}

void log_init() {
    log_set_backend(esp32_log_write);
}

#endif // ESP_PLATFORM
