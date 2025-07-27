// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest
#include "iso15118_extensionsImpl.hpp"
#include "esp_log.h"
#include "v2g_ctx.hpp"
#include "freertos_sync.hpp"

static const char* TAG = "iso15118_ext";

namespace module {
namespace extensions {

void iso15118_extensionsImpl::init() {
    if (!v2g_ctx) {
        ESP_LOGE(TAG, "v2g_ctx not created");
        return;
    }
}

void iso15118_extensionsImpl::ready() {
}

void iso15118_extensionsImpl::handle_set_get_certificate_response(
    types::iso15118::ResponseExiStreamStatus& certificate_response) {
    frt_mutex_lock(&v2g_ctx->mqtt_lock);
    if (certificate_response.exi_response.has_value() and not certificate_response.exi_response.value().empty()) {
        v2g_ctx->evse_v2g_data.cert_install_res_b64_buffer = std::string(certificate_response.exi_response.value());
    }
    v2g_ctx->evse_v2g_data.cert_install_status =
        (certificate_response.status == types::iso15118::Status::Accepted) ? true : false;
    frt_cond_signal(&v2g_ctx->mqtt_cond);
    /* unlock */
    frt_mutex_unlock(&v2g_ctx->mqtt_lock);
}

} // namespace extensions
} // namespace module
