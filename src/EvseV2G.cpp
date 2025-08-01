// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 chargebyte GmbH
// Copyright (C) 2022-2023 Contributors to EVerest
#include <EvseV2G.hpp>
#include "connection/connection.hpp"
#include "connection/tls_connection.hpp"
#include "esp_log.h"
#include "sdp.hpp"
#include <everest/logging.hpp>

static const char* TAG = "EvseV2G";

#include <csignal>

namespace {
} // namespace

struct v2g_context* v2g_ctx = nullptr;

namespace module {

void EvseV2G::init() {
    /* create v2g context */
    v2g_ctx = v2g_ctx_create(&(*p_charger), &(*p_extensions), &(*r_security), config.device.c_str());

    if (v2g_ctx == nullptr)
        return;

    v2g_ctx->tls_server = &tls_server;

    this->r_security->subscribe_certificate_store_update(
        [this](const types::evse_security::CertificateStoreUpdate& update) {
            if (!update.leaf_certificate_type.has_value()) {
                return;
            }

            if (update.leaf_certificate_type.value() != types::evse_security::LeafCertificateType::V2G) {
                return;
            }

            ESP_LOGI(TAG, "Certificate store update received, reconfiguring TLS server");
            tls::config_t config;
            (void)build_config(config, v2g_ctx);
        });

    invoke_init(*p_charger);
    invoke_init(*p_extensions);
}

void EvseV2G::ready() {
    int rv = 0;

    ESP_LOGD(TAG, "Starting SDP responder");

    rv = connection_init(v2g_ctx);

    if (rv == -1) {
        ESP_LOGE(TAG, "Failed to initialize connection");
        goto err_out;
    }

    if (config.enable_sdp_server) {
        rv = sdp_init(v2g_ctx);

        if (rv == -1) {
            ESP_LOGE(TAG, "Failed to start SDP responder");
            goto err_out;
        }
    }

    ESP_LOGD(TAG, "starting socket server(s)");
    if (connection_start_servers(v2g_ctx)) {
        ESP_LOGE(TAG, "start_connection_servers() failed");
        goto err_out;
    }

    invoke_ready(*p_charger);
    invoke_ready(*p_extensions);

    rv = sdp_listen(v2g_ctx);

    if (rv == -1) {
        ESP_LOGE(TAG, "sdp_listen() failed");
        goto err_out;
    }

    return;

err_out:
    v2g_ctx_free(v2g_ctx);
}

EvseV2G::~EvseV2G() {
    v2g_ctx_free(v2g_ctx);
}

} // namespace module
