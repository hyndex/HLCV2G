// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest

#include <cbv2g/din/din_msgDefDatatypes.h>

#include <inttypes.h>
#include <string.h>

#include "din_server.hpp"
#include "esp_log.h"
#include "tools.hpp"
#include "v2g_ctx.hpp"
#include "v2g_server.hpp"
#include "utils/session_utils.hpp"

static const char* TAG = "din_server";

#define SASCHEDULETUPLEID 1

/**
 * @brief load_din_physical_value This function copies the physical values from source to destination struct.
 * @param phy_value_dest is the destination struct.
 * @param phy_value_source is the source struct.
 */
void load_din_physical_value(struct din_PhysicalValueType* const phy_value_dest,
                             struct iso2_PhysicalValueType* const phy_value_source) {
    phy_value_dest->Multiplier = phy_value_source->Multiplier;
    phy_value_dest->Value = phy_value_source->Value;
    phy_value_dest->Unit_isUsed = 1;

    switch (phy_value_source->Unit) {
    case iso2_unitSymbolType_h:
        phy_value_dest->Unit = din_unitSymbolType_h;
        break;
    case iso2_unitSymbolType_m:
        phy_value_dest->Unit = din_unitSymbolType_m;
        break;
    case iso2_unitSymbolType_s:
        phy_value_dest->Unit = din_unitSymbolType_s;
        break;
    case iso2_unitSymbolType_A:
        phy_value_dest->Unit = din_unitSymbolType_A;
        break;
    case iso2_unitSymbolType_V:
        phy_value_dest->Unit = din_unitSymbolType_V;
        break;
    case iso2_unitSymbolType_W:
        phy_value_dest->Unit = din_unitSymbolType_W;
        break;
    case iso2_unitSymbolType_Wh:
        phy_value_dest->Unit = din_unitSymbolType_Wh;
        break;
    default:
        phy_value_dest->Unit = din_unitSymbolType_h;
        break;
    }
}

/*!
 * \brief din_validate_state This function checks whether the received message is expected and valid at this
 * point in the communication sequence state machine. The current V2G msg type must be set with the current V2G msg
 * state. \param state is the current state of the charging session \param current_v2g_msg is the current handled V2G
 * message \param state of the actual session. \return Returns a din_ResponseCode with sequence error if current_v2g_msg
 * is not expected, otherwise OK.
 */
static din_responseCodeType din_validate_state(int state, enum V2gMsgTypeId current_v2g_msg) {
    /* if the request type has enabled (= set) bit in expected_requests, then this
     * message is ok at this stage; otherwise reject it.
     */
    return (din_states[state].allowed_requests & (1 << current_v2g_msg)) ? din_responseCodeType_OK
                                                                         : din_responseCodeType_FAILED_SequenceError;
}

namespace utils {
/*!
 * \brief din_validate_response_code This function checks if an external error has occurred (sequence error, user
 * abort)... ). \param din_response_code is a pointer to the current response code. The value will be modified if an
 * external error has occurred. \param conn the structure with the external error information. \return Returns the next
 * v2g-event.
 */
v2g_event din_validate_response_code(din_responseCodeType* const din_response_code, struct v2g_connection const* conn) {
    enum v2g_event nextEvent = V2G_EVENT_NO_EVENT;
    din_responseCodeType response_code_tmp;

    if (conn->ctx->is_connection_terminated == true) {
        ESP_LOGE(TAG, "Connection is terminated. Abort charging");
        return V2G_EVENT_TERMINATE_CONNECTION;
    }

    /* If MQTT user abort or emergency shutdown has occurred */
    if ((conn->ctx->stop_hlc == true) || (conn->ctx->intl_emergency_shutdown == true)) {
        *din_response_code = din_responseCodeType_FAILED;
    }

    /* [V2G-DC-390]: at this point we must check whether the given request is valid at this step;
     * the idea is that we catch this error in each function below to respond with a valid
     * encoded message; note, that the handler functions below must not access v2g_session in
     * error path, since it might not be set, yet!
     */
    response_code_tmp = din_validate_state(conn->ctx->state, conn->ctx->current_v2g_msg);
    *din_response_code = (response_code_tmp >= din_responseCodeType_FAILED) ? response_code_tmp : *din_response_code;

    v2g_event session_event = utils::check_session_and_termination(din_response_code, conn);
    if (session_event != V2G_EVENT_NO_EVENT) {
        nextEvent = session_event; // [V2G-DC-665]
    }

    /* log failed response code message */
    if (*din_response_code >= din_responseCodeType_FAILED &&
        *din_response_code <= din_responseCodeType_FAILED_WrongEnergyTransferType) {
        ESP_LOGE(TAG, "Failed response code detected for message \"%s\", error: %s",
             v2g_msg_type[conn->ctx->current_v2g_msg], dinResponse[*din_response_code]);
    }

    return nextEvent;
}
} // namespace utils

/*!
 * \brief publish_DIN_DcEvStatus This function is a helper function to publish EVStatusType.
 * \param ctx is a pointer to the V2G context.
 * \param din_ev_status the structure the holds the EV Status elements.
 */
static void publish_DIN_DcEvStatus(struct v2g_context* ctx, const struct din_DC_EVStatusType& din_ev_status) {
    if ((ctx->ev_v2g_data.din_dc_ev_status.EVErrorCode != din_ev_status.EVErrorCode) ||
        (ctx->ev_v2g_data.din_dc_ev_status.EVReady != din_ev_status.EVReady) ||
        (ctx->ev_v2g_data.din_dc_ev_status.EVRESSSOC != din_ev_status.EVRESSSOC)) {
        ctx->ev_v2g_data.din_dc_ev_status.EVErrorCode = din_ev_status.EVErrorCode;
        ctx->ev_v2g_data.din_dc_ev_status.EVReady = din_ev_status.EVReady;
        ctx->ev_v2g_data.din_dc_ev_status.EVRESSSOC = din_ev_status.EVRESSSOC;

        types::iso15118::DcEvStatus ev_status;
        ev_status.dc_ev_error_code = static_cast<types::iso15118::DcEvErrorCode>(din_ev_status.EVErrorCode);
        ev_status.dc_ev_ready = din_ev_status.EVReady;
        ev_status.dc_ev_ress_soc = static_cast<float>(din_ev_status.EVRESSSOC);
        ctx->p_charger->publish_dc_ev_status(ev_status);
    }
}

//=============================================
//             Publishing request msg
//=============================================

/*!
 * \brief publish_din_service_discovery_req This function publishes the din_ServiceDiscoveryReqType message to the MQTT
 * interface. \param ctx is the V2G context. \param din_ServiceDiscoveryReqType is the request message.
 */
static void
publish_din_service_discovery_req(struct v2g_context* ctx,
                                  struct din_ServiceDiscoveryReqType const* const v2g_service_discovery_req) {
    // V2G values that can be published: ServiceCategory, ServiceScope
}

/*!
 * \brief publish_din_service_payment_selection_req This function publishes the din_ServicePaymentSelectionReqType
 * message to the MQTT interface.
 * \param ctx is the V2G context.
 * \param v2g_payment_service_selection_req is the request message.
 */
static void publish_din_service_payment_selection_req(
    struct v2g_context* ctx, struct din_ServicePaymentSelectionReqType const* const v2g_payment_service_selection_req) {
    // V2G values that can be published: selected_payment_option, SelectedServiceList
}

/*!
 * \brief publish_din_charge_parameter_discovery_req This function publishes the din_ChargeParameterDiscoveryReqType
 * message to the MQTT interface.
 * \param ctx is the V2G context.
 * \param v2g_charge_parameter_discovery_req is the request message.
 */
static void publish_din_charge_parameter_discovery_req(
    struct v2g_context* ctx,
    struct din_ChargeParameterDiscoveryReqType const* const v2g_charge_parameter_discovery_req) {
    // V2G values that can be published: DC_EVChargeParameter, MaxEntriesSAScheduleTuple
    ctx->p_charger->publish_requested_energy_transfer_mode(static_cast<types::iso15118::EnergyTransferMode>(
        v2g_charge_parameter_discovery_req->EVRequestedEnergyTransferType));
    if (v2g_charge_parameter_discovery_req->DC_EVChargeParameter_isUsed == (unsigned int)1) {

        if (v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVEnergyCapacity_isUsed == (unsigned int)1) {
            ctx->p_charger->publish_dc_ev_energy_capacity(calc_physical_value(
                v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVEnergyCapacity.Value,
                v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVEnergyCapacity.Multiplier));
        }
        if (v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVEnergyRequest_isUsed == (unsigned int)1) {
            ctx->p_charger->publish_dc_ev_energy_request(calc_physical_value(
                v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVEnergyRequest.Value,
                v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVEnergyRequest.Multiplier));
        }
        if (v2g_charge_parameter_discovery_req->DC_EVChargeParameter.FullSOC_isUsed == (unsigned int)1) {
            ctx->p_charger->publish_dc_full_soc(v2g_charge_parameter_discovery_req->DC_EVChargeParameter.FullSOC);
        }
        if (v2g_charge_parameter_discovery_req->DC_EVChargeParameter.BulkSOC_isUsed == (unsigned int)1) {
            ctx->p_charger->publish_dc_bulk_soc(v2g_charge_parameter_discovery_req->DC_EVChargeParameter.BulkSOC);
        }

        float evMaximumCurrentLimit = calc_physical_value(
            v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVMaximumCurrentLimit.Value,
            v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVMaximumCurrentLimit.Multiplier);
        float evMaximumPowerLimit = calc_physical_value(
            v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVMaximumPowerLimit.Value,
            v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVMaximumPowerLimit.Multiplier);
        float evMaximumVoltageLimit = calc_physical_value(
            v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVMaximumVoltageLimit.Value,
            v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVMaximumVoltageLimit.Multiplier);
        publish_dc_ev_maximum_limits(
            ctx, evMaximumCurrentLimit, (unsigned int)1, evMaximumPowerLimit,
            v2g_charge_parameter_discovery_req->DC_EVChargeParameter.EVMaximumPowerLimit_isUsed, evMaximumVoltageLimit,
            (unsigned int)1);
        publish_DIN_DcEvStatus(ctx, v2g_charge_parameter_discovery_req->DC_EVChargeParameter.DC_EVStatus);
    }
}

/*!
 * \brief publish_din_power_delivery_req This function publishes the din_PowerDeliveryReqType message to the MQTT
 * interface. \param ctx is the V2G context. \param din_power_delivery_req is the request message.
 */
static void publish_din_power_delivery_req(struct v2g_context* ctx,
                                           struct din_PowerDeliveryReqType const* const v2g_power_delivery_req) {
    // V2G values that can be published: ReadyToChargeState
    if (v2g_power_delivery_req->DC_EVPowerDeliveryParameter_isUsed == (unsigned int)1) {
        ctx->p_charger->publish_dc_charging_complete(
            v2g_power_delivery_req->DC_EVPowerDeliveryParameter.ChargingComplete);
        if (v2g_power_delivery_req->DC_EVPowerDeliveryParameter.BulkChargingComplete_isUsed == (unsigned int)1) {
            ctx->p_charger->publish_dc_bulk_charging_complete(
                v2g_power_delivery_req->DC_EVPowerDeliveryParameter.BulkChargingComplete);
        }
        publish_DIN_DcEvStatus(ctx, v2g_power_delivery_req->DC_EVPowerDeliveryParameter.DC_EVStatus);
    }
}

/*!
 * \brief publish_din_precharge_req This function publishes the din_PreChargeReqType message to the MQTT interface.
 * \param ctx is the V2G context.
 * \param v2g_precharge_req is the request message.
 */
static void publish_din_precharge_req(struct v2g_context* ctx,
                                      struct din_PreChargeReqType const* const v2g_precharge_req) {
    publish_dc_ev_target_voltage_current(
        ctx,
        calc_physical_value(v2g_precharge_req->EVTargetVoltage.Value, v2g_precharge_req->EVTargetVoltage.Multiplier),
        calc_physical_value(v2g_precharge_req->EVTargetCurrent.Value, v2g_precharge_req->EVTargetCurrent.Multiplier));
    publish_DIN_DcEvStatus(ctx, v2g_precharge_req->DC_EVStatus);
}

/*!
 * \brief publish_din_current_demand_req This function publishes the din_CurrentDemandReqType message to the MQTT
 * interface. \param ctx is the V2G context. \param v2g_current_demand_req is the request message.
 */
static void publish_din_current_demand_req(struct v2g_context* ctx,
                                           struct din_CurrentDemandReqType const* const v2g_current_demand_req) {
    if ((v2g_current_demand_req->BulkChargingComplete_isUsed == (unsigned int)1) &&
        (ctx->ev_v2g_data.bulk_charging_complete != v2g_current_demand_req->BulkChargingComplete)) {
        ctx->p_charger->publish_dc_bulk_charging_complete(v2g_current_demand_req->BulkChargingComplete);
        ctx->ev_v2g_data.bulk_charging_complete = v2g_current_demand_req->BulkChargingComplete;
    }
    if (ctx->ev_v2g_data.charging_complete != v2g_current_demand_req->ChargingComplete) {
        ctx->p_charger->publish_dc_charging_complete(v2g_current_demand_req->ChargingComplete);
        ctx->ev_v2g_data.charging_complete = v2g_current_demand_req->ChargingComplete;
    }

    publish_DIN_DcEvStatus(ctx, v2g_current_demand_req->DC_EVStatus);

    publish_dc_ev_target_voltage_current(ctx,
                                         calc_physical_value(v2g_current_demand_req->EVTargetVoltage.Value,
                                                             v2g_current_demand_req->EVTargetVoltage.Multiplier),
                                         calc_physical_value(v2g_current_demand_req->EVTargetCurrent.Value,
                                                             v2g_current_demand_req->EVTargetCurrent.Multiplier));

    float evMaximumCurrentLimit = calc_physical_value(v2g_current_demand_req->EVMaximumCurrentLimit.Value,
                                                      v2g_current_demand_req->EVMaximumCurrentLimit.Multiplier);
    float evMaximumPowerLimit = calc_physical_value(v2g_current_demand_req->EVMaximumPowerLimit.Value,
                                                    v2g_current_demand_req->EVMaximumPowerLimit.Multiplier);
    float evMaximumVoltageLimit = calc_physical_value(v2g_current_demand_req->EVMaximumVoltageLimit.Value,
                                                      v2g_current_demand_req->EVMaximumVoltageLimit.Multiplier);
    publish_dc_ev_maximum_limits(ctx, evMaximumCurrentLimit, v2g_current_demand_req->EVMaximumCurrentLimit_isUsed,
                                 evMaximumPowerLimit, v2g_current_demand_req->EVMaximumPowerLimit_isUsed,
                                 evMaximumVoltageLimit, v2g_current_demand_req->EVMaximumVoltageLimit_isUsed);

    float v2g_dc_ev_remaining_time_to_full_soc =
        calc_physical_value(v2g_current_demand_req->RemainingTimeToFullSoC.Value,
                            v2g_current_demand_req->RemainingTimeToFullSoC.Multiplier);
    float v2g_dc_ev_remaining_time_to_bulk_soc =
        calc_physical_value(v2g_current_demand_req->RemainingTimeToBulkSoC.Value,
                            v2g_current_demand_req->RemainingTimeToBulkSoC.Multiplier);

    publish_dc_ev_remaining_time(
        ctx, v2g_dc_ev_remaining_time_to_full_soc, v2g_current_demand_req->RemainingTimeToFullSoC_isUsed,
        v2g_dc_ev_remaining_time_to_bulk_soc, v2g_current_demand_req->RemainingTimeToBulkSoC_isUsed);
}

//=============================================
//             Request Handling
//=============================================

namespace states {

/*!
 * \brief handle_iso_session_setup This function handles the din_session_setup msg pair. It analyzes the request msg and
 * fills the response msg. The request and response msg based on the open V2G structures. This structures must be
 * provided within the \c conn structure. [V2G-DC-436]
 * \param conn holds the structure with the V2G msg pair.
 * \return Returns the next V2G-event.
 */
enum v2g_event handle_din_session_setup(struct v2g_connection* conn) {
    struct din_SessionSetupReqType* req = &conn->exi_in.dinEXIDocument->V2G_Message.Body.SessionSetupReq;
    struct din_SessionSetupResType* res = &conn->exi_out.dinEXIDocument->V2G_Message.Body.SessionSetupRes;
    enum v2g_event nextEvent = V2G_EVENT_NO_EVENT;
    char buffer[din_evccIDType_BYTES_SIZE * 2 + din_evccIDType_BYTES_SIZE - 1 +
                1]; /* format: (%02x:) * n - 1x ':' + 1x NUL */
    int idx;

    /* format EVCC ID */
    for (idx = 0; idx < req->EVCCID.bytesLen; idx++) {
        sprintf(&buffer[idx * 3], "%02" PRIX8 ":", req->EVCCID.bytes[idx]);
    }
    if (idx)
        buffer[idx * 3 - 1] = '\0';
    else
        buffer[0] = '\0';

    conn->ctx->p_charger->publish_evcc_id(buffer); // publish EVCC ID

    ESP_LOGI(TAG, "SessionSetupReq.EVCCID: %s", std::string(buffer).size() ? buffer : "(zero length provided)");

    /* Now fill the evse response message */
    res->ResponseCode = din_responseCodeType_OK_NewSessionEstablished; // [V2G-DC-393]

    /* Check and init session id */
    /* If the customer doesen't select a session id, generate one */
    srand((unsigned int)time(NULL));
    if (conn->ctx->evse_v2g_data.session_id == (uint64_t)0) {
        conn->ctx->evse_v2g_data.session_id =
            ((uint64_t)rand() << 48) | ((uint64_t)rand() << 32) | ((uint64_t)rand() << 16) | (uint64_t)rand();
        ESP_LOGI(TAG, "No session_id found. Generating random session id.");
    }

    ESP_LOGI(TAG, "Created new session with id 0x%08" PRIu64, conn->ctx->evse_v2g_data.session_id);

    res->EVSEID.bytesLen = std::min((int)conn->ctx->evse_v2g_data.evse_id.bytesLen, iso2_EVSEID_CHARACTER_SIZE);
    memcpy(res->EVSEID.bytes, conn->ctx->evse_v2g_data.evse_id.bytes, res->EVSEID.bytesLen);

    res->DateTimeNow_isUsed = conn->ctx->evse_v2g_data.date_time_now_is_used;
    res->DateTimeNow = time(NULL);

    /* Check the current response code and check if no external error has occurred */
    nextEvent = utils::din_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = WAIT_FOR_SERVICEDISCOVERY; // [V2G-DC-438]

    return nextEvent;
}

/*!
 * \brief handle_din_service_discovery This function handles the din service discovery msg pair. It analyzes the request
 * msg and fills the response msg. The request and response msg based on the open V2G structures. This structures must
 * be provided within the \c conn structure. [V2G-DC-440]
 * \param conn is the structure with the V2G msg pair.
 * \return Returns the next V2G-event.
 */
enum v2g_event handle_din_service_discovery(struct v2g_connection* conn) {
    struct din_ServiceDiscoveryReqType* req = &conn->exi_in.dinEXIDocument->V2G_Message.Body.ServiceDiscoveryReq;
    struct din_ServiceDiscoveryResType* res = &conn->exi_out.dinEXIDocument->V2G_Message.Body.ServiceDiscoveryRes;
    enum v2g_event nextEvent = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the MQTT interface */
    publish_din_service_discovery_req(conn->ctx, req);

    /* Now fill the evse response message */
    res->ResponseCode = din_responseCodeType_OK; // [V2G-DC-388]

    if ((conn->ctx->evse_v2g_data.charge_service.SupportedEnergyTransferMode.EnergyTransferMode.array[0] !=
         iso2_EnergyTransferModeType_DC_core) &&
        (conn->ctx->evse_v2g_data.charge_service.SupportedEnergyTransferMode.EnergyTransferMode.array[0]) !=
            iso2_EnergyTransferModeType_DC_extended) {
        conn->ctx->evse_v2g_data.charge_service.SupportedEnergyTransferMode.EnergyTransferMode.array[0] =
            iso2_EnergyTransferModeType_DC_extended;
        ESP_LOGW(TAG, "Selected EnergyTransferType is not supported in DIN 70121. Correcting value of field "
                                 "SupportedEnergyTransferType0 to 'DC_extended'");
    }

    res->ChargeService.ServiceTag.ServiceID =
        conn->ctx->evse_v2g_data.charge_service.ServiceID;               // ID of the charge service
    res->ChargeService.ServiceTag.ServiceName_isUsed = (unsigned int)0;  // [V2G-DC-628] Shall not be used in DIN 70121
    res->ChargeService.ServiceTag.ServiceScope_isUsed = (unsigned int)0; // [V2G-DC-629] Shall not be used in DIN 70121
    res->ChargeService.ServiceTag.ServiceCategory = din_serviceCategoryType_EVCharging; // Is fixed
    res->ChargeService.FreeService = conn->ctx->evse_v2g_data.charge_service.FreeService;
    res->ChargeService.EnergyTransferType =
        (din_EVSESupportedEnergyTransferType)
            conn->ctx->evse_v2g_data.charge_service.SupportedEnergyTransferMode.EnergyTransferMode.array[0];

    res->ServiceList_isUsed = 0; // Shall not be used in DIN 70121

    // In the scope of DIN 70121 only ExternalPayment shall be used.
    res->PaymentOptions.PaymentOption.array[0] = din_paymentOptionType_ExternalPayment;
    res->PaymentOptions.PaymentOption.arrayLen = 1;

    /* Check the current response code and check if no external error has occurred */
    nextEvent = utils::din_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = WAIT_FOR_PAYMENTSERVICESELECTION; // [V2G-DC-441]

    return nextEvent;
}

} // namespace states

/*!
 * \brief handle_din_service_discovery This function handles the din service payment selection msg pair. It analyzes the
 * request msg and fills the response msg. The request and response msg based on the open V2G structures. This
 * structures must be provided within the \c conn structure. [V2G-DC-443]
 * \param conn is the structure with the V2G msg pair.
 * \return Returns the next V2G-event.
 */
static enum v2g_event handle_din_service_payment_selection(struct v2g_connection* conn) {
    struct din_ServicePaymentSelectionReqType* req =
        &conn->exi_in.dinEXIDocument->V2G_Message.Body.ServicePaymentSelectionReq;
    struct din_ServicePaymentSelectionResType* res =
        &conn->exi_out.dinEXIDocument->V2G_Message.Body.ServicePaymentSelectionRes;
    enum v2g_event nextEvent = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the customer MQTT interface */
    publish_din_service_payment_selection_req(conn->ctx, req);

    /* Now fill the evse response message */
    res->ResponseCode = din_responseCodeType_OK; // [V2G-DC-388]

    res->ResponseCode = (req->SelectedPaymentOption != din_paymentOptionType_ExternalPayment)
                            ? din_responseCodeType_FAILED_PaymentSelectionInvalid
                            : res->ResponseCode; // [V2G-DC-395]

    res->ResponseCode = (req->SelectedServiceList.SelectedService.arrayLen == (uint16_t)1 &&
                         (req->SelectedServiceList.SelectedService.array[0].ServiceID ==
                          conn->ctx->evse_v2g_data.charge_service.ServiceID))
                            ? res->ResponseCode
                            : din_responseCodeType_FAILED_ServiceSelectionInvalid; // [V2G-DC-396] [V2G-DC-635] (List
                                                                                   // shall be limited to 1)

    /* Check the current response code and check if no external error has occurred */
    nextEvent = utils::din_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = WAIT_FOR_AUTHORIZATION; // [V2G-DC-444]

    return nextEvent;
}

/*!
 * \brief handle_din_service_discovery This function handles the din contract authentication msg pair. It analyzes the
 * request msg and fills the response msg. The request and response msg based on the open V2G structures. This
 * structures must be provided within the \c conn structure. [V2G-DC-494]
 * \param conn is the structure with the V2G msg pair.
 * \return Returns the next V2G-event.
 */
enum v2g_event states::handle_din_contract_authentication(struct v2g_connection* conn) {
    struct din_ContractAuthenticationResType* res =
        &conn->exi_out.dinEXIDocument->V2G_Message.Body.ContractAuthenticationRes;
    enum v2g_event nextEvent = V2G_EVENT_NO_EVENT;

    /* Fill the EVSE response message */
    res->ResponseCode = din_responseCodeType_OK; // [V2G-DC-388]
    res->EVSEProcessing = (conn->ctx->evse_v2g_data.evse_processing[PHASE_AUTH] == (uint8_t)0)
                              ? din_EVSEProcessingType_Finished
                              : din_EVSEProcessingType_Ongoing;

    /* Check the current response code and check if no external error has occurred */
    nextEvent = utils::din_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = (res->EVSEProcessing == din_EVSEProcessingType_Ongoing)
                           ? WAIT_FOR_AUTHORIZATION
                           : WAIT_FOR_CHARGEPARAMETERDISCOVERY; // [V2G-DC-444], [V2G-DC-497]

    return nextEvent;
}

/*!
 * \brief handle_din_charge_parameter This function handles the din charge parameters msg pair. It analyzes the request
 * msg and fills the response msg. The request and response msg based on the open V2G structures. This structures must
 * be provided within the \c conn structure. [V2G-DC-445]
 * \param conn is the structure with the v2g msg pair.
 * \return Returns the next V2G-event.
 */
static enum v2g_event handle_din_charge_parameter(struct v2g_connection* conn) {
    struct din_ChargeParameterDiscoveryReqType* req =
        &conn->exi_in.dinEXIDocument->V2G_Message.Body.ChargeParameterDiscoveryReq;
    struct din_ChargeParameterDiscoveryResType* res =
        &conn->exi_out.dinEXIDocument->V2G_Message.Body.ChargeParameterDiscoveryRes;
    enum v2g_event nextEvent = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the customer MQTT interface */
    publish_din_charge_parameter_discovery_req(conn->ctx, req);

    /* Now fill the EVSE response message */
    res->ResponseCode = din_responseCodeType_OK; // [V2G-DC-388]
    res->AC_EVSEChargeParameter_isUsed = 0u;

    if (((req->EVRequestedEnergyTransferType != din_EVRequestedEnergyTransferType_DC_core) &&
         (req->EVRequestedEnergyTransferType != din_EVRequestedEnergyTransferType_DC_extended)) ||
        conn->ctx->evse_v2g_data.charge_service.SupportedEnergyTransferMode.EnergyTransferMode.array[0] !=
            (iso2_EnergyTransferModeType)req->EVRequestedEnergyTransferType) {
        res->ResponseCode = din_responseCodeType_FAILED_WrongEnergyTransferType; // [V2G-DC-397] Failed reponse code is
                                                                                 // logged at the end of the function
    } else {
        log_selected_energy_transfer_type((int)req->EVRequestedEnergyTransferType);
    }

    res->ResponseCode = (req->AC_EVChargeParameter_isUsed == (unsigned int)1)
                            ? din_responseCodeType_FAILED_WrongChargeParameter
                            : res->ResponseCode; // [V2G-DC-398]

    /* DC_EVSEChargeParameter */
    res->DC_EVSEChargeParameter.DC_EVSEStatus.EVSEIsolationStatus =
        (din_isolationLevelType)conn->ctx->evse_v2g_data.evse_isolation_status;
    res->DC_EVSEChargeParameter.DC_EVSEStatus.EVSEIsolationStatus_isUsed =
        conn->ctx->evse_v2g_data.evse_isolation_status_is_used;

    res->DC_EVSEChargeParameter.DC_EVSEStatus.EVSENotification =
        (din_EVSENotificationType)conn->ctx->evse_v2g_data.evse_notification;
    res->DC_EVSEChargeParameter.DC_EVSEStatus.EVSEStatusCode =
        (true == conn->ctx->intl_emergency_shutdown)
            ? din_DC_EVSEStatusCodeType_EVSE_EmergencyShutdown
            : (din_DC_EVSEStatusCodeType)conn->ctx->evse_v2g_data.evse_status_code[PHASE_PARAMETER];
    res->DC_EVSEChargeParameter.DC_EVSEStatus.NotificationMaxDelay = conn->ctx->evse_v2g_data.notification_max_delay;

    if (conn->ctx->evse_v2g_data.evse_current_regulation_tolerance_is_used) {
        load_din_physical_value(&res->DC_EVSEChargeParameter.EVSECurrentRegulationTolerance,
                                &conn->ctx->evse_v2g_data.evse_current_regulation_tolerance);
        res->DC_EVSEChargeParameter.EVSECurrentRegulationTolerance.Unit_isUsed = (unsigned int)1;
    }
    res->DC_EVSEChargeParameter.EVSECurrentRegulationTolerance_isUsed =
        conn->ctx->evse_v2g_data.evse_current_regulation_tolerance_is_used;

    load_din_physical_value(&res->DC_EVSEChargeParameter.EVSEEnergyToBeDelivered,
                            &conn->ctx->evse_v2g_data.evse_energy_to_be_delivered);
    res->DC_EVSEChargeParameter.EVSEEnergyToBeDelivered_isUsed =
        conn->ctx->evse_v2g_data.evse_energy_to_be_delivered_is_used;

    load_din_physical_value(&res->DC_EVSEChargeParameter.EVSEMaximumCurrentLimit,
                            &conn->ctx->evse_v2g_data.evse_maximum_current_limit);

    load_din_physical_value(&res->DC_EVSEChargeParameter.EVSEMaximumPowerLimit,
                            &conn->ctx->evse_v2g_data.evse_maximum_power_limit);
    res->DC_EVSEChargeParameter.EVSEMaximumPowerLimit_isUsed =
        conn->ctx->evse_v2g_data.evse_maximum_power_limit_is_used;

    load_din_physical_value(&res->DC_EVSEChargeParameter.EVSEMaximumVoltageLimit,
                            &conn->ctx->evse_v2g_data.evse_maximum_voltage_limit);

    load_din_physical_value(&res->DC_EVSEChargeParameter.EVSEMinimumCurrentLimit,
                            &conn->ctx->evse_v2g_data.evse_minimum_current_limit);

    load_din_physical_value(&res->DC_EVSEChargeParameter.EVSEMinimumVoltageLimit,
                            &conn->ctx->evse_v2g_data.evse_minimum_voltage_limit);

    load_din_physical_value(&res->DC_EVSEChargeParameter.EVSEPeakCurrentRipple,
                            &conn->ctx->evse_v2g_data.evse_peak_current_ripple);
    res->DC_EVSEChargeParameter_isUsed = (unsigned int)1;

    // res->EVSEChargeParameter.noContent
    res->EVSEChargeParameter_isUsed = (unsigned int)0;
    res->EVSEProcessing = ((uint8_t)0 == conn->ctx->evse_v2g_data.evse_processing[PHASE_PARAMETER])
                              ? din_EVSEProcessingType_Finished
                              : din_EVSEProcessingType_Ongoing;

    if ((unsigned int)1 == res->DC_EVSEChargeParameter.EVSEMaximumPowerLimit_isUsed) {
        res->SAScheduleList.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].PMax =
            (SHRT_MAX < (conn->ctx->evse_v2g_data.evse_maximum_power_limit.Value *
                         pow(10, conn->ctx->evse_v2g_data.evse_maximum_power_limit.Multiplier)))
                ? SHRT_MAX
                : (conn->ctx->evse_v2g_data.evse_maximum_power_limit.Value *
                   pow(10, conn->ctx->evse_v2g_data.evse_maximum_power_limit.Multiplier));
    } else {
        res->SAScheduleList.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].PMax = SHRT_MAX;
    }
    res->SAScheduleList.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.duration =
        SA_SCHEDULE_DURATION; // Must cover 24 hours
    res->SAScheduleList.SAScheduleTuple.array[0]
        .PMaxSchedule.PMaxScheduleEntry.array[0]
        .RelativeTimeInterval.duration_isUsed = 1; // Must be used in DIN
    res->SAScheduleList.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval.start = 0;
    res->SAScheduleList.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].RelativeTimeInterval_isUsed =
        1;
    res->SAScheduleList.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.array[0].TimeInterval_isUsed =
        0; // no content

    res->SAScheduleList.SAScheduleTuple.array[0].SalesTariff_isUsed =
        0; // In the scope of DIN 70121, this optional element shall not be used. [V2G-DC-554]
    res->SAScheduleList.SAScheduleTuple.array[0].SAScheduleTupleID = SASCHEDULETUPLEID;
    res->SAScheduleList.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleEntry.arrayLen = 1;
    res->SAScheduleList.SAScheduleTuple.array[0].PMaxSchedule.PMaxScheduleID = 1;
    res->SAScheduleList.SAScheduleTuple.arrayLen = 1;
    res->SAScheduleList_isUsed = (unsigned int)1;

    // res->SASchedules.noContent
    res->SASchedules_isUsed = (unsigned int)0;

    /* Check the current response code and check if no external error has occurred */
    nextEvent = utils::din_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    if (res->EVSEProcessing == din_EVSEProcessingType_Finished) {
        if (res->DC_EVSEChargeParameter.DC_EVSEStatus.EVSEStatusCode != din_DC_EVSEStatusCodeType_EVSE_Ready) {
            ESP_LOGW(TAG, "EVSE wants to finish charge parameter phase, but status code is not set to 'ready' (1)");
        }
        conn->ctx->state = WAIT_FOR_CABLECHECK; // [V2G-DC-453]
    } else {
        conn->ctx->state = WAIT_FOR_CHARGEPARAMETERDISCOVERY; // [V2G-DC-498]
    }

    return nextEvent;
}

/*!
 * \brief handle_din_service_discovery This function handles the din power delivery msg pair. It analyzes the request
 * msg and fills the response msg. The request and response msg based on the open V2G structures. This structures must
 * be provided within the \c conn structure. [V2G-DC-461]
 * \param conn is the structure with the V2G msg pair.
 * \return Returns the next V2G-event.
 */
static enum v2g_event handle_din_power_delivery(struct v2g_connection* conn) {
    struct din_PowerDeliveryReqType* req = &conn->exi_in.dinEXIDocument->V2G_Message.Body.PowerDeliveryReq;
    struct din_PowerDeliveryResType* res = &conn->exi_out.dinEXIDocument->V2G_Message.Body.PowerDeliveryRes;
    enum v2g_event nextEvent = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the MQTT interface */
    publish_din_power_delivery_req(conn->ctx, req);

    if (req->ReadyToChargeState == (int)0) {
        conn->ctx->p_charger->publish_current_demand_finished(nullptr);
        conn->ctx->p_charger->publish_dc_open_contactor(nullptr);
        conn->ctx->session.is_charging = false;
    } else {
        conn->ctx->p_charger->publish_v2g_setup_finished(nullptr);
    }

    /* Now fill the evse response message */
    res->ResponseCode = din_responseCodeType_OK; // [V2G-DC-388]

    res->AC_EVSEStatus_isUsed = (unsigned int)0;
    res->DC_EVSEStatus.EVSEIsolationStatus = (din_isolationLevelType)conn->ctx->evse_v2g_data.evse_isolation_status;
    res->DC_EVSEStatus.EVSEIsolationStatus_isUsed = conn->ctx->evse_v2g_data.evse_isolation_status_is_used;
    res->DC_EVSEStatus.EVSENotification = (din_EVSENotificationType)conn->ctx->evse_v2g_data.evse_notification;
    res->DC_EVSEStatus.NotificationMaxDelay = conn->ctx->evse_v2g_data.notification_max_delay;
    res->DC_EVSEStatus.EVSEStatusCode =
        (conn->ctx->intl_emergency_shutdown == true)
            ? din_DC_EVSEStatusCodeType_EVSE_EmergencyShutdown
            : (din_DC_EVSEStatusCodeType)conn->ctx->evse_v2g_data.evse_status_code[PHASE_CHARGE];
    res->DC_EVSEStatus_isUsed = (unsigned int)1;
    res->EVSEStatus_isUsed = (unsigned int)0;
    // res->EVSEStatus.noContent

    /* Check response code */
    if (req->ChargingProfile_isUsed == (unsigned int)1) {
        /* Check the selected SAScheduleTupleID */
        res->ResponseCode = (req->ChargingProfile.SAScheduleTupleID != (int16_t)SASCHEDULETUPLEID)
                                ? din_responseCodeType_FAILED_TariffSelectionInvalid
                                : res->ResponseCode; // [V2G-DC-400]

        for (uint16_t idx = 0; idx < req->ChargingProfile.ProfileEntry.arrayLen; idx++) {
            bool entry_found = (req->ChargingProfile.ProfileEntry.array[idx].ChargingProfileEntryStart <=
                                (uint32_t)SA_SCHEDULE_DURATION);

            if ((entry_found == false) || (req->ChargingProfile.ProfileEntry.array[idx].ChargingProfileEntryMaxPower >
                                           (conn->ctx->evse_v2g_data.evse_maximum_power_limit.Value *
                                            pow(10, conn->ctx->evse_v2g_data.evse_maximum_power_limit.Multiplier)))) {
                // res->ResponseCode = din_responseCodeType_FAILED_ChargingProfileInvalid; //[V2G-DC-399]. Currently
                // commented to increase compatibility with EV'S
                ESP_LOGW(TAG, "EV's charging profile is invalid (ChargingProfileEntryMaxPower %d too high)!",
                     req->ChargingProfile.ProfileEntry.array[idx].ChargingProfileEntryMaxPower);
                break;
            }
        }
    }

    res->ResponseCode = ((req->ReadyToChargeState == (int)1) &&
                         (res->DC_EVSEStatus.EVSEStatusCode != din_DC_EVSEStatusCodeType_EVSE_Ready))
                            ? din_responseCodeType_FAILED_PowerDeliveryNotApplied
                            : res->ResponseCode; // [V2G-DC-401]

    /* Check the current response code and check if no external error has occurred */
    nextEvent = utils::din_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    if ((req->ReadyToChargeState == (int)1) && (V2G_CURRENT_DEMAND_MSG != conn->ctx->last_v2g_msg)) {
        conn->ctx->state = WAIT_FOR_CURRENTDEMAND; // [V2G-DC-462]
    } else {
        /* abort charging session if EV is ready to charge after current demand phase */
        if (req->ReadyToChargeState == (int)1) {
            res->ResponseCode = din_responseCodeType_FAILED;
            nextEvent = V2G_EVENT_SEND_AND_TERMINATE;
        }
        conn->ctx->state = WAIT_FOR_WELDINGDETECTION_SESSIONSTOP; // [V2G-DC-459]
    }

    return nextEvent;
}

/*!
 * \brief handle_din_service_discovery This function handles the din cable check msg pair. It analyzes the request msg
 * and fills the response msg. The request and response msg based on the open V2G structures. This structures must be
 * provided within the \c conn structure. [V2G-DC-454]
 * \param conn is the structure with the V2G msg pair.
 * \return Returns the next V2G-event.
 */
static enum v2g_event handle_din_cable_check(struct v2g_connection* conn) {
    struct din_CableCheckReqType* req = &conn->exi_in.dinEXIDocument->V2G_Message.Body.CableCheckReq;
    struct din_CableCheckResType* res = &conn->exi_out.dinEXIDocument->V2G_Message.Body.CableCheckRes;
    enum v2g_event nextEvent = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the MQTT interface */
    publish_DIN_DcEvStatus(conn->ctx, req->DC_EVStatus);

    // TODO: Wait for CP state C [V2G-DC-547]

    /* Now fill the evse response message */
    res->ResponseCode = din_responseCodeType_OK; // [V2G-DC-388]

    res->DC_EVSEStatus.EVSEIsolationStatus = (din_isolationLevelType)conn->ctx->evse_v2g_data.evse_isolation_status;
    res->DC_EVSEStatus.EVSEIsolationStatus_isUsed = conn->ctx->evse_v2g_data.evse_isolation_status_is_used;
    res->DC_EVSEStatus.EVSENotification =
        static_cast<din_EVSENotificationType>(conn->ctx->evse_v2g_data.evse_notification);
    res->DC_EVSEStatus.NotificationMaxDelay = static_cast<uint32_t>(conn->ctx->evse_v2g_data.notification_max_delay);
    res->EVSEProcessing = (conn->ctx->evse_v2g_data.evse_processing[PHASE_ISOLATION] == (uint8_t)0)
                              ? din_EVSEProcessingType_Finished
                              : din_EVSEProcessingType_Ongoing;

    if (conn->ctx->intl_emergency_shutdown == true) {
        res->DC_EVSEStatus.EVSEStatusCode = din_DC_EVSEStatusCodeType_EVSE_EmergencyShutdown;
    } else if (res->EVSEProcessing == din_EVSEProcessingType_Finished) {
        res->DC_EVSEStatus.EVSEStatusCode = din_DC_EVSEStatusCodeType_EVSE_Ready;
    } else {
        res->DC_EVSEStatus.EVSEStatusCode =
            static_cast<din_DC_EVSEStatusCodeType>(conn->ctx->evse_v2g_data.evse_status_code[PHASE_ISOLATION]);
    }

    /* Check the current response code and check if no external error has occurred */
    nextEvent = utils::din_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    if ((res->EVSEProcessing == din_EVSEProcessingType_Finished) &&
        (res->DC_EVSEStatus.EVSEIsolationStatus_isUsed == (unsigned int)1) &&
        ((res->DC_EVSEStatus.EVSEIsolationStatus == din_isolationLevelType_Valid) ||
         (res->DC_EVSEStatus.EVSEIsolationStatus == din_isolationLevelType_Warning)) &&
        (res->DC_EVSEStatus.EVSEStatusCode == din_DC_EVSEStatusCodeType_EVSE_Ready)) {
        conn->ctx->state = WAIT_FOR_PRECHARGE; // [V2G-DC-499]
    } else {
        if ((res->EVSEProcessing == din_EVSEProcessingType_Finished) &&
            ((res->DC_EVSEStatus.EVSEIsolationStatus_isUsed == (unsigned int)0) ||
             ((res->DC_EVSEStatus.EVSEIsolationStatus != din_isolationLevelType_Valid) &&
              (din_isolationLevelType_Warning != res->DC_EVSEStatus.EVSEIsolationStatus)))) {
            ESP_LOGW(TAG, "EVSE wants to finish cable check phase, but either status code is not set to "
                                     "'ready' (1) or isolation status is not valid");
        }

        conn->ctx->state = WAIT_FOR_CABLECHECK; // [V2G-DC-455]
    }

    return nextEvent;
}

/*!
 * \brief handle_din_service_discovery This function handles the din pre charge msg pair. It analyzes the request msg
 * and fills the response msg. The request and response msg based on the open V2G structures. This structures must be
 * provided within the \c conn structure. [V2G-DC-457]
 * \param conn is the structure with the V2G msg pair.
 * \return Returns the next V2G-event.
 */
static enum v2g_event handle_din_pre_charge(struct v2g_connection* conn) {
    struct din_PreChargeReqType* req = &conn->exi_in.dinEXIDocument->V2G_Message.Body.PreChargeReq;
    struct din_PreChargeResType* res = &conn->exi_out.dinEXIDocument->V2G_Message.Body.PreChargeRes;
    enum v2g_event nextEvent = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the customer MQTT interface */
    publish_din_precharge_req(conn->ctx, req);

    /* Now fill the EVSE response message */
    res->ResponseCode = din_responseCodeType_OK; // [V2G-DC-388]

    res->DC_EVSEStatus.EVSEIsolationStatus = (din_isolationLevelType)conn->ctx->evse_v2g_data.evse_isolation_status;
    res->DC_EVSEStatus.EVSEIsolationStatus_isUsed = conn->ctx->evse_v2g_data.evse_isolation_status_is_used;
    res->DC_EVSEStatus.EVSENotification = (din_EVSENotificationType)conn->ctx->evse_v2g_data.evse_notification;
    res->DC_EVSEStatus.EVSEStatusCode =
        (conn->ctx->intl_emergency_shutdown == true)
            ? din_DC_EVSEStatusCodeType_EVSE_EmergencyShutdown
            : (din_DC_EVSEStatusCodeType)conn->ctx->evse_v2g_data.evse_status_code[PHASE_PRECHARGE];
    res->DC_EVSEStatus.NotificationMaxDelay = conn->ctx->evse_v2g_data.notification_max_delay;

    load_din_physical_value(&res->EVSEPresentVoltage, &conn->ctx->evse_v2g_data.evse_present_voltage);

    /* Check the current response code and check if no external error has occurred */
    nextEvent = utils::din_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = WAIT_FOR_PRECHARGE_POWERDELIVERY; // [V2G-DC-458]

    return nextEvent;
}

/*!
 * \brief handle_din_service_discovery This function handles the din current demand msg pair. It analyzes the request
 * msg and fills the response msg. The request and response msg based on the open V2G structures. This structures must
 * be provided within the \c conn structure. [V2G-DC-464]
 * \param conn is the structure with the V2G msg pair.
 * \return Returns the next V2G-event.
 */
static enum v2g_event handle_din_current_demand(struct v2g_connection* conn) {
    struct din_CurrentDemandReqType* req = &conn->exi_in.dinEXIDocument->V2G_Message.Body.CurrentDemandReq;
    struct din_CurrentDemandResType* res = &conn->exi_out.dinEXIDocument->V2G_Message.Body.CurrentDemandRes;
    enum v2g_event nextEvent = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the MQTT interface */
    publish_din_current_demand_req(conn->ctx, req);

    /* Now fill the evse response message */
    res->ResponseCode = din_responseCodeType_OK; // [V2G-DC-388]

    res->DC_EVSEStatus.EVSEIsolationStatus = (din_isolationLevelType)conn->ctx->evse_v2g_data.evse_isolation_status;
    res->DC_EVSEStatus.EVSEIsolationStatus_isUsed = conn->ctx->evse_v2g_data.evse_isolation_status_is_used;
    res->DC_EVSEStatus.EVSENotification = (din_EVSENotificationType)conn->ctx->evse_v2g_data.evse_notification;
    res->DC_EVSEStatus.EVSEStatusCode =
        (conn->ctx->intl_emergency_shutdown == true)
            ? din_DC_EVSEStatusCodeType_EVSE_EmergencyShutdown
            : (din_DC_EVSEStatusCodeType)conn->ctx->evse_v2g_data.evse_status_code[PHASE_CHARGE];
    res->DC_EVSEStatus.NotificationMaxDelay = (uint32_t)conn->ctx->evse_v2g_data.notification_max_delay;

    res->EVSECurrentLimitAchieved = conn->ctx->evse_v2g_data.evse_current_limit_achieved;

    res->EVSEMaximumCurrentLimit_isUsed = conn->ctx->evse_v2g_data.evse_maximum_current_limit_is_used;
    load_din_physical_value(&res->EVSEMaximumCurrentLimit, &conn->ctx->evse_v2g_data.evse_maximum_current_limit);

    res->EVSEMaximumPowerLimit_isUsed = conn->ctx->evse_v2g_data.evse_maximum_power_limit_is_used;
    load_din_physical_value(&res->EVSEMaximumPowerLimit, &conn->ctx->evse_v2g_data.evse_maximum_power_limit);

    res->EVSEMaximumVoltageLimit_isUsed = conn->ctx->evse_v2g_data.evse_maximum_voltage_limit_is_used;
    load_din_physical_value(&res->EVSEMaximumVoltageLimit, &conn->ctx->evse_v2g_data.evse_maximum_voltage_limit);

    res->EVSEPowerLimitAchieved = conn->ctx->evse_v2g_data.evse_power_limit_achieved;

    load_din_physical_value(&res->EVSEPresentCurrent, &conn->ctx->evse_v2g_data.evse_present_current);
    load_din_physical_value(&res->EVSEPresentVoltage, &conn->ctx->evse_v2g_data.evse_present_voltage);

    res->EVSEVoltageLimitAchieved = conn->ctx->evse_v2g_data.evse_voltage_limit_achieved;

    /* Check the current response code and check if no external error has occurred */
    nextEvent = utils::din_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = WAIT_FOR_CURRENTDEMAND_POWERDELIVERY; // [V2G-DC-465]

    return nextEvent;
}

/*!
 * \brief handle_din_service_discovery This function handles the din welding detection msg pair. It analyzes the request
 * msg and fills the response msg. The request and response msg based on the open V2G structures. This structures must
 * be provided within the \c conn structure. [V2G-DC-468]
 * \param conn is the structure with the V2G msg pair.
 * \return Returns the next V2G-event.
 */
static enum v2g_event handle_din_welding_detection(struct v2g_connection* conn) {
    struct din_WeldingDetectionReqType* req = &conn->exi_in.dinEXIDocument->V2G_Message.Body.WeldingDetectionReq;
    struct din_WeldingDetectionResType* res = &conn->exi_out.dinEXIDocument->V2G_Message.Body.WeldingDetectionRes;
    enum v2g_event nextEvent = V2G_EVENT_NO_EVENT;

    /* At first, publish the received EV request message to the MQTT interface */
    publish_DIN_DcEvStatus(conn->ctx, req->DC_EVStatus);

    /* TODO: Waiting for CP-State B [V2G-DC-556]. */

    /* Now fill the evse response message */
    res->ResponseCode = din_responseCodeType_OK; // [V2G-DC-388]

    res->DC_EVSEStatus.EVSEIsolationStatus = (din_isolationLevelType)conn->ctx->evse_v2g_data.evse_isolation_status;
    res->DC_EVSEStatus.EVSEIsolationStatus_isUsed = conn->ctx->evse_v2g_data.evse_isolation_status_is_used;
    res->DC_EVSEStatus.EVSENotification = (din_EVSENotificationType)conn->ctx->evse_v2g_data.evse_notification;
    res->DC_EVSEStatus.EVSEStatusCode =
        (conn->ctx->intl_emergency_shutdown == true)
            ? din_DC_EVSEStatusCodeType_EVSE_EmergencyShutdown
            : (din_DC_EVSEStatusCodeType)conn->ctx->evse_v2g_data.evse_status_code[PHASE_WELDING];
    res->DC_EVSEStatus.NotificationMaxDelay = (uint32_t)conn->ctx->evse_v2g_data.notification_max_delay;

    load_din_physical_value(&res->EVSEPresentVoltage, &conn->ctx->evse_v2g_data.evse_present_voltage);

    /* Check the current response code and check if no external error has occurred */
    nextEvent = utils::din_validate_response_code(&res->ResponseCode, conn);

    /* Set next expected req msg */
    conn->ctx->state = WAIT_FOR_WELDINGDETECTION_SESSIONSTOP; // [V2G-DC-469]

    return nextEvent;
}

/*!
 * \brief handle_din_session_stop This function handles the din session stop msg pair. It analyzes the request msg and
 * fills the response msg. The request and response msg based on the open V2G structures. This structures must be
 * provided within the \c conn structure. [V2G-DC-450]
 * \param conn is the structure with the V2G msg pair.
 * \return Returns the next V2G-event.
 */
static enum v2g_event handle_din_session_stop(struct v2g_connection* conn) {
    struct din_SessionStopResType* res = &conn->exi_out.dinEXIDocument->V2G_Message.Body.SessionStopRes;

    /* Now fill the EVSE response message */
    res->ResponseCode = din_responseCodeType_OK; // [V2G-DC-388]

    /* Check the current response code and check if no external error has occurred */
    utils::din_validate_response_code(&res->ResponseCode, conn);

    /* Setuo dlink action */
    conn->dlink_action = MQTT_DLINK_ACTION_TERMINATE;

    /* Set next expected req msg */
    conn->ctx->state = WAIT_FOR_TERMINATED_SESSION; // [V2G-DC-451]

    /* Check the current response code and check if no external error has occurred */
    return V2G_EVENT_SEND_AND_TERMINATE; // Charging must be terminated after sending the response message.
}

enum v2g_event din_handle_request(v2g_connection* conn) {
    using namespace states;

    struct din_exiDocument* exi_in = conn->exi_in.dinEXIDocument;
    struct din_exiDocument* exi_out = conn->exi_out.dinEXIDocument;
    enum v2g_event next_v2g_event = V2G_EVENT_TERMINATE_CONNECTION; // ERROR_UNEXPECTED_REQUEST_MESSAGE;

    /* extract session id */
    conn->ctx->ev_v2g_data.received_session_id = v2g_session_id_from_exi(false, exi_in);

    /* init V2G structure (document, header, body) */
    init_din_exiDocument(exi_out);
    init_din_MessageHeaderType(&exi_out->V2G_Message.Header);

    exi_out->V2G_Message.Header.SessionID.bytesLen = 8;
    init_din_BodyType(&exi_out->V2G_Message.Body);

    // === Start request handling ===
    if (exi_in->V2G_Message.Body.CurrentDemandReq_isUsed) {
        ESP_LOGV(TAG, "Handling CurrentDemandReq");
        if (conn->ctx->last_v2g_msg == V2G_POWER_DELIVERY_MSG) {
            conn->ctx->p_charger->publish_current_demand_started(nullptr);
            conn->ctx->session.is_charging = true;
        }
        conn->ctx->current_v2g_msg = V2G_CURRENT_DEMAND_MSG;
        exi_out->V2G_Message.Body.CurrentDemandRes_isUsed = 1u;
        init_din_CurrentDemandResType(&exi_out->V2G_Message.Body.CurrentDemandRes);
        next_v2g_event = handle_din_current_demand(conn);
    } else if (exi_in->V2G_Message.Body.SessionSetupReq_isUsed) {
        ESP_LOGV(TAG, "Handling SessionSetupReq");
        conn->ctx->current_v2g_msg = V2G_SESSION_SETUP_MSG;
        exi_out->V2G_Message.Body.SessionSetupRes_isUsed = 1u;
        init_din_SessionSetupResType(&exi_out->V2G_Message.Body.SessionSetupRes);
        /* Handle v2g msg */
        next_v2g_event = handle_din_session_setup(conn);
    } else if (exi_in->V2G_Message.Body.ServiceDiscoveryReq_isUsed) {
        ESP_LOGV(TAG, "Handling ServiceDiscoveryReq");
        conn->ctx->current_v2g_msg = V2G_SERVICE_DISCOVERY_MSG;
        exi_out->V2G_Message.Body.ServiceDiscoveryRes_isUsed = 1u;
        init_din_ServiceDiscoveryResType(&exi_out->V2G_Message.Body.ServiceDiscoveryRes);
        next_v2g_event = handle_din_service_discovery(conn);
    } else if (exi_in->V2G_Message.Body.ServicePaymentSelectionReq_isUsed) {
        ESP_LOGV(TAG, "Handling PaymentServiceSelectionReq");
        conn->ctx->current_v2g_msg = V2G_PAYMENT_SERVICE_SELECTION_MSG;
        exi_out->V2G_Message.Body.ServicePaymentSelectionRes_isUsed = 1u;
        init_din_ServicePaymentSelectionResType(&exi_out->V2G_Message.Body.ServicePaymentSelectionRes);
        next_v2g_event = handle_din_service_payment_selection(conn);
    } else if (exi_in->V2G_Message.Body.ContractAuthenticationReq_isUsed) {
        ESP_LOGV(TAG, "Handling ContractAuthenticationReq");
        conn->ctx->current_v2g_msg = V2G_AUTHORIZATION_MSG;
        if (conn->ctx->last_v2g_msg != V2G_AUTHORIZATION_MSG) {
            ESP_LOGI(TAG, "Auth-phase started");
            conn->ctx->p_charger->publish_require_auth_eim(nullptr);
        }
        exi_out->V2G_Message.Body.ContractAuthenticationRes_isUsed = 1u;
        init_din_ContractAuthenticationResType(&exi_out->V2G_Message.Body.ContractAuthenticationRes);
        next_v2g_event = handle_din_contract_authentication(conn);
    } else if (exi_in->V2G_Message.Body.PaymentDetailsReq_isUsed) {
        ESP_LOGE(TAG, "PaymentDetails request is not supported in DIN 70121");
        conn->ctx->current_v2g_msg = V2G_UNKNOWN_MSG;
        next_v2g_event = V2G_EVENT_IGNORE_MSG;
    } else if (exi_in->V2G_Message.Body.ServiceDetailReq_isUsed) {
        ESP_LOGE(TAG, "ServiceDetail request is not supported in DIN 70121");
        conn->ctx->current_v2g_msg = V2G_UNKNOWN_MSG;
        next_v2g_event = V2G_EVENT_IGNORE_MSG;
    } else if (exi_in->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed) {
        ESP_LOGV(TAG, "Handling ChargeParameterDiscoveryReq");
        conn->ctx->current_v2g_msg = V2G_CHARGE_PARAMETER_DISCOVERY_MSG;
        if (conn->ctx->last_v2g_msg == V2G_AUTHORIZATION_MSG) {
            ESP_LOGI(TAG, "Parameter-phase started");
        }
        exi_out->V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed = 1u;
        init_din_ChargeParameterDiscoveryResType(&exi_out->V2G_Message.Body.ChargeParameterDiscoveryRes);
        next_v2g_event = handle_din_charge_parameter(conn);
    } else if (exi_in->V2G_Message.Body.CableCheckReq_isUsed) {
        ESP_LOGV(TAG, "Handling CableCheckReq");
        conn->ctx->current_v2g_msg = V2G_CABLE_CHECK_MSG;
        if (conn->ctx->last_v2g_msg == V2G_CHARGE_PARAMETER_DISCOVERY_MSG) {
            conn->ctx->p_charger->publish_start_cable_check(nullptr);
            ESP_LOGI(TAG, "Isolation-phase started");
        }
        exi_out->V2G_Message.Body.CableCheckRes_isUsed = 1u;
        init_din_CableCheckResType(&exi_out->V2G_Message.Body.CableCheckRes);
        next_v2g_event = handle_din_cable_check(conn);
    } else if (exi_in->V2G_Message.Body.PreChargeReq_isUsed) {
        ESP_LOGV(TAG, "Handling PreChargeReq");
        conn->ctx->current_v2g_msg = V2G_PRE_CHARGE_MSG;
        if (conn->ctx->last_v2g_msg == V2G_CABLE_CHECK_MSG) {
            conn->ctx->p_charger->publish_start_pre_charge(nullptr);
            ESP_LOGI(TAG, "Precharge-phase started");
        }
        exi_out->V2G_Message.Body.PreChargeRes_isUsed = 1u;
        init_din_PreChargeResType(&exi_out->V2G_Message.Body.PreChargeRes);
        next_v2g_event = handle_din_pre_charge(conn);
    } else if (exi_in->V2G_Message.Body.PowerDeliveryReq_isUsed) {
        ESP_LOGV(TAG, "Handling PowerDeliveryReq");
        conn->ctx->current_v2g_msg = V2G_POWER_DELIVERY_MSG;
        if (conn->ctx->last_v2g_msg == V2G_PRE_CHARGE_MSG) {
            ESP_LOGI(TAG, "Charge-phase started");
        }
        exi_out->V2G_Message.Body.PowerDeliveryRes_isUsed = 1u;
        init_din_PowerDeliveryResType(&exi_out->V2G_Message.Body.PowerDeliveryRes);
        next_v2g_event = handle_din_power_delivery(conn);
    } else if (exi_in->V2G_Message.Body.ChargingStatusReq_isUsed) {
        ESP_LOGV(TAG, "ChargingStatus request is not supported in DIN 70121");
        conn->ctx->current_v2g_msg = V2G_UNKNOWN_MSG;
        exi_out->V2G_Message.Body.ChargingStatusRes_isUsed = 0u;
        init_din_ChargingStatusResType(&exi_out->V2G_Message.Body.ChargingStatusRes);
        next_v2g_event = V2G_EVENT_IGNORE_MSG;
    } else if (exi_in->V2G_Message.Body.MeteringReceiptReq_isUsed) {
        ESP_LOGV(TAG, "MeteringReceipt request is not supported in DIN 70121");
        conn->ctx->current_v2g_msg = V2G_UNKNOWN_MSG;
        exi_out->V2G_Message.Body.MeteringReceiptRes_isUsed = 0u;
        init_din_MeteringReceiptResType(&exi_out->V2G_Message.Body.MeteringReceiptRes);
        next_v2g_event = V2G_EVENT_IGNORE_MSG;
    } else if (exi_in->V2G_Message.Body.CertificateUpdateReq_isUsed) {
        ESP_LOGV(TAG, "CertificateUpdate request is not supported in DIN 70121");
        conn->ctx->current_v2g_msg = V2G_UNKNOWN_MSG;
        next_v2g_event = V2G_EVENT_IGNORE_MSG;
    } else if (exi_in->V2G_Message.Body.CertificateInstallationReq_isUsed) {
        ESP_LOGV(TAG, "CertificateInstallation request is not supported in DIN 70121");
        conn->ctx->current_v2g_msg = V2G_UNKNOWN_MSG;
        next_v2g_event = V2G_EVENT_IGNORE_MSG;
    } else if (exi_in->V2G_Message.Body.WeldingDetectionReq_isUsed) {
        ESP_LOGV(TAG, "Handling WeldingDetectionReq");
        conn->ctx->current_v2g_msg = V2G_WELDING_DETECTION_MSG;
        if (conn->ctx->last_v2g_msg == V2G_POWER_DELIVERY_MSG) {
            ESP_LOGI(TAG, "Welding-phase started");
        }
        exi_out->V2G_Message.Body.WeldingDetectionRes_isUsed = 1u;
        init_din_WeldingDetectionResType(&exi_out->V2G_Message.Body.WeldingDetectionRes);
        next_v2g_event = handle_din_welding_detection(conn);
    } else if (exi_in->V2G_Message.Body.SessionStopReq_isUsed) {
        ESP_LOGV(TAG, "Handling SessionStopReq");
        conn->ctx->current_v2g_msg = V2G_SESSION_STOP_MSG;

        exi_out->V2G_Message.Body.SessionStopRes_isUsed = 1u;
        init_din_SessionStopResType(&exi_out->V2G_Message.Body.SessionStopRes);
        next_v2g_event = handle_din_session_stop(conn);
    } else {
        ESP_LOGE(TAG, "Create_response_message: request type not found");
        next_v2g_event = V2G_EVENT_IGNORE_MSG;
    }

    if (next_v2g_event != V2G_EVENT_IGNORE_MSG) {
        /* Configure session id */
        memcpy(exi_out->V2G_Message.Header.SessionID.bytes, &conn->ctx->evse_v2g_data.session_id, sizeof(uint64_t));

        // TODO: Set byteLen
        exi_out->V2G_Message.Header.SessionID.bytesLen = din_sessionIDType_BYTES_SIZE;

        ESP_LOGV(TAG, "Current state: %s", din_states[conn->ctx->state].description);
        conn->ctx->last_v2g_msg = conn->ctx->current_v2g_msg;
    }

    return next_v2g_event;
}
