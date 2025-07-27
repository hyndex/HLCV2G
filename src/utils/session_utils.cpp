#include "utils/session_utils.hpp"

namespace utils {

v2g_event check_session_and_termination(iso2_responseCodeType* response_code,
                                        const struct v2g_connection* conn) {
    if ((conn->ctx->current_v2g_msg != V2G_SESSION_SETUP_MSG) &&
        (conn->ctx->evse_v2g_data.session_id != conn->ctx->ev_v2g_data.received_session_id)) {
        *response_code = iso2_responseCodeType_FAILED_UnknownSession;
    }
    if (conn->ctx->terminate_connection_on_failed_response &&
        (*response_code >= iso2_responseCodeType_FAILED)) {
        return V2G_EVENT_SEND_AND_TERMINATE;
    }
    return V2G_EVENT_NO_EVENT;
}

v2g_event check_session_and_termination(din_responseCodeType* response_code,
                                        const struct v2g_connection* conn) {
    if ((conn->ctx->current_v2g_msg != V2G_SESSION_SETUP_MSG) &&
        (conn->ctx->evse_v2g_data.session_id != conn->ctx->ev_v2g_data.received_session_id)) {
        *response_code = din_responseCodeType_FAILED_UnknownSession;
    }
    if (conn->ctx->terminate_connection_on_failed_response &&
        (*response_code >= din_responseCodeType_FAILED)) {
        return V2G_EVENT_SEND_AND_TERMINATE;
    }
    return V2G_EVENT_NO_EVENT;
}

} // namespace utils
