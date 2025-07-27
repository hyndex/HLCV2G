#include "ISO15118_chargerImplStub.hpp"
#include "evse_securityIntfStub.hpp"
#include "iso15118_extensionsImplStub.hpp"
#include "utest_log.hpp"
#include <gtest/gtest.h>
#include <v2g_ctx.hpp>
#include <v2g.hpp>

// include implementation to access static functions
#include "../src/iso_server.cpp"

namespace {

class IsoServerTest : public testing::Test {
protected:
    module::stub::ModuleAdapterStub adapter;
    module::stub::ISO15118_chargerImplStub charger;
    module::stub::evse_securityIntfStub security;
    module::stub::iso15118_extensionsImplStub extensions;

    v2g_connection conn{};
    v2g_context ctx{};
    iso2_exiDocument exi_in{};
    iso2_exiDocument exi_out{};

    IsoServerTest() : charger(adapter), security(adapter) {}

    void SetUp() override {
        conn.ctx = &ctx;
        ctx.p_charger = &charger;
        ctx.p_extensions = &extensions;
        ctx.r_security = &security;
        conn.exi_in.iso2EXIDocument = &exi_in;
        conn.exi_out.iso2EXIDocument = &exi_out;
        conn.buffer = static_cast<uint8_t*>(malloc(DEFAULT_BUFFER_SIZE));
        conn.stream.data = conn.buffer;
    }

    void TearDown() override {
        free(conn.buffer);
    }
};

TEST_F(IsoServerTest, CertificateUpdateSuccess) {
    ctx.evse_v2g_data.cert_install_res_b64_buffer = "AQ=="; // base64 for 0x01
    ctx.evse_v2g_data.cert_install_status = true;

    exi_out.V2G_Message.Body.CertificateUpdateRes_isUsed = 1u;
    init_iso2_CertificateUpdateResType(&exi_out.V2G_Message.Body.CertificateUpdateRes);

    conn.stream.data_size = V2GTP_HEADER_LENGTH + 1;

    auto ev = handle_iso_certificate_update(&conn);

    EXPECT_EQ(ev, V2G_EVENT_SEND_RECV_EXI_MSG);
    EXPECT_EQ(exi_out.V2G_Message.Body.CertificateUpdateRes.ResponseCode, iso2_responseCodeType_OK);
    ASSERT_EQ(conn.stream.byte_pos, V2GTP_HEADER_LENGTH + 1);
    EXPECT_EQ(conn.buffer[V2GTP_HEADER_LENGTH], 0x01);
}

TEST_F(IsoServerTest, CertificateUpdateDecodeFail) {
    ctx.evse_v2g_data.cert_install_res_b64_buffer = "!"; // invalid base64
    ctx.evse_v2g_data.cert_install_status = true;

    exi_out.V2G_Message.Body.CertificateUpdateRes_isUsed = 1u;
    init_iso2_CertificateUpdateResType(&exi_out.V2G_Message.Body.CertificateUpdateRes);

    conn.stream.data_size = V2GTP_HEADER_LENGTH + 1;

    auto ev = handle_iso_certificate_update(&conn);

    EXPECT_NE(ev, V2G_EVENT_SEND_RECV_EXI_MSG);
    EXPECT_EQ(exi_out.V2G_Message.Body.CertificateUpdateRes.ResponseCode, iso2_responseCodeType_FAILED);
}

TEST_F(IsoServerTest, SessionResumeSuccess) {
    // initial session setup
    exi_out.V2G_Message.Body.SessionSetupRes_isUsed = 1u;
    init_iso2_SessionSetupResType(&exi_out.V2G_Message.Body.SessionSetupRes);
    exi_in.V2G_Message.Body.SessionSetupReq_isUsed = 1u;
    init_iso2_SessionSetupReqType(&exi_in.V2G_Message.Body.SessionSetupReq);
    exi_in.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
    memset(exi_in.V2G_Message.Header.SessionID.bytes, 0, iso2_sessionIDType_BYTES_SIZE);

    auto ev = handle_iso_session_setup(&conn);
    EXPECT_EQ(ev, V2G_EVENT_NO_EVENT);
    EXPECT_EQ(exi_out.V2G_Message.Body.SessionSetupRes.ResponseCode,
              iso2_responseCodeType_OK_NewSessionEstablished);
    uint64_t session_id = ctx.evse_v2g_data.session_id;

    // EV requests pause
    exi_out.V2G_Message.Body.SessionStopRes_isUsed = 1u;
    init_iso2_SessionStopResType(&exi_out.V2G_Message.Body.SessionStopRes);
    exi_in.V2G_Message.Body.SessionStopReq_isUsed = 1u;
    init_iso2_SessionStopReqType(&exi_in.V2G_Message.Body.SessionStopReq);
    exi_in.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
    memcpy(exi_in.V2G_Message.Header.SessionID.bytes, &session_id, iso2_sessionIDType_BYTES_SIZE);
    exi_in.V2G_Message.Body.SessionStopReq.ChargingSession = iso2_chargingSessionType_Pause;
    handle_iso_session_stop(&conn);

    // connection teardown while paused
    v2g_ctx_init_charging_session(&ctx, true);

    // resume session
    exi_out.V2G_Message.Body.SessionSetupRes_isUsed = 1u;
    init_iso2_SessionSetupResType(&exi_out.V2G_Message.Body.SessionSetupRes);
    exi_in.V2G_Message.Body.SessionSetupReq_isUsed = 1u;
    init_iso2_SessionSetupReqType(&exi_in.V2G_Message.Body.SessionSetupReq);
    exi_in.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
    memcpy(exi_in.V2G_Message.Header.SessionID.bytes, &session_id, iso2_sessionIDType_BYTES_SIZE);

    ev = handle_iso_session_setup(&conn);
    EXPECT_EQ(ev, V2G_EVENT_NO_EVENT);
    EXPECT_EQ(exi_out.V2G_Message.Body.SessionSetupRes.ResponseCode,
              iso2_responseCodeType_OK_OldSessionJoined);
    EXPECT_FALSE(ctx.hlc_pause_active);
}

TEST_F(IsoServerTest, SessionResumeUnknown) {
    // create and terminate session
    exi_out.V2G_Message.Body.SessionSetupRes_isUsed = 1u;
    init_iso2_SessionSetupResType(&exi_out.V2G_Message.Body.SessionSetupRes);
    exi_in.V2G_Message.Body.SessionSetupReq_isUsed = 1u;
    init_iso2_SessionSetupReqType(&exi_in.V2G_Message.Body.SessionSetupReq);
    exi_in.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
    memset(exi_in.V2G_Message.Header.SessionID.bytes, 0, iso2_sessionIDType_BYTES_SIZE);

    handle_iso_session_setup(&conn);
    uint64_t old_id = ctx.evse_v2g_data.session_id;

    exi_out.V2G_Message.Body.SessionStopRes_isUsed = 1u;
    init_iso2_SessionStopResType(&exi_out.V2G_Message.Body.SessionStopRes);
    exi_in.V2G_Message.Body.SessionStopReq_isUsed = 1u;
    init_iso2_SessionStopReqType(&exi_in.V2G_Message.Body.SessionStopReq);
    exi_in.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
    memcpy(exi_in.V2G_Message.Header.SessionID.bytes, &old_id, iso2_sessionIDType_BYTES_SIZE);
    exi_in.V2G_Message.Body.SessionStopReq.ChargingSession = iso2_chargingSessionType_Terminate;
    handle_iso_session_stop(&conn);

    // connection teardown after termination
    v2g_ctx_init_charging_session(&ctx, true);

    // try to resume using old session id
    exi_out.V2G_Message.Body.SessionSetupRes_isUsed = 1u;
    init_iso2_SessionSetupResType(&exi_out.V2G_Message.Body.SessionSetupRes);
    exi_in.V2G_Message.Body.SessionSetupReq_isUsed = 1u;
    init_iso2_SessionSetupReqType(&exi_in.V2G_Message.Body.SessionSetupReq);
    exi_in.V2G_Message.Header.SessionID.bytesLen = iso2_sessionIDType_BYTES_SIZE;
    memcpy(exi_in.V2G_Message.Header.SessionID.bytes, &old_id, iso2_sessionIDType_BYTES_SIZE);

    auto ev2 = handle_iso_session_setup(&conn);
    EXPECT_EQ(ev2, V2G_EVENT_NO_EVENT);
    EXPECT_EQ(exi_out.V2G_Message.Body.SessionSetupRes.ResponseCode,
              iso2_responseCodeType_FAILED_UnknownSession);
}

TEST_F(IsoServerTest, ValidateResponseCodeUnknownSession) {
    iso2_responseCodeType rc = iso2_responseCodeType_OK;
    ctx.is_dc_charger = false;
    ctx.state = static_cast<int>(iso_ac_state_id::WAIT_FOR_AUTHORIZATION);
    ctx.current_v2g_msg = V2G_AUTHORIZATION_MSG;
    ctx.evse_v2g_data.session_id = 1;
    ctx.ev_v2g_data.received_session_id = 2;
    ctx.terminate_connection_on_failed_response = false;

    auto ev = iso_validate_response_code(&rc, &conn);
    EXPECT_EQ(rc, iso2_responseCodeType_FAILED_UnknownSession);
    EXPECT_EQ(ev, V2G_EVENT_NO_EVENT);
}

TEST_F(IsoServerTest, ValidateResponseCodeSendTerminate) {
    iso2_responseCodeType rc = iso2_responseCodeType_FAILED;
    ctx.is_dc_charger = false;
    ctx.state = static_cast<int>(iso_ac_state_id::WAIT_FOR_SESSIONSETUP);
    ctx.current_v2g_msg = V2G_SESSION_SETUP_MSG;
    ctx.evse_v2g_data.session_id = 0;
    ctx.ev_v2g_data.received_session_id = 0;
    ctx.terminate_connection_on_failed_response = true;

    auto ev = iso_validate_response_code(&rc, &conn);
    EXPECT_EQ(ev, V2G_EVENT_SEND_AND_TERMINATE);
}

} // namespace
