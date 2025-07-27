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

} // namespace
