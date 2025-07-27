#ifndef SESSION_UTILS_HPP
#define SESSION_UTILS_HPP

#include <v2g.hpp>

namespace utils {

v2g_event check_session_and_termination(iso2_responseCodeType* response_code,
                                        const struct v2g_connection* conn);

v2g_event check_session_and_termination(din_responseCodeType* response_code,
                                        const struct v2g_connection* conn);

} // namespace utils

#endif // SESSION_UTILS_HPP
