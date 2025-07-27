// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 - 2023 Pionix GmbH and Contributors to EVerest

#pragma once

#include <string>
#include <vector>

enum dloglevel_t {
    DLOG_LEVEL_ALWAYS = 0,
    DLOG_LEVEL_ERROR,
    DLOG_LEVEL_WARNING,
    DLOG_LEVEL_INFO,
    DLOG_LEVEL_DEBUG,
    DLOG_LEVEL_TRACE,
};

namespace module::stub {
std::vector<std::string>& get_logs(dloglevel_t loglevel);
void clear_logs();

} // namespace module::stub
