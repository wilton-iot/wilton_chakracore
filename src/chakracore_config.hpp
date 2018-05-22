/*
 * Copyright 2018, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   chakracore_config.hpp
 * Author: alex
 *
 * Created on May 22, 2018, 3:20 PM
 */

#ifndef WILTON_CHAKRACORE_CONFIG_HPP
#define WILTON_CHAKRACORE_CONFIG_HPP

#include <cstdint>

#include "staticlib/json.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

namespace wilton {
namespace chakracore {

class chakracore_config {
public:
    uint64_t runtime_memory_limit = 0;
    bool disable_background_work = false;
    bool disable_native_code_generation = false;
    bool disable_fatal_on_oom = false;

    chakracore_config(const sl::json::value& env_json) {
        for (const sl::json::field& fi : env_json.as_object()) {
            auto& name = fi.name();
            if (sl::utils::starts_with(name, "CHAKRA_")) {
                if ("CHAKRA_RuntimeMemoryLimit" == name) {
                    this->runtime_memory_limit = str_as_u64(fi, name);
                } else if ("CHAKRA_DisableBackgroundWork" == name) {
                    this->disable_background_work = str_as_bool(fi, name);
                } else if ("CHAKRA_DisableNativeCodeGeneration" == name) {
                    this->disable_native_code_generation = str_as_bool(fi, name);
                } else if ("CHAKRA_DisableFatalOnOOM" == name) {
                    this->disable_fatal_on_oom = str_as_bool(fi, name);
                } else {
                    throw support::exception(TRACEMSG("Unknown 'chakracore_config' field: [" + name + "]"));
                }
            }
        }
    }

    chakracore_config(const chakracore_config& other) :
    runtime_memory_limit(other.runtime_memory_limit),
    disable_background_work(other.disable_background_work),
    disable_native_code_generation(other.disable_native_code_generation),
    disable_fatal_on_oom(other.disable_fatal_on_oom) { }

    chakracore_config& operator=(const chakracore_config& other) {
        runtime_memory_limit = other.runtime_memory_limit;
        disable_background_work = other.disable_background_work;
        disable_native_code_generation = other.disable_native_code_generation;
        disable_fatal_on_oom = other.disable_fatal_on_oom;
        return *this;
    }

    sl::json::value to_json() const {
        return {
            { "RuntimeMemoryLimit", runtime_memory_limit },
            { "DisableBackgroundWork", disable_background_work },
            { "DisableNativeCodeGeneration", disable_native_code_generation },
            { "DisableFatalOnOOM", disable_fatal_on_oom }
        };
    }

private:

    static uint64_t str_as_u64(const sl::json::field& fi, const std::string& name) {
        auto str = fi.as_string_nonempty_or_throw(name);
        try {
            return sl::utils::parse_uint64(str);
        } catch (std::exception& e) {
            throw support::exception(TRACEMSG(e.what() + 
                    "\nError parsing parameter: [" + name + "], value: [" + str + "]"));
        }
    }

    static bool str_as_bool(const sl::json::field& fi, const std::string& name) {
        auto str = fi.as_string_nonempty_or_throw(name);
        if ("true" == str) {
            return true;
        }
        if ("false" == str) {
            return false;
        }
        throw support::exception(TRACEMSG("Error parsing parameter: [" + name + "]," +
                " value: [" + str + "]"));
    }
};

} // namespace
}

#endif /* WILTON_CHAKRACORE_CONFIG_HPP */

