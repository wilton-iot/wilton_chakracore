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
 * File:   chakracore_engine.cpp
 * Author: alex
 *
 * Created on May 12, 2018, 2:11 PM
 */

#include "chakracore_engine.hpp"

#include <cstdio>
#include <array>
#include <functional>
#include <memory>

#include "ChakraCore.h"

#include "staticlib/io.hpp"
#include "staticlib/json.hpp"
#include "staticlib/pimpl/forward_macros.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

#include "wilton/wiltoncall.h"
#include "wilton/wilton_loader.h"

#include "wilton/support/exception.hpp"
#include "wilton/support/logging.hpp"

#include "chakracore_config.hpp"

namespace wilton {
namespace chakracore {

namespace { // anonymous

chakracore_config get_config() {
    char* conf = nullptr;
    int conf_len = 0;
    auto err = wilton_config(std::addressof(conf), std::addressof(conf_len));
    if (nullptr != err) support::throw_wilton_error(err, TRACEMSG(err));
    auto deferred = sl::support::defer([conf] () STATICLIB_NOEXCEPT {
        wilton_free(conf);
    });
    auto json = sl::json::load({const_cast<const char*>(conf), conf_len});
    return chakracore_config(json["environmentVariables"]);
}

JsRuntimeAttributes create_attributes(chakracore_config& cfg) {
    auto res = JsRuntimeAttributeNone;
    if (cfg.disable_background_work) {
        res = static_cast<JsRuntimeAttributes> (res | JsRuntimeAttributeDisableBackgroundWork);
    }
    if (cfg.disable_native_code_generation) {
        res = static_cast<JsRuntimeAttributes> (res | JsRuntimeAttributeDisableNativeCodeGeneration);
    }
    if (cfg.disable_fatal_on_oom) {
        res = static_cast<JsRuntimeAttributes> (res | JsRuntimeAttributeDisableFatalOnOOM);
    }
    return res;
}

void register_c_func(const std::string& name, JsNativeFunction cb) {
    JsValueRef global = JS_INVALID_REFERENCE;
    auto err_global = JsGetGlobalObject(std::addressof(global));
    if (JsNoError != err_global) throw support::exception(TRACEMSG(
            "'JsGetGlobalObject' error, func name: [" + name + "]," +
            " code: [" + sl::support::to_string(err_global) + "]"));

    JsPropertyIdRef prop = JS_INVALID_REFERENCE;
    auto err_prop = JsCreatePropertyId(name.c_str(), name.length(), std::addressof(prop));
    if (JsNoError != err_prop) throw support::exception(TRACEMSG(
            "'JsCreatePropertyId' error, func name: [" + name + "]," +
            " code: [" + sl::support::to_string(err_prop) + "]"));

    JsValueRef func = JS_INVALID_REFERENCE;
    auto err_create = JsCreateFunction(cb, nullptr, std::addressof(func));
    if (JsNoError != err_create) throw support::exception(TRACEMSG(
            "'JsCreateFunction' error, func name: [" + name + "]," +
            " code: [" + sl::support::to_string(err_create) + "]"));

    auto err_set = JsSetProperty(global, prop, func, true);
    if (JsNoError != err_set) throw support::exception(TRACEMSG(
            "'JsSetProperty' error, func name: [" + name + "]," +
            " code: [" + sl::support::to_string(err_create) + "]"));
}

std::string jsval_to_string(JsValueRef val) STATICLIB_NOEXCEPT {
    // convert to string
    JsValueRef val_str = JS_INVALID_REFERENCE;
    auto err_convert = JsConvertValueToString(val, std::addressof(val_str));
    if (JsNoError != err_convert) return "";

    // extract string
    size_t len = 0;
    auto err_size = JsCopyString(val_str, nullptr, 0, std::addressof(len));
    if (JsNoError != err_size) return "";
    if (0 == len) return "";
    auto res = std::string();
    res.resize(len);
    auto err_copy = JsCopyString(val_str, std::addressof(res.front()), res.length(), nullptr);
    if (JsNoError != err_copy) return "";
    return res;
}

std::string format_stack_trace(JsErrorCode err) STATICLIB_NOEXCEPT {
    auto default_msg = std::string() + "Error code: [" + sl::support::to_string(err) + "]";
    JsValueRef exc = JS_INVALID_REFERENCE;
    auto err_get = JsGetAndClearException(std::addressof(exc));
    if (JsNoError != err_get) {
        return default_msg;
    }
    JsPropertyIdRef prop = JS_INVALID_REFERENCE;
    auto name = std::string("stack");
    auto err_prop = JsCreatePropertyId(name.c_str(), name.length(), std::addressof(prop));
    if (JsNoError != err_prop) {
        return default_msg;
    }
    JsValueRef stack_ref = JS_INVALID_REFERENCE;
    auto err_stack = JsGetProperty(exc, prop, std::addressof(stack_ref));
    if (JsNoError != err_stack) {
        return default_msg;
    }
    auto stack = jsval_to_string(stack_ref);
    // filter and format
    auto vec = sl::utils::split(stack, '\n');
    auto res = std::string();
    for (size_t i = 0; i < vec.size(); i++) {
        auto& line = vec.at(i);
        if(line.length() > 1 && !(std::string::npos != line.find("(wilton-requirejs/require.js:")) &&
                !(std::string::npos != line.find("(wilton-require.js:"))) {
            if (sl::utils::starts_with(line, "   at")) {
                res.push_back(' ');
            }
            res += line;
            res.push_back('\n');
        }
    }
    if (res.length() > 0 && '\n' == res.back()) {
        res.pop_back();
    }
    return res;
}

bool is_string_ref(JsValueRef val) {
    JsValueType vt = JsUndefined;
    auto err_type = JsGetValueType(val, std::addressof(vt));
    if (JsNoError != err_type) throw support::exception(TRACEMSG(
            "'JsGetValueType' error, code: [" + sl::support::to_string(err_type) + "]"));
    return JsString == vt;
}

std::string eval_js(const char* code, size_t code_len, const std::string& path) {
    JsValueRef rcode = JS_INVALID_REFERENCE;
    auto err_rcode = JsCreateString(code, code_len, std::addressof(rcode));
    if (JsNoError != err_rcode) throw support::exception(TRACEMSG(
            "'JsCreateString' error, path: [" + path + "]," +
            " code: [" + sl::support::to_string(err_rcode) + "]"));
    JsValueRef rpath = JS_INVALID_REFERENCE;
    auto err_rpath = JsCreateString(path.c_str(), path.length(), std::addressof(rpath));
    if (JsNoError != err_rpath) throw support::exception(TRACEMSG(
            "'JsCreateString' error, path: [" + path + "]," +
            " code: [" + sl::support::to_string(err_rpath) + "]"));
    auto hasher = std::hash<std::string>();
    auto src_ctx = static_cast<JsSourceContext>(hasher(path));
    JsValueRef res = JS_INVALID_REFERENCE;
    auto err = JsRun(rcode, src_ctx, rpath, JsParseScriptAttributeNone, std::addressof(res));
    if (JsErrorInExceptionState == err) {
        throw support::exception(TRACEMSG(format_stack_trace(err)));
    }
    if (JsNoError != err) {
        throw support::exception(TRACEMSG("'JsRunScript' error, path: [" + path + "]," +
                " err: [" + sl::support::to_string(err) + "]"));
    }
    if (JS_INVALID_REFERENCE != res) {
        JsValueType vt = JsUndefined;
        auto err_type = JsGetValueType(res, std::addressof(vt));
        if (JsNoError != err_type) throw support::exception(TRACEMSG(
                "'JsGetValueType' error, path: [" + path + "]," +
                " code: [" + sl::support::to_string(err_type) + "]"));
        if (JsString == vt) {
            return jsval_to_string(res);
        }
    }
    return "";
}

JsValueRef create_error(const std::string& msg) STATICLIB_NOEXCEPT {
    JsValueRef str = JS_INVALID_REFERENCE;
    auto err_rmsg = JsCreateString(msg.c_str(), msg.length(), std::addressof(str));
    if (JsNoError != err_rmsg) {
        // fallback
        auto em = std::string("ERROR");
        JsCreateString(em.c_str(), em.length(), std::addressof(str));
    }
    JsValueRef res = JS_INVALID_REFERENCE;
    auto err_err = JsCreateError(str, std::addressof(res));
    if (JsNoError != err_err) {
        // fallback, todo: check me
        JsCreateError(JS_INVALID_REFERENCE, std::addressof(res));
    }
    return res;
}

JsValueRef CHAKRA_CALLBACK print_func(JsValueRef /* callee */, bool /* is_construct_call */,
        JsValueRef* args, unsigned short args_count, void* /* callback_state */) STATICLIB_NOEXCEPT {
    if (args_count > 1) {
        auto val = jsval_to_string(args[1]);
        puts(val.c_str());
    } else {
        puts("");
    }
    return JS_INVALID_REFERENCE;
}

JsValueRef CHAKRA_CALLBACK load_func(JsValueRef /* callee */, bool /* is_construct_call */,
        JsValueRef* args, unsigned short args_count, void* /* callback_state */) STATICLIB_NOEXCEPT {
    auto path = std::string();
    try {
        // check args
        if (args_count < 2 || !is_string_ref(args[1])) {
            throw support::exception(TRACEMSG("Invalid arguments specified"));
        }

        // load code
        path = jsval_to_string(args[1]);
        char* code = nullptr;
        int code_len = 0;
        auto err_load = wilton_load_resource(path.c_str(), static_cast<int>(path.length()),
                std::addressof(code), std::addressof(code_len));
        if (nullptr != err_load) {
            support::throw_wilton_error(err_load, TRACEMSG(err_load));
        }
        auto deferred = sl::support::defer([code] () STATICLIB_NOEXCEPT {
            wilton_free(code);
        });
        auto path_short = support::script_engine_map_detail::shorten_script_path(path);
        wilton::support::log_debug("wilton.engine.chakracore.eval",
                "Evaluating source file, path: [" + path + "] ...");
        eval_js(code, static_cast<size_t>(code_len), path_short);
        wilton::support::log_debug("wilton.engine.chakracore.eval", "Eval complete");
    } catch (const std::exception& e) {
        auto msg = TRACEMSG(e.what() + "\nError loading script, path: [" + path + "]");
        auto err = create_error(msg);
        JsSetException(err);
        return JS_INVALID_REFERENCE;
    } catch (...) {
        auto msg = TRACEMSG("Error(...) loading script, path: [" + path + "]");
        auto err = create_error(msg);
        JsSetException(err);
        return JS_INVALID_REFERENCE;
    }
    return JS_INVALID_REFERENCE;
}

JsValueRef CHAKRA_CALLBACK wiltoncall_func(JsValueRef /* callee */, bool /* is_construct_call */,
        JsValueRef* args, unsigned short args_count, void* /* callback_state */) STATICLIB_NOEXCEPT {
    if (args_count < 3 || !is_string_ref(args[1]) || !is_string_ref(args[2])) {
        auto msg = TRACEMSG("Invalid arguments specified");
        auto err = create_error(msg);
        JsSetException(err);
        return JS_INVALID_REFERENCE;
    }
    auto name = jsval_to_string(args[1]);
    auto input = jsval_to_string(args[2]);
    char* out = nullptr;
    int out_len = 0;
    wilton::support::log_debug("wilton.wiltoncall." + name,
            "Performing a call,  input length: [" + sl::support::to_string(input.length()) + "] ...");
    auto err = wiltoncall(name.c_str(), static_cast<int> (name.length()),
            input.c_str(), static_cast<int> (input.length()),
            std::addressof(out), std::addressof(out_len));
    wilton::support::log_debug("wilton.wiltoncall." + name,
            "Call complete, result: [" + (nullptr != err ? std::string(err) : "") + "]");
    if (nullptr == err) {
        if (nullptr != out) {
            JsValueRef res = JS_INVALID_REFERENCE;
            auto err_str = JsCreateString(out, out_len, std::addressof(res));
            if (JsNoError != err_str) {
                // fallback
                auto em = std::string("ERROR");
                JsCreateString(em.c_str(), em.length(), std::addressof(res));
            }
            wilton_free(out);
            return res;
        } else {
            JsValueRef null_ref = JS_INVALID_REFERENCE;
            JsGetNullValue(std::addressof(null_ref));
            return null_ref;
        }
    } else {
        auto msg = TRACEMSG(err + "\n'wiltoncall' error for name: [" + name + "]");
        wilton_free(err);
        auto err = create_error(msg);
        JsSetException(err);
        return JS_INVALID_REFERENCE;
    }
}

} // namespace

class chakracore_engine::impl : public sl::pimpl::object::impl {
    JsRuntimeHandle runtime = JS_INVALID_RUNTIME_HANDLE;

public:
    ~impl() STATICLIB_NOEXCEPT {
        JsSetCurrentContext(JS_INVALID_REFERENCE);
        JsDisableRuntimeExecution(runtime);
        JsDisposeRuntime(runtime);
    }
    
    impl(sl::io::span<const char> init_code) {
        auto cfg = get_config();
        wilton::support::log_info("wilton.engine.chakracore.init", std::string() + "Initializing engine instance," +
                " config: [" + cfg.to_json().dumps() + "]");
        auto attrs = create_attributes(cfg);
        auto err_runtime = JsCreateRuntime(attrs, nullptr, std::addressof(this->runtime));
        if (JsNoError != err_runtime) throw support::exception(TRACEMSG(
                "'JsCreateRuntime' error, code: [" + sl::support::to_string(err_runtime) + "]"));
        if (cfg.runtime_memory_limit > 0) {
            auto err_limit = JsSetRuntimeMemoryLimit(runtime, static_cast<size_t>(cfg.runtime_memory_limit));
            if (JsNoError != err_limit) throw support::exception(TRACEMSG(
                    "'JsSetRuntimeMemoryLimit' error, code: [" + sl::support::to_string(err_limit) + "]"));
        }
        JsContextRef ctx = JS_INVALID_REFERENCE;
        auto err_ctx = JsCreateContext(runtime, std::addressof(ctx));
        if (JsNoError != err_runtime) throw support::exception(TRACEMSG(
                "'JsCreateContext' error, code: [" + sl::support::to_string(err_ctx) + "]"));
        auto err_set = JsSetCurrentContext(ctx);
        if (JsNoError != err_set) throw support::exception(TRACEMSG(
                "'JsSetCurrentContext' error, code: [" + sl::support::to_string(err_set) + "]"));
        register_c_func("print", print_func);
        register_c_func("WILTON_load", load_func);
        register_c_func("WILTON_wiltoncall", wiltoncall_func);
        eval_js(init_code.data(), init_code.size(), "wilton-require.js");
        wilton::support::log_info("wilton.engine.chakracore.init", "Engine initialization complete");
    }

    support::buffer run_callback_script(chakracore_engine&, sl::io::span<const char> callback_script_json) {
        wilton::support::log_debug("wilton.engine.chakracore.run",
                "Running callback script: [" + std::string(callback_script_json.data(), callback_script_json.size()) + "] ...");
        // extract wilton_run
        JsValueRef global = JS_INVALID_REFERENCE;
        auto err_global = JsGetGlobalObject(&global);
        if (JsNoError != err_global) throw support::exception(TRACEMSG(
                "'JsGetGlobalObject' error, code: [" + sl::support::to_string(err_global) + "]"));
        JsValueRef cb_arg_ref = JS_INVALID_REFERENCE;
        auto err_arg = JsCreateString(callback_script_json.data(), callback_script_json.size(), std::addressof(cb_arg_ref));
        if (JsNoError != err_arg) throw support::exception(TRACEMSG(
                "'JsCreateString' error, code: [" + sl::support::to_string(err_arg) + "]"));
        JsPropertyIdRef fun_prop = JS_INVALID_REFERENCE;
        auto name = std::string("WILTON_run");
        auto err_prop = JsCreatePropertyId(name.c_str(), name.length(), std::addressof(fun_prop));
        if (JsNoError != err_prop) throw support::exception(TRACEMSG(
                "'JsCreatePropertyId' error, code: [" + sl::support::to_string(err_prop) + "]"));
        JsValueRef fun = JS_INVALID_REFERENCE;
        auto err_get = JsGetProperty(global, fun_prop, std::addressof(fun));
        if (JsNoError != err_get) throw support::exception(TRACEMSG(
                "'JsGetProperty' error, code: [" + sl::support::to_string(err_get) + "]"));
        JsValueType fun_type = JsUndefined;
        auto err_type = JsGetValueType(fun, std::addressof(fun_type));
        if (JsNoError != err_type) throw support::exception(TRACEMSG(
                "'JsGetValueType' error, code: [" + sl::support::to_string(err_type) + "]"));
        if (JsFunction != fun_type) throw support::exception(TRACEMSG(
                "Error accessing 'WILTON_run' function: not a function"));
        JsValueRef null_ref = JS_INVALID_REFERENCE;
        auto err_null = JsGetNullValue(std::addressof(null_ref));
        if (JsNoError != err_null) throw support::exception(TRACEMSG(
                "'JsGetNullValue' error, code: [" + sl::support::to_string(err_null) + "]"));
        // call
        auto args = std::array<JsValueRef, 2>();
        args[0] = null_ref;
        args[1] = cb_arg_ref;
        JsValueRef res = JS_INVALID_REFERENCE;
        auto err_call = JsCallFunction(fun, args.data(), static_cast<unsigned short>(args.size()), std::addressof(res));
        wilton::support::log_debug("wilton.engine.jsc.run",
                "Callback run complete, result: [" + sl::support::to_string_bool(JsNoError == err_call) + "]");
        if (JsNoError != err_call) {
            throw support::exception(TRACEMSG(format_stack_trace(err_call)));
        }
        if (is_string_ref(res)) {
            auto str = jsval_to_string(res);
            return support::make_string_buffer(str);
        }
        return support::make_null_buffer();
    }

    void run_garbage_collector(chakracore_engine&) {
        auto err = JsCollectGarbage(this->runtime);
        if (JsNoError != err) throw support::exception(TRACEMSG(
                "'JsCollectGarbage' error, code: [" + sl::support::to_string(err) + "]"));
    }
};

PIMPL_FORWARD_CONSTRUCTOR(chakracore_engine, (sl::io::span<const char>), (), support::exception)
PIMPL_FORWARD_METHOD(chakracore_engine, support::buffer, run_callback_script, (sl::io::span<const char>), (), support::exception)
PIMPL_FORWARD_METHOD(chakracore_engine, void, run_garbage_collector, (), (), support::exception)

} // namespace
}

