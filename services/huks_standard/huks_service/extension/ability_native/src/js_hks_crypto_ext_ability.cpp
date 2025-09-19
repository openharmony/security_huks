/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// #include "hks_log.h"
#include "js_hks_crypto_ext_ability.h"
#include "errors.h"
#include "hks_crypto_ext_stub_impl.h"
#include "extension_context.h"
#include "if_system_ability_manager.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"
#include "log_utils.h"

namespace OHOS {
namespace Security {
namespace Huks {
namespace {
    constexpr size_t ARGC_ZERO = 0;
    constexpr size_t ARGC_ONE = 1;
    // constexpr size_t ARGC_TWO = 2;
    // constexpr size_t ARGC_THREE = 3;
    // constexpr size_t ARGC_FOUR = 4;
    constexpr size_t MAX_ARG_COUNT = 5;
    // constexpr int EXCEPTION = -1;
    // constexpr int NOEXCEPTION = -2;
}

static int DoCallJsMethod(CallJsParam *param)
{
    if (param == nullptr || param->jsRuntime == nullptr) {
        LOGE("failed to get jsRuntime.");
        return EINVAL;
    }
    AbilityRuntime::JsRuntime *jsRuntime = param->jsRuntime;

    OHOS::AbilityRuntime::HandleEscape handleEscape(*jsRuntime);
    auto &nativeEngine = jsRuntime->GetNativeEngine();
    auto env = reinterpret_cast<napi_env>(&nativeEngine);
    size_t argc = 0;
    napi_value argv[MAX_ARG_COUNT] = { nullptr };
    if (param->argParser != nullptr) {
        if (!param->argParser(env, argv, argc)) {
            LOGE("failed to get params.");
            return EINVAL;
        }
    }

    napi_value value = nullptr;
    auto ref = reinterpret_cast<napi_ref>(param->jsObj);
    napi_get_reference_value(env, ref, &value);
    if (value == nullptr) {
        LOGE("failed to get native value object.");
        return EINVAL;
    }
    napi_value method = nullptr;
    napi_get_named_property(env, value, param->funcName.c_str(), &method);
    if (method == nullptr) {
        LOGE("failed to get %s from FileExtAbility object.", param->funcName.c_str());
        return EINVAL;
    }
    if (param->retParser == nullptr) {
        LOGE("ResultValueParser must not null.");
        return EINVAL;
    }
    napi_value result = nullptr;
    napi_call_function(env, value, method, argc, argv, &result);
    if (result == nullptr) {
        LOGE("Napi call function fail.");
        return -1;
    }
    if (!param->retParser(env, handleEscape.Escape(result))) {
        LOGE("Parser js result fail.");
        return -1;
    }
    return ERR_OK;
}

JsHksCryptoExtAbility *JsHksCryptoExtAbility::Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO JsHksCryptoExtAbility Create start");
    return new JsHksCryptoExtAbility(static_cast<AbilityRuntime::JsRuntime &>(*runtime));
}

JsHksCryptoExtAbility::JsHksCryptoExtAbility(AbilityRuntime::JsRuntime &jsRuntime) : jsRuntime_(jsRuntime) {}

JsHksCryptoExtAbility::~JsHksCryptoExtAbility()
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO ~JsHksCryptoExtAbility start");
    jsRuntime_.FreeNativeReference(std::move(jsObj_));
}

void JsHksCryptoExtAbility::Init(const std::shared_ptr<AbilityRuntime::AbilityLocalRecord> &record,
    const std::shared_ptr<AbilityRuntime::OHOSApplication> &application, std::shared_ptr<AbilityRuntime::AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO JsHksCryptoExtAbility(JS) Init");
    HksCryptoExtAbility::Init(record, application, handler, token);
    std::string srcPath = "";
    if (abilityInfo_ == nullptr) {
        LOGE("abilityInfo_ is nullptr");
        return;
    }
    GetSrcPath(srcPath);
    if (srcPath.empty()) {
        LOGE("Failed to get srcPath");
        return;
    }
    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    jsObj_ = jsRuntime_.LoadModule(moduleName, srcPath, abilityInfo_->hapPath,
        abilityInfo_->compileMode == AbilityRuntime::CompileMode::ES_MODULE);
    if (jsObj_ == nullptr) {
        LOGE("Failed to get jsObj_");
        return;
    }

    if (jsObj_->GetNapiValue() == nullptr) {
        LOGE("Failed to get JsHksCryptoExtAbility value");
        return;
    }
}

void JsHksCryptoExtAbility::OnStart(const AAFwk::Want &want)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO JsHksCryptoExtAbility(JS) OnStart");
    Extension::OnStart(want);
    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    napi_value argv[] = { napiWant };
    CallObjectMethod("onCreate", argv, ARGC_ONE);
}

sptr<IRemoteObject> JsHksCryptoExtAbility::OnConnect(const AAFwk::Want &want)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO JsHksCryptoExtAbility(JS) OnConnect");
    Extension::OnConnect(want);
    sptr<HksCryptoExtStubImpl> remoteObject(
        new (std::nothrow) HksCryptoExtStubImpl(std::static_pointer_cast<JsHksCryptoExtAbility>(shared_from_this()),
        reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine())));
    if (remoteObject == nullptr) {
        LOGE("No memory allocated for HksCryptoExtStubImpl");
        return nullptr;
    }

    return remoteObject->AsObject();
}

napi_status JsHksCryptoExtAbility::GetStringValue(napi_env env, napi_value value, std::string &result)
{
    size_t tempSize = 0;
    if (napi_get_value_string_utf8(env, value, nullptr, 0, &tempSize) != napi_ok) {
        return napi_generic_failure;
    }
    result.reserve(tempSize + 1);
    result.resize(tempSize);
    if (napi_get_value_string_utf8(env, value, result.data(), tempSize + 1, &tempSize) != napi_ok) {
        return napi_generic_failure;
    }
    return napi_ok;
}

napi_value JsHksCryptoExtAbility::CallObjectMethod(const char *name, napi_value const *argv, size_t argc)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO JsHksCryptoExtAbility(JS) CallObjectMethod");
    if (!jsObj_) {
        LOGE("JsHksCryptoExtAbility::CallObjectMethod jsObj Not found FileAccessExtAbility.js");
        return nullptr;
    }

    OHOS::AbilityRuntime::HandleEscape handleEscape(jsRuntime_);
    auto &nativeEngine = jsRuntime_.GetNativeEngine();
    auto env = reinterpret_cast<napi_env>(&nativeEngine);

    napi_value value = jsObj_->GetNapiValue();
    if (value == nullptr) {
        LOGE("Failed to get HksCryptoExtAbility value");
        return nullptr;
    }

    napi_value method = nullptr;
    napi_get_named_property(env, value, name, &method);
    if (method == nullptr) {
        LOGE("Failed to get '%s' from HksCryptoExtAbility object", name);
        return nullptr;
    }

    napi_value result = nullptr;
    if (napi_call_function(env, value, method, argc, argv, &result) != napi_ok) {
        LOGE("Call function fail");
        return nullptr;
    }
    return handleEscape.Escape(result);
}

int JsHksCryptoExtAbility::CallJsMethod(const std::string &funcName, AbilityRuntime::JsRuntime &jsRuntime, NativeReference *jsObj,
    InputArgsParser argParser, ResultValueParser retParser)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO JsHksCryptoExtAbility(JS) CallJsMethod");
    uv_loop_s *loop = nullptr;
    napi_status status = napi_get_uv_event_loop(reinterpret_cast<napi_env>(&jsRuntime.GetNativeEngine()), &loop);
    if (status != napi_ok) {
        LOGE("failed to get uv event loop.");
        return EINVAL;
    }
    auto param = std::make_shared<CallJsParam>(funcName, &jsRuntime, jsObj, argParser, retParser);
    if (param == nullptr) {
        LOGE("failed to new param.");
        return EINVAL;
    }

    auto task = [param {param.get()}]() {
        if (param == nullptr || param->jsRuntime == nullptr) {
            LOGE("failed to get CallJsParam.");
            return;
        }

        napi_handle_scope scope = nullptr;
        napi_env env = reinterpret_cast<napi_env>(&(param->jsRuntime->GetNativeEngine()));
        napi_open_handle_scope(env, &scope);

        if (DoCallJsMethod(param) != ERR_OK) {
            LOGE("failed to call DoCallJsMethod.");
        }

        std::unique_lock<std::mutex> lock(param->CryptoOperateMutex);
        param->isReady = true;
        param->CryptoOperateCondition.notify_one();
        napi_close_handle_scope(env, scope);
    };
    auto ret = napi_send_event(jsRuntime.GetNapiEnv(), task, napi_eprio_high);
    if (ret != napi_ok) {
        LOGE("failed to napi_send_event, ret:%d.", ret);
        return EINVAL;
    }
    std::unique_lock<std::mutex> lock(param->CryptoOperateMutex);
    param->CryptoOperateCondition.wait(lock, [param]() { return param->isReady; });
    return ERR_OK;
}


void JsHksCryptoExtAbility::GetSrcPath(std::string &srcPath)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO JsHksCryptoExtAbility(JS) GetSrcPath");
    srcPath.append(Extension::abilityInfo_->moduleName + "/");
    srcPath.append(Extension::abilityInfo_->srcEntrance);
    srcPath.erase(srcPath.rfind('.'));
    srcPath.append(".abc");
}

bool JsHksCryptoExtAbility::ParserVectorStringJsResult(napi_env &env, napi_value nativeValue,
    Value<std::vector<std::string>> &results)
{
    napi_value code = nullptr;
    napi_get_named_property(env, nativeValue, "code", &code);
    if (napi_get_value_int32(env, code, &results.code) != napi_ok) {
        LOGE("Convert js value code fail.");
        return napi_generic_failure;
    }
    napi_value nativeArray = nullptr;
    napi_create_array(env, &nativeArray);
    napi_get_named_property(env, nativeValue, "testOut", &nativeArray);
    if (nativeArray == nullptr) {
        LOGE("Convert js array object fail.");
        return false;
    }

    uint32_t length = 0;
    if (napi_get_array_length(env, nativeArray, &length) != napi_ok) {
        LOGE("Get nativeArray length fail.");
        return false;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value queryResult = nullptr;
        napi_get_element(env, nativeArray, i, &queryResult);
        if (queryResult == nullptr) {
            LOGE("Get native queryResult fail.");
            return false;
        }

        std::string tempValue;
        if (GetStringValue(env, queryResult, tempValue) != napi_ok) {
            LOGE("Convert js value fail.");
            return false;
        }
        results.data.emplace_back(std::move(tempValue));
    }
    return true;
}

int JsHksCryptoExtAbility::test(const std::string &testIn, std::vector<std::string> &testOut)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO JsHksCryptoExtAbility(JS) test");
    auto value = std::make_shared<Value<std::vector<std::string>>>();
    if (value == nullptr) {
        LOGE("Query value is nullptr.");
        return -1;
    }

    auto argParser = [testIn](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        napi_value nativeTestIn = nullptr;
        napi_create_string_utf8(env, testIn.c_str(), testIn.length(), &nativeTestIn);
        argv[ARGC_ZERO] = nativeTestIn;
        argc = ARGC_ONE;
        return true;
    };

    auto retParser = [value, this](napi_env &env, napi_value result) -> bool {
        Value<std::vector<std::string>> queryResult;
        bool ret = ParserVectorStringJsResult(env, result, queryResult);
        if (!ret) {
            LOGE("Parser js value fail.");
            return ret;
        }
        value->code = queryResult.code;
        value->data = queryResult.data;
        return ret;
    };

    auto errCode = CallJsMethod("test", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (errCode != ERR_OK) {
        LOGE("CallJsMethod error, code:%d.", errCode);
        return errCode;
    }

    if (value->code != ERR_OK) {
        LOGE("fileio fail.");
        return value->code;
    }

    testOut = std::move(value->data);
    return ERR_OK;
}

int32_t JsHksCryptoExtAbility::OnCreateRemoteIndex(const std::string &abilityName, std::string &index)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO JsHksCryptoExtAbility(JS) OnCreateRemoteIndex");

    auto value = std::make_shared<Value<std::string>>();
        if (value == nullptr) {
        LOGE("Query value is nullptr.");
        return -1;
    }

    auto argParser = [abilityName](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        napi_value nativeAbilityName = nullptr;
        napi_create_string_utf8(env, abilityName.c_str(), abilityName.length(), &nativeAbilityName);
        argv[ARGC_ZERO] = nativeAbilityName;
        argc = ARGC_ONE;
        return true;
    };

    auto retParser = [value, this](napi_env &env, napi_value result) -> bool {
        napi_value code = nullptr;
        napi_get_named_property(env, result, "code", &code);
        if (napi_get_value_int32(env, code, &value->code) != napi_ok) {
            HILOG_ERROR("Convert js value code fail.");
            return napi_generic_failure;
        }
        napi_value index = nullptr;
        napi_get_named_property(env, result, "index", &index);
        if (GetStringValue(env, index, value->data) != napi_ok) {
            HILOG_ERROR("Convert js value fail.");
            return napi_generic_failure;
        }
        return true;
    };
    auto errCode = CallJsMethod("OnCreateRemoteIndex", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (errCode != ERR_OK) {
        LOGE("CallJsMethod error, code:%d.", errCode);
        return errCode;
    }

    if (value->code != ERR_OK) {
        LOGE("OnCreateRemoteIndex fail.");
        return value->code;
    }

    index = std::move(value->data);
    return ERR_OK;
}

int JsHksCryptoExtAbility::OnGetRemoteHandle(const std::string& index, std::string& handle)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO JsHksCryptoExtAbility(JS) OnGetRemoteHandle");

    auto value = std::make_shared<Value<std::string>>();
        if (value == nullptr) {
        LOGE("Query value is nullptr.");
        return -1;
    }

    auto argParser = [index](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        napi_value nativeIndex = nullptr;
        napi_create_string_utf8(env, index.c_str(), index.length(), &nativeIndex);
        argv[ARGC_ZERO] = nativeIndex;
        argc = ARGC_ONE;
        return true;
    };

    auto retParser = [value, this](napi_env &env, napi_value result) -> bool {
        napi_value code = nullptr;
        napi_get_named_property(env, result, "code", &code);
        if (napi_get_value_int32(env, code, &value->code) != napi_ok) {
            HILOG_ERROR("Convert js value code fail.");
            return napi_generic_failure;
        }
        napi_value index = nullptr;
        napi_get_named_property(env, result, "handle", &index);
        if (GetStringValue(env, index, value->data) != napi_ok) {
            HILOG_ERROR("Convert js value fail.");
            return napi_generic_failure;
        }
        return true;
    };
    auto errCode = CallJsMethod("OnGetRemoteHandle", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (errCode != ERR_OK) {
        LOGE("CallJsMethod error, code:%d.", errCode);
        return errCode;
    }

    if (value->code != ERR_OK) {
        LOGE("OnGetRemoteHandle fail.");
        return value->code;
    }

    handle = std::move(value->data);
    return ERR_OK;
}

int JsHksCryptoExtAbility::OnOpenRemoteHandle(const std::string& handle)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO JsHksCryptoExtAbility(JS) OnOpenRemoteHandle");

    auto argParser = [handle](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        napi_value nativeHandle = nullptr;
        napi_create_string_utf8(env, handle.c_str(), handle.length(), &nativeHandle);
        argv[ARGC_ZERO] = nativeHandle;
        argc = ARGC_ONE;
        return true;
    };
    auto resultCode = std::make_shared<int>();
    auto retParser = [resultCode, this](napi_env &env, napi_value result) -> bool {
        napi_value code = nullptr;
        napi_get_named_property(env, result, "code", &code);
        if (napi_get_value_int32(env, code, resultCode.get()) != napi_ok) {
            HILOG_ERROR("Convert js value resultCode fail.");
            return napi_generic_failure;
        }
        return true;
    };
    auto errCode = CallJsMethod("OnOpenRemoteHandle", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (errCode != ERR_OK) {
        LOGE("CallJsMethod error, code:%d.", errCode);
        return errCode;
    }

    if (*resultCode != ERR_OK) {
        LOGE("OnOpenRemoteHandle fail.");
        return *resultCode;
    }

    return ERR_OK;
}

int JsHksCryptoExtAbility::OnCloseRemoteHandle(const std::string& index)
{
    LOGE("wqy!!!!!!!!!!!!!!!!!!!!!!!!!TODO JsHksCryptoExtAbility(JS) OnCloseRemoteHandle");

    auto argParser = [index](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        napi_value nativeIndex = nullptr;
        napi_create_string_utf8(env, index.c_str(), index.length(), &nativeIndex);
        argv[ARGC_ZERO] = nativeIndex;
        argc = ARGC_ONE;
        return true;
    };
    auto resultCode = std::make_shared<int>();
    auto retParser = [resultCode, this](napi_env &env, napi_value result) -> bool {
        napi_value code = nullptr;
        napi_get_named_property(env, result, "code", &code);
        if (napi_get_value_int32(env, code, resultCode.get()) != napi_ok) {
            HILOG_ERROR("Convert js value resultCode fail.");
            return napi_generic_failure;
        }
        return true;
    };
    auto errCode = CallJsMethod("OnCloseRemoteHandle", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (errCode != ERR_OK) {
        LOGE("CallJsMethod error, code:%d.", errCode);
        return errCode;
    }

    if (*resultCode != ERR_OK) {
        LOGE("OnCloseRemoteHandle fail.");
        return *resultCode;
    }

    return ERR_OK;
}

} // names
} // namespace Security
} // namespace OHOS