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
#include "hks_cpp_paramset.h"
#include "hks_crypto_ext_stub_impl.h"
#include "extension_context.h"
#include "if_system_ability_manager.h"
#include "js_native_api.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"
#include "log_utils.h"
#include "huks_napi_common_item.h"

namespace OHOS {
namespace Security {
namespace Huks {
namespace {
    constexpr size_t ARGC_ZERO = 0;
    constexpr size_t ARGC_ONE = 1;
    constexpr size_t ARGC_TWO = 2;
    // constexpr size_t ARGC_THREE = 3;
    // constexpr size_t ARGC_FOUR = 4;
    constexpr size_t MAX_ARG_COUNT = 5;
    // constexpr int EXCEPTION = -1;
    // constexpr int NOEXCEPTION = -2;
}

struct HandleInfoParam {
    std::string handle {};
    CppParamSet params {};
};

struct IndexInfoParam {
    std::string index {};
    CppParamSet params {};
};

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

    auto errcode = CallJsMethod("test", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (errcode != ERR_OK) {
        LOGE("CallJsMethod error, code:%d.", errcode);
        return errcode;
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
            LOGE("Convert js value code fail.");
            return napi_generic_failure;
        }
        napi_value index = nullptr;
        napi_get_named_property(env, result, "index", &index);
        if (GetStringValue(env, index, value->data) != napi_ok) {
            LOGE("Convert js value fail.");
            return napi_generic_failure;
        }
        return true;
    };
    auto errcode = CallJsMethod("OnCreateRemoteIndex", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (errcode != ERR_OK) {
        LOGE("CallJsMethod error, code:%d.", errcode);
        return errcode;
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
            LOGE("Convert js value code fail.");
            return napi_generic_failure;
        }
        napi_value index = nullptr;
        napi_get_named_property(env, result, "handle", &index);
        if (GetStringValue(env, index, value->data) != napi_ok) {
            LOGE("Convert js value fail.");
            return napi_generic_failure;
        }
        return true;
    };
    auto errcode = CallJsMethod("OnGetRemoteHandle", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (errcode != ERR_OK) {
        LOGE("CallJsMethod error, code:%d.", errcode);
        return errcode;
    }

    if (value->code != ERR_OK) {
        LOGE("OnGetRemoteHandle fail.");
        return value->code;
    }

    handle = std::move(value->data);
    return ERR_OK;
}

bool MakeJsNativeCppParamSet(napi_env &env, const CppParamSet &CppParamSet, napi_value nativeCppParamSet)
{
    napi_value napiHksParam = HuksNapiItem::GenerateHksParamArray(env, *CppParamSet.GetParamSet());
    if (napi_set_named_property(env, nativeCppParamSet, "properties", napiHksParam) != napi_ok) {
        LOGE("Set property to nativeCppParamSet failed");
        return false;
    }
    return true;
}

static bool BuildHandleInfoParam(napi_env &env, HandleInfoParam &param,
    napi_value *argv, size_t &argc)
{
    napi_value nativeHandle = nullptr;
    napi_create_string_utf8(env, param.handle.c_str(), param.handle.length(), &nativeHandle);

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()){
        napi_create_object(env, &nativeCppParamSet);
        if (nativeCppParamSet == nullptr) {
            LOGE("Create js NativeValue object failed");
            return false;
        }
        if (MakeJsNativeCppParamSet(env, param.params, nativeCppParamSet) != true) {
            LOGE("Make js CppParamSet failed");
            return false;
        }
    }
    argv[ARGC_ZERO] = nativeHandle;
    argv[ARGC_ONE] = nativeCppParamSet;
    argc = ARGC_TWO;
    return true;
}

static bool BuildIndexInfoParam(napi_env &env, IndexInfoParam &param,
    napi_value *argv, size_t &argc)
{
    napi_value nativeIndex = nullptr;
    napi_create_string_utf8(env, param.index.c_str(), param.index.length(), &nativeIndex);

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()){
        napi_create_object(env, &nativeCppParamSet);
        if (nativeCppParamSet == nullptr) {
            LOGE("Create js NativeValue object failed");
            return false;
        }
        if (MakeJsNativeCppParamSet(env, param.params, nativeCppParamSet) != true) {
            LOGE("Make js CppParamSet failed");
            return false;
        }
    }
    argv[ARGC_ZERO] = nativeIndex;
    argv[ARGC_ONE] = nativeCppParamSet;
    argc = ARGC_TWO;
    return true;
}

void JsHksCryptoExtAbility::GetOpenRemoteHandleParams(napi_env env, napi_value funcResult, CryptoResultParam &resultParams)
{
    napi_value napiHandle = nullptr;
    napi_get_named_property(env, funcResult, "handle", &napiHandle);
    if (GetStringValue(env, napiHandle, resultParams.handle) != napi_ok) {
        LOGE("Convert js napiHandle fail.");
    }
    LOGE("wqy !!!!!!!!!!!!!!!!!!!!!! ConvertFunctionResult %s", resultParams.handle.c_str());
}

void JsHksCryptoExtAbility::GetAuthUkeyPin(napi_env env, napi_value funcResult, CryptoResultParam &resultParams)
{
    napi_value napiAuthState = nullptr;
    napi_get_named_property(env, funcResult, "authState", &napiAuthState);
    if (napi_get_value_int32(env, napiAuthState, &resultParams.authState) != napi_ok) {
        LOGE("Convert js value authState failed.");
    }

    napi_value napiRetryCnt = nullptr;
    napi_get_named_property(env, funcResult, "retryCnt", &napiRetryCnt);
    if (napi_get_value_uint32(env, napiRetryCnt, &resultParams.retryCnt) != napi_ok) {
        LOGE("Convert js value retryCnt failed.");
    }
    LOGE("wqy !!!!!!!!!!!!!!!!!!!!!! ConvertFunctionResult %s", resultParams.handle.c_str());
}

bool JsHksCryptoExtAbility::ConvertFunctionResult(napi_env env, napi_value funcResult, CryptoResultParam &resultParams)
{
    if (funcResult == nullptr) {
        LOGE("The funcResult is error.");
        return false;
    }
 
    napi_value napiCode = nullptr;
    napi_get_named_property(env, funcResult, "errCode", &napiCode);
    if (napi_get_value_int32(env, napiCode, &resultParams.errCode) != napi_ok) {
        LOGE("Convert js value napiCode failed.");
        return false;
    }

    switch (resultParams.paramType) {
        case CryptoResultParamType::OPEN_REMOTE_HANDLE:
            GetOpenRemoteHandleParams(env, funcResult, resultParams);
            break;
        case CryptoResultParamType::AUTH_UKEY_PIN:
            GetAuthUkeyPin(env, funcResult, resultParams);
            break;
        case CryptoResultParamType::CLOSE_REMOTE_HANDLE:
        default:
            break;
    }

    LOGE("wqy !!!!!!!!!!!!!!!!!!!!!! ConvertFunctionResult %d", resultParams.errCode);
    return true;
}

napi_value JsHksCryptoExtAbility::PromiseCallback(napi_env env, napi_callback_info info)
{
    LOGE("enter");
    if (info == nullptr) {
        LOGE("PromiseCallback, invalid input info");
        return nullptr;
    }
 
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    void *data = nullptr;
 
    napi_get_cb_info(env, info, &argc, &argv[ARGC_ZERO], nullptr, &data);
    if (data == nullptr) {
        LOGE("PromiseCallback, invalid data");
        return nullptr;
    }
    auto *callbackInfo = static_cast<PromiseCallbackInfo *>(data);
    if (callbackInfo == nullptr) {
        LOGE("PromiseCallback, invalid callbackInfo");
        return nullptr;
    }
    auto dataParam = callbackInfo->GetJsCallBackParam();
    ConvertFunctionResult(env, argv[ARGC_ZERO], *dataParam);

    LOGE("wqy !!!!!!!!!!!!!!!!! PromiseCallbackInfo Destroy");
    PromiseCallbackInfo::Destroy(callbackInfo);
    dataParam->callJsCon.notify_one();
    dataParam->callJsExMethodDone.store(true);
    callbackInfo = nullptr;
    return nullptr;
}
 
void JsHksCryptoExtAbility::CallPromise(napi_env &env, napi_value funcResult, std::shared_ptr<CryptoResultParam> dataParam)
{
    LOGE("call");
    napi_value promiseThen = nullptr;
    napi_get_named_property(env, funcResult, "then", &promiseThen);
 
    bool isCallable = false;
    napi_is_callable(env, promiseThen, &isCallable);
    if (!isCallable) {
        LOGE("property then is not callable.");
        return;
    }
 
    napi_value promiseCallback = nullptr;
    auto *callbackInfo = PromiseCallbackInfo::Create(dataParam);
    if (callbackInfo == nullptr) {
        LOGE("Failed to new promise callbackInfo.");
        return;
    }
    napi_create_function(env, "promiseCallback", strlen("promiseCallback"), PromiseCallback,
        callbackInfo, &promiseCallback);
 
    napi_status status;
    napi_value argvPromise[1] = { promiseCallback };
 
    status = napi_call_function(env, funcResult, promiseThen, ARGS_ONE, argvPromise, nullptr);
    if (status != napi_ok) {
        LOGE("Invoke pushCheck promise then error.");
        PromiseCallbackInfo::Destroy(callbackInfo);
        return;
    }
}

int JsHksCryptoExtAbility::OpenRemoteHandle(const std::string& index, const CppParamSet& params, std::string& handle,
    int32_t& errcode)
{
    LOGE("wqy !!!!!!!!!!!!!!!!!!JsHksCryptoExtAbility(JS) OpenRemoteHandle");
    auto argParser = [index, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct IndexInfoParam param = {
            index,
            params,
        };
        return BuildIndexInfoParam(env, param, argv, argc);
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::OPEN_REMOTE_HANDLE;
    auto retParser = [&handle, &errcode, dataParam, this](napi_env &env, napi_value result) -> bool {
        bool isPromise = false;
        LOGE("check promise");
        napi_is_promise(env, result, &isPromise);
        if (!isPromise) {
            LOGE("retParser is not promise");
            return false;
        }
        LOGE("call Promise");
        CallPromise(env, result, dataParam);
        return true;
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onOpenRemoteHandle", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    std::unique_lock<std::mutex> lock(dataParam->callJsMutex);
    LOGE("wait start");
    dataParam->callJsCon.wait(lock, [this, dataParam] { return dataParam->callJsExMethodDone.load(); });
    LOGE("wait end");
    handle = std::move(dataParam->handle);
    errcode = std::move(dataParam->errCode);
    return ERR_OK;
}

int JsHksCryptoExtAbility::CloseRemoteHandle(const std::string& handle, const CppParamSet& params, int32_t& errcode)
{
    LOGE("wqy !!!!!!!!!!!!!!!!!!JsHksCryptoExtAbility(JS) CloseRemoteHandle");
    auto argParser = [handle, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct HandleInfoParam param = {
            handle,
            params,
        };
        return BuildHandleInfoParam(env, param, argv, argc);
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::CLOSE_REMOTE_HANDLE;
    auto retParser = [dataParam, this](napi_env &env, napi_value result) -> bool {
        bool isPromise = false;
        LOGE("check promise");
        napi_is_promise(env, result, &isPromise);
        if (!isPromise) {
            LOGE("retParser is not promise");
            return false;
        }
        LOGE("call Promise");
        CallPromise(env, result, dataParam);
        return true;
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onCloseRemoteHandle", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    std::unique_lock<std::mutex> lock(dataParam->callJsMutex);
    LOGE("wait start");
    dataParam->callJsCon.wait(lock, [this, dataParam] { return dataParam->callJsExMethodDone.load(); });
    LOGE("wait end");
    errcode = std::move(dataParam->errCode);
    return ERR_OK;
}

int JsHksCryptoExtAbility::AuthUkeyPin(const std::string& handle, const CppParamSet& params, int32_t& errcode,
    int32_t& authState, uint32_t& retryCnt)
{
    LOGE("wqy !!!!!!!!!!!!!!!!!!JsHksCryptoExtAbility(JS) AuthUkeyPin");
    auto argParser = [handle, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct HandleInfoParam param = {
            handle,
            params,
        };
        return BuildHandleInfoParam(env, param, argv, argc);
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::AUTH_UKEY_PIN;
    auto retParser = [dataParam, this](napi_env &env, napi_value result) -> bool {
        bool isPromise = false;
        LOGE("check promise");
        napi_is_promise(env, result, &isPromise);
        if (!isPromise) {
            LOGE("retParser is not promise");
            return false;
        }
        LOGE("call Promise");
        CallPromise(env, result, dataParam);
        return true;
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onAuthUkeyPin", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    std::unique_lock<std::mutex> lock(dataParam->callJsMutex);
    LOGE("wait start");
    dataParam->callJsCon.wait(lock, [this, dataParam] { return dataParam->callJsExMethodDone.load(); });
    LOGE("wait end");
    errcode = std::move(dataParam->errCode);
    authState = std::move(dataParam->authState);
    retryCnt = std::move(dataParam->retryCnt);
    return ERR_OK;
}

PromiseCallbackInfo::PromiseCallbackInfo(std::shared_ptr<CryptoResultParam> cryptoResultParam)
    : cryptoResultParam_(cryptoResultParam)
{}
 
PromiseCallbackInfo::~PromiseCallbackInfo() = default;
 
PromiseCallbackInfo* PromiseCallbackInfo::Create(std::shared_ptr<CryptoResultParam> cryptoResultParam)
{
    return new (std::nothrow) PromiseCallbackInfo(cryptoResultParam);
}
 
void PromiseCallbackInfo::Destroy(PromiseCallbackInfo *callbackInfo)
{
    delete callbackInfo;
}
 
std::shared_ptr<CryptoResultParam> PromiseCallbackInfo::GetJsCallBackParam()
{
    return cryptoResultParam_;
}
} // names
} // namespace Security
} // namespace OHOS