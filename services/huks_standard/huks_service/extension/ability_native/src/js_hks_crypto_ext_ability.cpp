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

#include "js_hks_crypto_ext_ability.h"
#include "environment_callback.h"
#include "errors.h"
#include "hks_cpp_paramset.h"
#include "hks_crypto_ext_stub_impl.h"
#include "extension_context.h"
#include "hks_error_code.h"
#include "if_system_ability_manager.h"
#include "image_type.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"
#include "log_utils.h"
#include "hks_json_wrapper.h"
#include <vector>
#include "hks_template.h"

#define WAIT_FOR_CALL_JS_METHOD(dataParam, waitTime) do { \
    const auto maxWaitTime = std::chrono::seconds((waitTime)); \
    std::unique_lock<std::mutex> lock((dataParam)->callJsMutex); \
    if (!(dataParam)->callJsExMethodDone.load()) { \
        (dataParam)->callJsCon.wait_for( \
            lock, maxWaitTime, [dataParam] { return (dataParam)->callJsExMethodDone.load(); }); \
    } \
    errcode = std::move((dataParam)->errCode); \
} while (0) \

namespace OHOS {
namespace Security {
namespace Huks {
namespace {
constexpr size_t ARGC_ZERO = 0;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr size_t ARGC_THREE = 3;
constexpr size_t MAX_ARG_COUNT = 5;
constexpr size_t MAX_CERT_SIZE = 5 * 8196;
constexpr int32_t MAX_WAIT_TIME = 3;

struct HandleInfoParam {
    std::string handle {};
    CppParamSet params {};
};

struct IndexInfoParam {
    std::string index {};
    CppParamSet params {};
};

int32_t BlobToBase64String(const HksBlob &strBlob, std::string &outStr)
{
    if (strBlob.size == 0 || strBlob.data == nullptr) {
        LOGE("strBlob is nullptr");
        return HKS_ERROR_EXT_BASE64_FAILED;
    }
    std::vector<uint8_t> strVector(strBlob.data, strBlob.data + strBlob.size);
    auto base64Str = U8Vec2Base64Str(strVector);
    if (base64Str.first != HKS_SUCCESS) {
        LOGE("U8Vec2Base64Str failed. ret = %d", base64Str.first);
        return HKS_ERROR_EXT_BASE64_FAILED;
    }
    outStr = std::move(base64Str.second);
    return HKS_SUCCESS;
}

napi_value GenerateArrayBuffer(const napi_env &env, uint8_t *data, uint32_t size)
{
    if (data == nullptr) {
        LOGE("Invalid input: data is null but size is %u", size);
        return nullptr;
    }

    napi_value buffer;
    void *bufferPtr = nullptr;
    auto status = napi_create_arraybuffer(env, size * sizeof(uint8_t), &bufferPtr, &buffer);
    if (status != napi_ok) {
        LOGE("napi_create_arraybuffer failed, status:%d", status);
        return nullptr;
    }
    napi_value outBuffer;
    status = napi_create_typedarray(env, napi_uint8_array, size, buffer, 0, &outBuffer);
    if (status != napi_ok) {
        LOGE("napi_create_typedarray failed, status:%d", status);
        return nullptr;
    }
    uint8_t *outPut_bytes = (uint8_t *)bufferPtr;
    for (uint32_t i = 0; i < size; ++i) {
        outPut_bytes[i] = data[i];
    }
    return outBuffer;
}

int32_t GenerateHksParamValue(const napi_env &env, const HksParam &param, napi_value &value)
{
    napi_status status = napi_ok;
    switch (param.tag & HKS_TAG_TYPE_MASK) {
        case HKS_TAG_TYPE_INT:
            status = napi_create_int32(env, param.int32Param, &value);
            break;
        case HKS_TAG_TYPE_UINT:
            status = napi_create_uint32(env, param.uint32Param, &value);
            break;
        case HKS_TAG_TYPE_ULONG:
            status = napi_create_bigint_uint64(env, param.uint64Param, &value);
            break;
        case HKS_TAG_TYPE_BOOL:
            status = napi_get_boolean(env, param.boolParam, &value);
            break;
        case HKS_TAG_TYPE_BYTES:
            value = GenerateArrayBuffer(env, param.blob.data, param.blob.size);
            break;
        default:
            LOGE("hks tag Undefined");
            return HKS_ERROR_EXT_TAG_UNDEFINED;
    }
    if (status != napi_ok || value == nullptr) {
        LOGE("napi Create value failed %d", status);
        return HKS_ERROR_EXT_CREATE_VALUE_FAILED;
    }
    return HKS_SUCCESS;
}

static int32_t GenerateHksParam(const napi_env &env, const HksParam &param, napi_value &element)
{
    napi_value hksParam = nullptr;
    auto status = napi_create_object(env, &hksParam);
    if (status != napi_ok) {
        LOGE("napi create object failed, status:%d", status);
        return HKS_ERROR_EXT_CREATE_VALUE_FAILED;
    }

    napi_value tag = nullptr;
    status = napi_create_uint32(env, param.tag, &tag);
    if (status != napi_ok) {
        LOGE("napi create uint32t failed, status:%d", status);
        return HKS_ERROR_EXT_CREATE_VALUE_FAILED;
    }
    
    status = napi_set_named_property(env, hksParam, "tag", tag);
    if (status != napi_ok) {
        LOGE("napi set name failed, status:%d", status);
        return HKS_ERROR_EXT_SET_NAME_PROPERTY_FAILED;
    }
    napi_value value = nullptr;
    int32_t result = GenerateHksParamValue(env, param, value);
    if (result != HKS_SUCCESS) {
        LOGE("GenerateHksParamValue failed");
        return result;
    }
    status = napi_set_named_property(env, hksParam, "value", value);
    if (status != napi_ok) {
        LOGE("napi set name property failed, status:%d", status);
        return HKS_ERROR_EXT_SET_NAME_PROPERTY_FAILED;
    }
    element = std::move(hksParam);
    return HKS_SUCCESS;
}

napi_value GenerateHksParamArray(const napi_env env, const HksParamSet &paramSet)
{
    napi_value paramArray = nullptr;
    auto status = napi_create_array(env, &paramArray);
    if (status != napi_ok) {
        LOGE("create array failed, status:%d", status);
        return nullptr;
    }

    for (uint32_t i = 0; i < paramSet.paramsCnt; i++) {
        napi_value element = nullptr;
        auto ret = GenerateHksParam(env, paramSet.params[i], element);
        if (ret != HKS_SUCCESS) {
            LOGE("GenerateHksParam failed");
            return nullptr;
        }
        status = napi_set_element(env, paramArray, i, element);
        if (status != napi_ok) {
            LOGE("napi set element failed, status:%d", status);
            return nullptr;
        }
    }

    return paramArray;
}

bool MakeJsNativeCppParamSet(const napi_env &env, const CppParamSet &CppParamSet, napi_value nativeCppParamSet)
{
    napi_value napiHksParam = GenerateHksParamArray(env, *CppParamSet.GetParamSet());
    if (napiHksParam == nullptr) {
        return false;
    }
    auto status = napi_set_named_property(env, nativeCppParamSet, "properties", napiHksParam);
    if (status != napi_ok) {
        LOGE("Set property to nativeCppParamSet failed, status:%d", status);
        return false;
    }
    return true;
}

bool MakeJsNativeVectorInData(const napi_env &env, const std::vector<uint8_t> &inData, napi_value &nativeIndata)
{
    size_t length = inData.size();

    napi_value inDataBuffer;
    void *inDataPtr = nullptr;
    auto status = napi_create_arraybuffer(env, length, &inDataPtr, &inDataBuffer);
    if (status != napi_ok) {
        LOGE("create arraybuffer failed, status:%d", status);
        return false;
    }
    status = napi_create_typedarray(env, napi_uint8_array, length, inDataBuffer, 0, &nativeIndata);
    if (status != napi_ok) {
        LOGE("create typedarray failed, status:%d", status);
        return false;
    }

    uint8_t *inData_bytes = (uint8_t *)inDataPtr;
    for (size_t i = 0; i < length; ++i) {
        inData_bytes[i] = inData[i];
    }

    return true;
}

bool BuildHandleInfoParam(const napi_env &env, const HandleInfoParam &param, napi_value *argv, size_t &argc)
{
    napi_value nativeHandle = nullptr;
    auto status = napi_create_string_utf8(env, param.handle.c_str(), param.handle.length(), &nativeHandle);
    if (status != napi_ok) {
        LOGE("create string utf8 failed, status:%d", status);
        return false;
    };

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()) {
        status = napi_create_object(env, &nativeCppParamSet);
        if (nativeCppParamSet == nullptr) {
            LOGE("Create js NativeValue object failed, status:%d", status);
            return false;
        }
        nativeCppParamSet = GenerateHksParamArray(env, *param.params.GetParamSet());
        if (nativeCppParamSet == nullptr) {
            return false;
        }
    }
    argv[ARGC_ZERO] = nativeHandle;
    argv[ARGC_ONE] = nativeCppParamSet;
    argc = ARGC_TWO;
    return true;
}

bool BuildIndexInfoParam(const napi_env &env, const IndexInfoParam &param, napi_value *argv, size_t &argc)
{
    napi_value nativeIndex = nullptr;
    auto status = napi_create_string_utf8(env, param.index.c_str(), param.index.length(), &nativeIndex);
    if (status != napi_ok) {
        LOGE("create string utf8 failed, status:%d", status);
        return false;
    };

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()) {
        status = napi_create_object(env, &nativeCppParamSet);
        if (nativeCppParamSet == nullptr) {
            LOGE("Create js NativeValue object failed, status:%d", status);
            return false;
        }
        nativeCppParamSet = GenerateHksParamArray(env, *param.params.GetParamSet());
        if (nativeCppParamSet == nullptr) {
            return false;
        }
    }
    argv[ARGC_ZERO] = nativeIndex;
    argv[ARGC_ONE] = nativeCppParamSet;
    argc = ARGC_TWO;
    return true;
}

bool BuildIndexInfoParamWithHuksOption(const napi_env &env, const IndexInfoParam &param, napi_value *argv, size_t &argc)
{
    napi_value nativeIndex = nullptr;
    auto status = napi_create_string_utf8(env, param.index.c_str(), param.index.length(), &nativeIndex);
    if (status != napi_ok) {
        LOGE("create string utf8 failed, status:%d", status);
        return false;
    };

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()) {
        status = napi_create_object(env, &nativeCppParamSet);
        if (nativeCppParamSet == nullptr) {
            LOGE("Create js NativeValue object failed, status:%d", status);
            return false;
        }
        if (!MakeJsNativeCppParamSet(env, param.params, nativeCppParamSet)) {
            LOGE("Make js CppParamSet failed");
            return false;
        }
    }
    argv[ARGC_ZERO] = nativeIndex;
    argv[ARGC_ONE] = nativeCppParamSet;
    argc = ARGC_TWO;
    return true;
}

bool BuildHandleWithInData(const napi_env &env, const HandleInfoParam &param, const std::vector<uint8_t> &inData,
    napi_value *argv, size_t &argc)
{
    napi_value nativeHandle = nullptr;
    auto status = napi_create_string_utf8(env, param.handle.c_str(), param.handle.length(), &nativeHandle);
    if (status != napi_ok) {
        LOGE("create string utf8 failed, status:%d", status);
        return false;
    };

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()) {
        status = napi_create_object(env, &nativeCppParamSet);
        if (nativeCppParamSet == nullptr) {
            LOGE("Create js NativeValue object failed, status:%d", status);
            return false;
        }
        if (!MakeJsNativeCppParamSet(env, param.params, nativeCppParamSet)) {
            LOGE("Make js CppParamSet failed");
            return false;
        }
    }

    napi_value nativeInData = nullptr;
    if (!MakeJsNativeVectorInData(env, inData, nativeInData)) {
        LOGE("Make js CppParamSet failed");
        return false;
    }
    status = napi_set_named_property(env, nativeCppParamSet, "inData", nativeInData);
    if (status != napi_ok) {
        LOGE("Set property to nativeCppParamSet failed, status:%d", status);
        return false;
    }

    argv[ARGC_ZERO] = nativeHandle;
    argv[ARGC_ONE] = nativeCppParamSet;
    argc = ARGC_TWO;
    return true;
}

bool BuildPropertyData(const napi_env &env, const std::string &propertyId, const HandleInfoParam &param,
    napi_value *argv, size_t &argc)
{
    napi_value nativeHandle = nullptr;
    auto status = napi_create_string_utf8(env, param.handle.c_str(), param.handle.length(), &nativeHandle);
    if (status != napi_ok) {
        LOGE("create string utf8 failed, status:%d", status);
        return false;
    };

    napi_value nativePropertyId = nullptr;
    status = napi_create_string_utf8(env, propertyId.c_str(), propertyId.length(), &nativePropertyId);
    if (status != napi_ok) {
        LOGE("create string utf8 failed, status:%d", status);
        return false;
    };

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()) {
        status = napi_create_object(env, &nativeCppParamSet);
        if (nativeCppParamSet == nullptr) {
            LOGE("Create js NativeValue object failed, status:%d", status);
            return false;
        }
        nativeCppParamSet = GenerateHksParamArray(env, *param.params.GetParamSet());
        if (nativeCppParamSet == nullptr) {
            return false;
        }
    }

    argv[ARGC_ZERO] = nativeHandle;
    argv[ARGC_ONE] = nativePropertyId;
    argv[ARGC_TWO] = nativeCppParamSet;
    argc = ARGC_THREE;
    return true;
}

int32_t DoCallJsMethod(std::shared_ptr<CallJsParam> param)
{
    if (param == nullptr || param->jsRuntime == nullptr) {
        LOGE("failed to get jsRuntime.");
        return HKS_ERROR_EXT_NULLPTR;
    }
    AbilityRuntime::JsRuntime *jsRuntime = param->jsRuntime;

    OHOS::AbilityRuntime::HandleEscape handleEscape(*jsRuntime);
    auto &nativeEngine = jsRuntime->GetNativeEngine();
    auto env = reinterpret_cast<napi_env>(&nativeEngine);
    size_t argc = 0;
    napi_value argv[MAX_ARG_COUNT] = { nullptr };
    if (!param->argParser(env, argv, argc)) {
        LOGE("failed to get params.");
        return HKS_ERROR_EXT_PARSE_FUNC_FAILED;
    }

    napi_value value = nullptr;
    auto ref = reinterpret_cast<napi_ref>(param->jsObj);
    auto status = napi_get_reference_value(env, ref, &value);
    if (value == nullptr) {
        LOGE("failed to get native value object, status:%d", status);
        return HKS_ERROR_EXT_GET_VALUE_FAILED;
    }
    napi_value method = nullptr;
    status = napi_get_named_property(env, value, param->funcName.c_str(), &method);
    if (method == nullptr || status != napi_ok) {
        LOGE("failed to get %s from FileExtAbility object.status:%d", param->funcName.c_str(), status);
        return HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED;
    }
    if (param->retParser == nullptr) {
        LOGE("ResultValueParser must not null.");
        return HKS_ERROR_EXT_PARSE_FUNC_FAILED;
    }
    napi_value result = nullptr;
    status = napi_call_function(env, value, method, argc, argv, &result);
    if (result == nullptr || status != napi_ok) {
        LOGE("Napi call function fail, status:%d", status);
        return HKS_ERROR_EXT_CALL_FUNCTION_FAILED;
    }
    if (!param->retParser(env, handleEscape.Escape(result))) {
        LOGE("Parser js result fail.");
        return HKS_ERROR_EXT_PARSE_FUNC_FAILED;
    }
    return HKS_SUCCESS;
}

int32_t GetStringValue(napi_env env, napi_value value, std::string &result)
{
    size_t tempSize = 0;
    auto status = napi_get_value_string_utf8(env, value, nullptr, 0, &tempSize);
    if (status != napi_ok) {
        LOGE("get_length_string_utf8 failed, status:%d", status);
        return HKS_ERROR_EXT_GET_VALUE_FAILED;
    }
    if (tempSize > MAX_CERT_SIZE) {
        LOGE("exceed the max size");
        return HKS_ERROR_EXT_EXCEED_MAX_SIZE;
    }
    result.reserve(tempSize + 1);
    result.resize(tempSize + 1);
    status = napi_get_value_string_utf8(env, value, result.data(), tempSize + 1, &tempSize);
    if (status != napi_ok) {
        LOGE("get_value_string_utf8 failed, status:%d", status);
        return HKS_ERROR_EXT_GET_VALUE_FAILED;
    }
    result.pop_back();
    return HKS_SUCCESS;
}

napi_status GetUint8ArrayValue(napi_env env, napi_value value, HksBlob &result)
{
    size_t length = 0;
    void *data = nullptr;
    napi_typedarray_type type;
    napi_value array = nullptr;
    size_t offset = 0;
    auto status = napi_get_typedarray_info(env, value, &type, &length, (void **)(&data), &array, &offset);
    if (status != napi_ok) {
        LOGE("napi_get_typedarray_info failed %d", int32_t(status));
        return status;
    }
    if (type != napi_uint8_array) {
        LOGE("TypeArray is not napi_uint8_array.");
        return napi_invalid_arg;
    }

    uint8_t *uint8Data = nullptr;
    size_t byte_length = 0;
    status = napi_get_arraybuffer_info(env, array, (void **)&uint8Data, &byte_length);
    if (status != napi_ok) {
        LOGE("napi_get_typedarray_info %d", int32_t(status));
        return status;
    }
    if (byte_length > UINT32_MAX) {
        LOGE("byte_length is out of uint32_t.");
        return napi_invalid_arg;
    }
    result.size = static_cast<uint32_t>(byte_length);
    result.data = uint8Data;
    return napi_ok;
}

int32_t GetHksCertInfoValue(napi_env env, napi_value value, HksCertInfo &certInfo)
{
    napi_value napiPurpose = nullptr;
    auto status = napi_get_named_property(env, value, "purpose", &napiPurpose);
    if (status != napi_ok) {
        LOGE("napi_get_named_property failed, status %d", status);
        return status;
    }
    if (napiPurpose == nullptr) {
        LOGE("napi_get_named_property get napiPurpose is nullptr.");
        return napi_invalid_arg;
    }
    status = napi_get_value_int32(env, napiPurpose, &certInfo.purpose);
    if (status != napi_ok) {
        LOGE("GetHksCertInfoValue js value napiPurpose failed, status %d", status);
        return status;
    }

    napi_value napiIndex = nullptr;
    status = napi_get_named_property(env, value, "resourceId", &napiIndex);
    if (status != napi_ok) {
        LOGE("napi_get_named_property failed, status %d", status);
        return status;
    }
    if (napiIndex == nullptr) {
        LOGE("napi_get_named_property get napiIndex is nullptr.");
        return napi_invalid_arg;
    }
    auto result = GetStringValue(env, napiIndex, certInfo.index);
    if (result != HKS_SUCCESS) {
        LOGE("GetHksCertInfoValue js value napiIndex failed, result %d", result);
        return result;
    }
    
    napi_value napiCerts = nullptr;
    status = napi_get_named_property(env, value, "cert", &napiCerts);
    if (status != napi_ok) {
        LOGE("napi_get_named_property failed, status %d", status);
        return status;
    }
    if (napiCerts == nullptr) {
        LOGE("napi_get_named_property get napiCerts is nullptr.");
        return napi_invalid_arg;
    }
    status = GetUint8ArrayValue(env, napiCerts, certInfo.certsArray);
    if (status != napi_ok) {
        LOGE("GetHksCertInfoValue js value napiCerts failed, status %d", status);
        return status;
    }
    return napi_ok;
}

napi_status GetHksParamsfromValue(napi_env env, napi_value value, HksParam &param)
{
    napi_value napiTag = nullptr;
    auto status = napi_get_named_property(env, value, "tag", &napiTag);
    if (status != napi_ok) {
        LOGE("tag get failed, status %d", status);
        return status;
    }
    HKS_IF_TRUE_LOGE_RETURN(napiTag == nullptr, napi_invalid_arg, "napi_get_named_property get napiTag is nullptr.")
    status = napi_get_value_uint32(env, napiTag, &param.tag);
    if (status != napi_ok) {
        LOGE("tag get failed, status %d", status);
        return status;
    }
    napi_value napiValue = nullptr;
    status = napi_get_named_property(env, value, "value", &napiValue);
    if (status != napi_ok) {
        LOGE("napi_get_named_property failed, status %d", status);
        return status;
    }
    HKS_IF_TRUE_LOGE_RETURN(napiValue == nullptr, napi_invalid_arg, "napi_get_named_property get napiValue is nullptr.")
    bool lossLess = true;
    switch (param.tag & HKS_TAG_TYPE_MASK) {
        case HKS_TAG_TYPE_INT:
            status = napi_get_value_int32(env, napiValue, &param.int32Param);
            break;
        case HKS_TAG_TYPE_UINT:
            status = napi_get_value_uint32(env, napiValue, &param.uint32Param);
            break;
        case HKS_TAG_TYPE_ULONG:
            lossLess = false;
            status = napi_get_value_bigint_uint64(env, napiValue, &param.uint64Param, &lossLess);
            break;
        case HKS_TAG_TYPE_BOOL:
            status = napi_get_value_bool(env, napiValue, &param.boolParam);
            break;
        case HKS_TAG_TYPE_BYTES:
            status = GetUint8ArrayValue(env, napiValue, param.blob);
            break;
        default:
            LOGE("tag is unknow");
            break;
    }
    if (status != napi_ok || !lossLess) {
        LOGE("value get failed, lossLess: %d", lossLess);
        return status;
    }
    return napi_ok;
}

int32_t CallJsMethod(const std::string &funcName, AbilityRuntime::JsRuntime &jsRuntime,
    NativeReference *jsObj, InputArgsParser argParser, ResultValueParser retParser)
{
    auto param = std::make_shared<CallJsParam>(funcName, &jsRuntime, jsObj, argParser, retParser);
    if (param == nullptr) {
        LOGE("failed to new param.");
        return EINVAL;
    }

    auto weakPtrParam = std::weak_ptr<CallJsParam>(param);
    auto task = [weakPtrParam]() {
        auto param = weakPtrParam.lock();
        if (param == nullptr || param->jsRuntime == nullptr) {
            LOGE("failed to get CallJsParam.");
            return;
        }

        AbilityRuntime::HandleScope handleScope(*param->jsRuntime);
        param->errcode = DoCallJsMethod(param);
        if (param->errcode != HKS_SUCCESS) {
            LOGE("failed to call DoCallJsMethod.");
        }

        std::unique_lock<std::mutex> lock(param->CryptoOperateMutex);
        param->isReady = true;
        param->CryptoOperateCondition.notify_one();
    };
    auto ret = napi_send_event(jsRuntime.GetNapiEnv(), task, napi_eprio_high);
    if (ret != napi_ok) {
        LOGE("failed to napi_send_event, ret:%d.", ret);
        return HKS_ERROR_EXT_SEND_EVENT_FAILED;
    }
    const auto maxWaitTime = std::chrono::seconds(MAX_WAIT_TIME);
    std::unique_lock<std::mutex> lock(param->CryptoOperateMutex);
    if (!param->isReady) {
        param->CryptoOperateCondition.wait_for(lock, maxWaitTime, [param]() { return param->isReady; });
    }
    return param->errcode;
}

void GetOpenRemoteHandleParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    napi_value napiHandle = nullptr;
    auto status = napi_get_named_property(env, funcResult, "handle", &napiHandle);
    if (status != napi_ok || napiHandle == nullptr) {
        LOGE("GetOpenRemoteHandleParams::napi_get_named_property failed, status:%d", status);
        return;
    }
    auto result = GetStringValue(env, napiHandle, resultParams.handle);
    if (result != HKS_SUCCESS) {
        LOGE("GetOpenRemoteHandleParams::Convert js napiHandle fail.result:%d", result);
    }
}

void GetAuthUkeyPinParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    napi_value napiAuthState = nullptr;
    auto status = napi_get_named_property(env, funcResult, "authState", &napiAuthState);
    if (status == napi_ok && napiAuthState != nullptr) {
        status = napi_get_value_int32(env, napiAuthState, &resultParams.authState);
        if (status != napi_ok) {
            LOGE("Convert js value authState failed, status:%d", status);
        }
    } else {
        LOGE("napi_get_named_property failed, status:%d", status);
    }
    napi_value napiRetryCnt = nullptr;
    status = napi_get_named_property(env, funcResult, "retryCount", &napiRetryCnt);
    if (status != napi_ok || napiRetryCnt == nullptr) {
        LOGE("napi_get_named_property failed, status:%d", status);
        return;
    }
    status = napi_get_value_uint32(env, napiRetryCnt, &resultParams.retryCnt);
    if (status != napi_ok) {
        LOGE("Convert js value retryCnt failed.status:%d", status);
    }
}

void GetUkeyPinAuthStateParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    napi_value napiAuthState = nullptr;
    auto status = napi_get_named_property(env, funcResult, "authState", &napiAuthState);
    if (status != napi_ok || napiAuthState == nullptr) {
        LOGE("napi_get_named_property failed, status:%d", status);
        return;
    }
    status = napi_get_value_int32(env, napiAuthState, &resultParams.authState);
    if (status != napi_ok) {
        LOGE("napi_get_value_int32 failed.status:%d", status);
    }
}

void HksCertInfoToString(std::vector<HksCertInfo> &certInfoVec, std::string &jsonStr)
{
    auto jsonObj = CommJsonObject::CreateArray();
    if (jsonObj.IsNull()) {
        LOGE("jsonObj is null");
        return;
    }
    
    for (auto certInfo : certInfoVec) {
        auto certJsonObj = CommJsonObject::CreateObject();
        if (certJsonObj.IsNull()) {
            LOGE("certJsonObj is null");
            break;
        }

        if (!certJsonObj.SetValue("purpose", certInfo.purpose)) {
            LOGE("set purpose value failed");
            break;
        }

        if (!certJsonObj.SetValue("index", certInfo.index)) {
            LOGE("set index value failed");
            break;
        }

        std::string certStr = "";
        if (BlobToBase64String(certInfo.certsArray, certStr) != HKS_SUCCESS) {
            LOGE("blob to base64 failed");
            break;
        }
        if (!certJsonObj.SetValue("cert", certStr)) {
            LOGE("set index cert failed");
            break;
        }

        if (!jsonObj.AppendElement(certJsonObj)) {
            LOGE("AppendElement error");
        }
    }
    jsonStr = jsonObj.Serialize();
    if (jsonStr.empty()) {
        LOGE("jsonStr is empty");
        return;
    }
    return ;
}

void GetExportCertificateParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    napi_value nativeArray = nullptr;
    auto status = napi_create_array(env, &nativeArray);
    if (status != napi_ok) {
        LOGE("create_array failed, status %d", status);
        return;
    }

    status = napi_get_named_property(env, funcResult, "certs", &nativeArray);
    if (nativeArray == nullptr || status != napi_ok) {
        LOGE("napi_get_named_property failed. status:%d", status);
        return;
    }

    uint32_t length = 0;
    status = napi_get_array_length(env, nativeArray, &length);
    if (status != napi_ok) {
        LOGE("Get nativeArray length fail. status:%d", status);
        return;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value queryResult = nullptr;
        status = napi_get_element(env, nativeArray, i, &queryResult);
        if (queryResult == nullptr) {
            LOGE("Get native queryResult fail. status:%d", status);
            return;
        }

        HksCertInfo certInfo;
        auto result = GetHksCertInfoValue(env, queryResult, certInfo);
        if (result != napi_ok) {
            LOGE("Convert js certInfo fail. result:%d", result);
            return;
        }
        resultParams.certs.emplace_back(std::move(certInfo));
    }
    return;
}

void GetSessionParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    napi_value napiOutData = nullptr;
    auto status = napi_create_array(env, &napiOutData);
    if (status != napi_ok) {
        LOGE("create_array failed, status:%d", status);
        return;
    }
    status = napi_get_named_property(env, funcResult, "outData", &napiOutData);
    if (napiOutData == nullptr || status != napi_ok) {
        LOGE("Convert js array object fail, status:%d", status);
        return;
    }

    napi_typedarray_type type;
    napi_value nativeArray;
    size_t byte_offset;
    size_t length;
    status = napi_get_typedarray_info(env, napiOutData, &type, &length, nullptr, &nativeArray, &byte_offset);
    if (status != napi_ok) {
        LOGE("get typedarray info failed, status:%d", status);
        return;
    }

    void *data;
    size_t byte_length;
    status = napi_get_arraybuffer_info(env, nativeArray, &data, &byte_length);
    if (status != napi_ok || data == nullptr) {
        LOGE("get arraybuffer info failed, status:%d", status);
        return;
    }

    if (type == napi_uint8_array) {
        uint8_t *data_bytes = (uint8_t *)(data);
        size_t num = length / sizeof(uint8_t);

        for (size_t i = 0; i < num; ++i) {
            resultParams.outData.push_back(*((uint8_t *)(data_bytes) + i));
        }
    }
}

void GetGetPropertyParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    napi_value nativeArray = nullptr;
    auto status = napi_create_array(env, &nativeArray);
    if (status != napi_ok) {
        LOGE("create_array failed, status:%d", status);
        return;
    }
    status = napi_get_named_property(env, funcResult, "property", &nativeArray);
    if (nativeArray == nullptr || status != napi_ok) {
        LOGE("Convert js array object fail.status:%d", status);
        return;
    }

    uint32_t length = 0;
    status = napi_get_array_length(env, nativeArray, &length);
    if (status != napi_ok) {
        LOGE("Get nativeArray length fail.status:%d", status);
        return;
    }
    std::vector<HksParam> paramVec {};
    for (uint32_t i = 0; i < length; ++i) {
        napi_value queryResult = nullptr;
        status = napi_get_element(env, nativeArray, i, &queryResult);
        if (queryResult == nullptr) {
            LOGE("Get native queryResult fail.status:%d", status);
            return;
        }

        HksParam param;
        status = GetHksParamsfromValue(env, queryResult, param);
        if (status != napi_ok) {
            LOGE("Convert js param fail.status:%d", status);
            return;
        }
        paramVec.emplace_back(std::move(param));
    }
    CppParamSet cppParamSetTemp(paramVec);
    resultParams.paramSet = std::move(cppParamSetTemp);
    return;
}

int32_t ConvertFunctionResult(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    if (funcResult == nullptr) {
        LOGE("The funcResult is error.");
        return HKS_ERROR_EXT_NULLPTR;
    }
 
    napi_value napiCode = nullptr;
    auto status = napi_get_named_property(env, funcResult, "resultCode", &napiCode);
    if (status != napi_ok || napiCode == nullptr) {
        LOGE("napi_get_named_property failed, status:%d", status);
        return HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED;
    }
    status = napi_get_value_int32(env, napiCode, &resultParams.errCode);
    if (status != napi_ok) {
        LOGE("Convert js value napiCode failed.status:%d", status);
        return HKS_ERROR_EXT_GET_VALUE_FAILED;
    }

    switch (resultParams.paramType) {
        case CryptoResultParamType::OPEN_REMOTE_HANDLE:
        case CryptoResultParamType::INIT_SESSION:
            GetOpenRemoteHandleParams(env, funcResult, resultParams);
            break;
        case CryptoResultParamType::AUTH_UKEY_PIN:
            GetAuthUkeyPinParams(env, funcResult, resultParams);
            break;
        case CryptoResultParamType::GET_UKEY_PIN_AUTH_STATE:
            GetUkeyPinAuthStateParams(env, funcResult, resultParams);
            break;
        case CryptoResultParamType::EXPORT_CERTIFICATE:
        case CryptoResultParamType::EXPORT_PROVIDER_CERTIFICATES:
            GetExportCertificateParams(env, funcResult, resultParams);
            break;
        case CryptoResultParamType::UPDATE_SESSION:
        case CryptoResultParamType::FINISH_SESSION:
            GetSessionParams(env, funcResult, resultParams);
            break;
        case CryptoResultParamType::GET_PROPERTY:
            GetGetPropertyParams(env, funcResult, resultParams);
            break;
        case CryptoResultParamType::CLOSE_REMOTE_HANDLE:
        case CryptoResultParamType::CLEAR_UKEY_PIN_AUTH:
        default:
            break;
    }
    return HKS_SUCCESS;
}

napi_value PromiseCallback(napi_env env, napi_callback_info info)
{
    if (info == nullptr) {
        LOGE("PromiseCallback, invalid input info");
        return nullptr;
    }
 
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    void *data = nullptr;
 
    auto status = napi_get_cb_info(env, info, &argc, &argv[ARGC_ZERO], nullptr, &data);
    if (data == nullptr) {
        LOGE("PromiseCallback, invalid data, status:%d", status);
        return nullptr;
    }
    auto *callbackInfo = static_cast<PromiseCallbackInfo *>(data);
    if (callbackInfo == nullptr) {
        LOGE("PromiseCallback, invalid callbackInfo");
        return nullptr;
    }
    auto dataParam = callbackInfo->GetJsCallBackParam();
    dataParam->hksErrorCode = ConvertFunctionResult(env, argv[ARGC_ZERO], *dataParam);

    PromiseCallbackInfo::Destroy(callbackInfo);
    dataParam->callJsCon.notify_one();
    dataParam->callJsExMethodDone.store(true);
    callbackInfo = nullptr;
    return nullptr;
}
 
int32_t CallPromise(napi_env &env, napi_value funcResult, std::shared_ptr<CryptoResultParam> dataParam)
{
    napi_value promiseThen = nullptr;
    auto status = napi_get_named_property(env, funcResult, "then", &promiseThen);
    if (status != napi_ok || promiseThen == nullptr) {
        LOGE("get then from promiseValue failed, status:%d", status);
        return HKS_ERROR_EXT_SET_NAME_PROPERTY_FAILED;
    }
 
    bool isCallable = false;
    status = napi_is_callable(env, promiseThen, &isCallable);
    if (!isCallable) {
        LOGE("property then is not callable, status:%d", status);
        return HKS_ERROR_EXT_THEN_IS_NOT_CALLABLE;
    }
 
    napi_value promiseCallback = nullptr;
    auto *callbackInfo = PromiseCallbackInfo::Create(dataParam);
    if (callbackInfo == nullptr) {
        LOGE("Failed to new promise callbackInfo.");
        return HKS_ERROR_EXT_NULLPTR;
    }
    status = napi_create_function(env, "promiseCallback", strlen("promiseCallback"), PromiseCallback,
        callbackInfo, &promiseCallback);
    if (status != napi_ok) {
        LOGE("create promiseCallback function failed: status:%d", status);
        PromiseCallbackInfo::Destroy(callbackInfo);
        return HKS_ERROR_EXT_CREATE_FUNCTION_FAILED;
    }

    napi_value argvPromise[1] = { promiseCallback };
 
    status = napi_call_function(env, funcResult, promiseThen, ARGS_ONE, argvPromise, nullptr);
    if (status != napi_ok) {
        LOGE("Invoke pushCheck promise then error. status:%d", status);
        PromiseCallbackInfo::Destroy(callbackInfo);
        return HKS_ERROR_EXT_CALL_FUNCTION_FAILED;
    }
    return HKS_SUCCESS;
}

bool CheckAndCallPromise(napi_env env, napi_value result, std::shared_ptr<CryptoResultParam> dataParam)
{
    bool isPromise = false;
    auto status = napi_is_promise(env, result, &isPromise);
    if (!isPromise) {
        LOGE("retParser is not promise, status:%d", status);
        dataParam->hksErrorCode = HKS_ERROR_EXT_IS_NOT_PROMISE;
        return false;
    }
    dataParam->hksErrorCode = CallPromise(env, result, dataParam);
    return true;
}
} // namespace

JsHksCryptoExtAbility *JsHksCryptoExtAbility::Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime)
{
    return new (std::nothrow) JsHksCryptoExtAbility(static_cast<AbilityRuntime::JsRuntime &>(*runtime));
}

JsHksCryptoExtAbility::JsHksCryptoExtAbility(AbilityRuntime::JsRuntime &jsRuntime) : jsRuntime_(jsRuntime) {}

JsHksCryptoExtAbility::~JsHksCryptoExtAbility()
{
    jsRuntime_.FreeNativeReference(std::move(jsObj_));
}

void JsHksCryptoExtAbility::GetSrcPath(std::string &srcPath)
{
    srcPath.append(abilityInfo_->moduleName + "/");
    srcPath.append(abilityInfo_->srcEntrance);
    auto dotPos = srcPath.rfind('.');
    if (dotPos != std::string::npos) {
        srcPath.erase(dotPos);
    }
    srcPath.append(".abc");
}

void JsHksCryptoExtAbility::Init(const std::shared_ptr<AbilityRuntime::AbilityLocalRecord> &record,
    const std::shared_ptr<AbilityRuntime::OHOSApplication> &application,
    std::shared_ptr<AbilityRuntime::AbilityHandler> &handler, const sptr<IRemoteObject> &token)
{
    HksCryptoExtAbility::Init(record, application, handler, token);
    std::string srcPath = "";
    if (abilityInfo_ == nullptr) {
        LOGE("abilityInfo_ is nullptr");
        return;
    }
    GetSrcPath(srcPath);
    
    std::string moduleName(abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    jsObj_ = jsRuntime_.LoadModule(moduleName, srcPath, abilityInfo_->hapPath,
        abilityInfo_->compileMode == AbilityRuntime::CompileMode::ES_MODULE);
    
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());
    napi_value exception = nullptr;
    napi_status status = napi_get_and_clear_last_exception(env, &exception);
    if (status == napi_ok && exception != nullptr) {
        LOGE("Clear Error in jsRuntime_.");
    }
    
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
    Extension::OnStart(want);
    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    napi_value argv[] = { napiWant };
    CallObjectMethod("onCreate", argv, ARGC_ONE); // Don't enforce this function
}

void JsHksCryptoExtAbility::OnDisconnect(const AAFwk::Want &want)
{
    Extension::OnDisconnect(want);
    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    napi_value argv[] = { napiWant };
    CallObjectMethod("onDisconnect", argv, ARGC_ONE); // Don't enforce this function
}

sptr<IRemoteObject> JsHksCryptoExtAbility::OnConnect(const AAFwk::Want &want)
{
    Extension::OnConnect(want);
    sptr<HksCryptoExtStubImpl> remoteObject(
        new (std::nothrow) HksCryptoExtStubImpl(std::static_pointer_cast<JsHksCryptoExtAbility>(shared_from_this())));
    if (remoteObject == nullptr) {
        LOGE("No memory allocated for HksCryptoExtStubImpl");
        return nullptr;
    }
    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    napi_value argv[] = { napiWant };
    CallObjectMethod("onConnect", argv, ARGC_ONE); // Don't enforce this function
    if (!jsObj_) {
        LOGE("CallObjectMethod jsObj Not found HksCryptoExtAbility.js in OnConnect.");
        return nullptr;
    }
    return remoteObject->AsObject();
}

napi_value JsHksCryptoExtAbility::CallObjectMethod(const char *name, napi_value const *argv, size_t argc)
{
    if (!jsObj_) {
        LOGE("CallObjectMethod jsObj Not found HksCryptoExtAbility.js");
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
    auto status = napi_get_named_property(env, value, name, &method);
    if (method == nullptr || status != napi_ok) {
        LOGE("Failed to get '%s' from HksCryptoExtAbility object, status:%d", name, status);
        return nullptr;
    }

    napi_value result = nullptr;
    status = napi_call_function(env, value, method, argc, argv, &result);
    if (status != napi_ok) {
        LOGE("Call function fail, status:%d", status);
        return nullptr;
    }
    return handleEscape.Escape(result);
}

int32_t JsHksCryptoExtAbility::OpenRemoteHandle(const std::string &index, const CppParamSet &params,
    std::string &handle, int32_t &errcode)
{
    auto argParser = [index, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct IndexInfoParam param = {
            index,
            params,
        };
        return BuildIndexInfoParam(env, param, argv, argc);
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::OPEN_REMOTE_HANDLE;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onOpenResource", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    handle = std::move(dataParam->handle);
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::CloseRemoteHandle(const std::string &handle, const CppParamSet &params, int32_t &errcode)
{
    auto argParser = [handle, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct HandleInfoParam param = {
            handle,
            params,
        };
        return BuildHandleInfoParam(env, param, argv, argc);
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::CLOSE_REMOTE_HANDLE;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onCloseResource", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::AuthUkeyPin(const std::string &handle, const CppParamSet &params, int32_t &errcode,
    int32_t &authState, uint32_t &retryCnt)
{
    auto argParser = [handle, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct HandleInfoParam param = {
            handle,
            params,
        };
        return BuildHandleInfoParam(env, param, argv, argc);
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::AUTH_UKEY_PIN;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onAuthUkeyPin", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    authState = std::move(dataParam->authState);
    retryCnt = std::move(dataParam->retryCnt);
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::GetUkeyPinAuthState(const std::string &handle, const CppParamSet &params,
    int32_t &authState, int32_t &errcode)
{
    auto argParser = [handle, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct HandleInfoParam param = {
            handle,
            params,
        };
        return BuildHandleInfoParam(env, param, argv, argc);
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::GET_UKEY_PIN_AUTH_STATE;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onGetUkeyPinAuthState", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    authState = std::move(dataParam->authState);
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::ExportCertificate(const std::string &index, const CppParamSet &params,
    std::string &certJsonArr, int32_t &errcode)
{
    auto argParser = [index, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct IndexInfoParam param = {
            index,
            params,
        };
        return BuildIndexInfoParam(env, param, argv, argc);
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::EXPORT_CERTIFICATE;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onExportCertificate", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    HksCertInfoToString(dataParam->certs, certJsonArr);
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::ExportProviderCertificates(const CppParamSet &params, std::string &certJsonArr,
    int32_t &errcode)
{
    auto argParser = [params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        napi_value nativeCppParamSet = nullptr;
        napi_create_object(env, &nativeCppParamSet);
        if (nativeCppParamSet == nullptr) {
            LOGE("Create js NativeValue object failed");
            return false;
        }
        nativeCppParamSet = GenerateHksParamArray(env, *params.GetParamSet());
        if (nativeCppParamSet == nullptr) {
            return false;
        }
        argv[ARGC_ZERO] = nativeCppParamSet;
        argc = ARGC_ONE;
        return true;
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::EXPORT_PROVIDER_CERTIFICATES;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onEnumCertificates", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    HksCertInfoToString(dataParam->certs, certJsonArr);
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::InitSession(const std::string &index, const CppParamSet &params, std::string &handle,
    int32_t &errcode)
{
    auto argParser = [index, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct IndexInfoParam param = {
            index,
            params,
        };
        return BuildIndexInfoParamWithHuksOption(env, param, argv, argc);
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::INIT_SESSION;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onInitSession", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    handle = std::move(dataParam->handle);
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::UpdateSession(const std::string &handle, const CppParamSet &params,
    const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData, int32_t &errcode)
{
    auto argParser = [handle, params, inData](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct HandleInfoParam param = {
            handle,
            params,
        };
        return BuildHandleWithInData(env, param, inData, argv, argc);
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::UPDATE_SESSION;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onUpdateSession", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    outData = std::move(dataParam->outData);
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::FinishSession(const std::string &handle, const CppParamSet &params,
    const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData, int32_t &errcode)
{
    auto argParser = [handle, params, inData](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct HandleInfoParam param = {
            handle,
            params,
        };
        return BuildHandleWithInData(env, param, inData, argv, argc);
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::FINISH_SESSION;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onFinishSession", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    outData = std::move(dataParam->outData);
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::GetProperty(const std::string &handle, const std::string &propertyId,
    const CppParamSet &params, CppParamSet &outParams, int32_t &errcode)
{
    auto argParser = [handle, propertyId, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct HandleInfoParam param = {
            handle,
            params,
        };
        return BuildPropertyData(env, propertyId, param, argv, argc);
    };
    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    HksParamSet *defaultParamSet = nullptr;
    dataParam->paramType = CryptoResultParamType::GET_PROPERTY;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    int32_t ret = CallJsMethod("onGetProperty", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    if (dataParam->paramSet.GetParamSet() == nullptr) {
        LOGE("paramSet is nullptr. HksInitParamSet:%d", HksInitParamSet(&defaultParamSet));
        dataParam->paramSet = CppParamSet(defaultParamSet, true);
    }
    outParams = std::move(dataParam->paramSet);
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::ClearUkeyPinAuthState(const std::string &handle, const CppParamSet &params,
    int32_t &errcode)
{
    auto argParser = [handle, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct HandleInfoParam param = {
            handle,
            params,
        };
        return BuildHandleInfoParam(env, param, argv, argc);
    };
    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::CLEAR_UKEY_PIN_AUTH;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onClearUkeyPinAuthState", jsRuntime_, jsObj_.get(), argParser, retParser);
    if (ret != ERR_OK) {
        LOGE("CallJsMethod error, code:%d", ret);
        return ret;
    }
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    return dataParam->hksErrorCode;
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