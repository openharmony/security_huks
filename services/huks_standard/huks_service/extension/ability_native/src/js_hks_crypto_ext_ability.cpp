/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "hks_ukey_common.h"
#include "hks_mem.h"

#define WAIT_FOR_CALL_JS_METHOD(dataParam, waitTime) do { \
    const auto maxWaitTime = std::chrono::seconds((waitTime)); \
    std::unique_lock<std::mutex> lock((dataParam)->callJsMutex); \
    if (!(dataParam)->callJsExMethodDone.load()) { \
        (dataParam)->callJsCon.wait_for( \
            lock, maxWaitTime, [dataParam] { return (dataParam)->callJsExMethodDone.load(); }); \
    } \
} while (0) \

namespace OHOS {
namespace Security {
namespace Huks {
namespace {
constexpr size_t ARGC_ZERO = 0;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr size_t ARGC_THREE = 3;
constexpr size_t ARGC_FOUR = 4;
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

struct ImportWrappedKeyParam {
    std::string index {};
    std::string wrappingKeyIndex {};
    CppParamSet params {};
    std::vector<uint8_t> wrappedData {};
};

int32_t BlobToBase64String(const HksBlob &strBlob, std::string &outStr)
{
    HKS_EXT_IF_TRUE_LOGE_RETURN(strBlob.size == 0 || strBlob.data == nullptr,
        HKS_ERROR_EXT_BASE64_FAILED, "strBlob is nullptr")
    std::vector<uint8_t> strVector(strBlob.data, strBlob.data + strBlob.size);
    auto base64Str = U8Vec2Base64Str(strVector);
    HKS_EXT_IF_TRUE_LOGE_RETURN(base64Str.first != HKS_SUCCESS,
        HKS_ERROR_EXT_BASE64_FAILED, "U8Vec2Base64Str failed. ret = %d", base64Str.first)
    outStr = std::move(base64Str.second);
    return HKS_SUCCESS;
}

napi_value GenerateArrayBuffer(const napi_env &env, uint8_t *data, uint32_t size)
{
    HKS_EXT_IF_TRUE_LOGE_RETURN(data == nullptr, nullptr, "Invalid input: data is null but size is %u", size)

    napi_value buffer;
    void *bufferPtr = nullptr;
    auto status = napi_create_arraybuffer(env, size * sizeof(uint8_t), &bufferPtr, &buffer);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, nullptr, "napi_create_arraybuffer failed, status:%d", status)
    napi_value outBuffer;
    status = napi_create_typedarray(env, napi_uint8_array, size, buffer, 0, &outBuffer);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, nullptr, "napi_create_typedarray failed, status:%d", status)
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || value == nullptr,
        HKS_ERROR_EXT_CREATE_VALUE_FAILED, "napi Create value failed %d", status)
    return HKS_SUCCESS;
}

static int32_t GenerateHksParam(const napi_env &env, const HksParam &param, napi_value &element)
{
    napi_value hksParam = nullptr;
    auto status = napi_create_object(env, &hksParam);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        HKS_ERROR_EXT_CREATE_VALUE_FAILED, "napi create object failed, status:%d", status)

    napi_value tag = nullptr;
    status = napi_create_uint32(env, param.tag, &tag);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        HKS_ERROR_EXT_CREATE_VALUE_FAILED, "napi create uint32t failed, status:%d", status)
    
    status = napi_set_named_property(env, hksParam, "tag", tag);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        HKS_ERROR_EXT_SET_NAME_PROPERTY_FAILED, "napi set name failed, status:%d", status)
    napi_value value = nullptr;
    int32_t result = GenerateHksParamValue(env, param, value);
    HKS_EXT_IF_TRUE_LOGE_RETURN(result != HKS_SUCCESS, result, "GenerateHksParamValue failed")
    status = napi_set_named_property(env, hksParam, "value", value);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        HKS_ERROR_EXT_SET_NAME_PROPERTY_FAILED, "napi set name property failed, status:%d", status)
    element = std::move(hksParam);
    return HKS_SUCCESS;
}

napi_value GenerateHksParamArray(const napi_env env, const HksParamSet &paramSet)
{
    napi_value paramArray = nullptr;
    auto status = napi_create_array(env, &paramArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, nullptr, "create array failed, status:%d", status)

    for (uint32_t i = 0; i < paramSet.paramsCnt; i++) {
        napi_value element = nullptr;
        auto ret = GenerateHksParam(env, paramSet.params[i], element);
        HKS_EXT_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, nullptr, "GenerateHksParam failed")
        status = napi_set_element(env, paramArray, i, element);
        HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, nullptr, "napi set element failed, status:%d", status)
    }

    return paramArray;
}

static int32_t ConvertCertInfoIdlToJsObject(const napi_env &env, const HksExtCertInfoIdl &certInfo,
    napi_value &certObj)
{
    napi_status status = napi_create_object(env, &certObj);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || certObj == nullptr,
        HKS_ERROR_EXT_CREATE_VALUE_FAILED, "napi_create_object failed")

    napi_value purposeVal = nullptr;
    status = napi_create_int32(env, certInfo.purpose, &purposeVal);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || purposeVal == nullptr,
        HKS_ERROR_EXT_CREATE_VALUE_FAILED, "napi_create_int32 failed")
    status = napi_set_named_property(env, certObj, "purpose", purposeVal);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        HKS_ERROR_EXT_CREATE_VALUE_FAILED, "napi_set_named_property purpose failed")

    std::string indexStr(reinterpret_cast<const char*>(certInfo.index.data()), certInfo.index.size());
    napi_value resourceIdVal = nullptr;
    status = napi_create_string_utf8(env, indexStr.c_str(), indexStr.size(), &resourceIdVal);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || resourceIdVal == nullptr,
        HKS_ERROR_EXT_CREATE_VALUE_FAILED, "napi_create_string_utf8 failed")
    status = napi_set_named_property(env, certObj, "resourceId", resourceIdVal);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        HKS_ERROR_EXT_CREATE_VALUE_FAILED, "napi_set_named_property resourceId failed")

    void* data = nullptr;
    napi_value buffer = nullptr;
    status = napi_create_arraybuffer(env, certInfo.cert.size(), &data, &buffer);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || data == nullptr,
        HKS_ERROR_MALLOC_FAIL, "napi_create_arraybuffer failed")
    HKS_EXT_IF_TRUE_LOGE_RETURN(memcpy_s(data, certInfo.cert.size(), certInfo.cert.data(), certInfo.cert.size()) != EOK,
        HKS_ERROR_INSUFFICIENT_MEMORY, "memcpy_s failed in ConvertCertInfoIdlToJsObject")
    napi_value certArray = nullptr;
    status = napi_create_typedarray(env, napi_uint8_array, certInfo.cert.size(), buffer, 0, &certArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || certArray == nullptr,
        HKS_ERROR_EXT_CREATE_VALUE_FAILED, "napi_create_typedarray failed")
    status = napi_set_named_property(env, certObj, "cert", certArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        HKS_ERROR_EXT_CREATE_VALUE_FAILED, "napi_set_named_property cert failed")

    return HKS_SUCCESS;
}

bool MakeJsNativeCppParamSet(const napi_env &env, const CppParamSet &CppParamSet, napi_value nativeCppParamSet)
{
    napi_value napiHksParam = GenerateHksParamArray(env, *CppParamSet.GetParamSet());
    HKS_EXT_IF_TRUE_RETURN(napiHksParam == nullptr, false)

    auto status = napi_set_named_property(env, nativeCppParamSet, "properties", napiHksParam);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false, "Set property to nativeCppParamSet failed, status:%d", status)
    return true;
}

bool MakeJsNativeVectorInData(const napi_env &env, const std::vector<uint8_t> &inData, napi_value &nativeIndata)
{
    size_t length = inData.size();

    napi_value inDataBuffer;
    void *inDataPtr = nullptr;
    auto status = napi_create_arraybuffer(env, length, &inDataPtr, &inDataBuffer);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false, "create arraybuffer failed, status:%d", status)

    status = napi_create_typedarray(env, napi_uint8_array, length, inDataBuffer, 0, &nativeIndata);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false, "create typedarray failed, status:%d", status)

    uint8_t *inData_bytes = (uint8_t *)inDataPtr;
    for (size_t i = 0; i < length; ++i) {
        inData_bytes[i] = inData[i];
    }

    return true;
}

bool BuildImportWrappedKeyParam(const napi_env &env, const ImportWrappedKeyParam &param,
    napi_value *argv, size_t &argc)
{
    napi_value nativeIndex = nullptr;
    auto status = napi_create_string_utf8(env, param.index.c_str(), param.index.length(), &nativeIndex);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false, "create string utf8 failed, status:%d", status)

    napi_value nativeWrappingKeyIndex = nullptr;
    status = napi_create_string_utf8(env, param.wrappingKeyIndex.c_str(),
        param.wrappingKeyIndex.length(), &nativeWrappingKeyIndex);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false, "create string utf8 failed, status:%d", status)

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()) {
        nativeCppParamSet = GenerateHksParamArray(env, *param.params.GetParamSet());
        HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false, "GenerateHksParamArray failed")
    }

    napi_value nativeWrappedData = nullptr;
    HKS_EXT_IF_TRUE_LOGE_RETURN(!MakeJsNativeVectorInData(env, param.wrappedData, nativeWrappedData),
        false, "Make js NativeValue vector failed")

    argv[ARGC_ZERO] = nativeIndex;
    argv[ARGC_ONE] = nativeWrappingKeyIndex;
    argv[ARGC_TWO] = nativeCppParamSet;
    argv[ARGC_THREE] = nativeWrappedData;
    argc = ARGC_FOUR;
    return true;
}

bool BuildHandleInfoParam(const napi_env &env, const HandleInfoParam &param, napi_value *argv, size_t &argc)
{
    napi_value nativeHandle = nullptr;
    auto status = napi_create_string_utf8(env, param.handle.c_str(), param.handle.length(), &nativeHandle);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false, "create string utf8 failed, status:%d", status)

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()) {
        status = napi_create_object(env, &nativeCppParamSet);
        HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false,
            "Create js NativeValue object failed, status:%d", status)
        nativeCppParamSet = GenerateHksParamArray(env, *param.params.GetParamSet());
        HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false, "GenerateHksParamArray failed")
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false, "create string utf8 failed, status:%d", status)

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()) {
        status = napi_create_object(env, &nativeCppParamSet);
        HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false,
            "Create js NativeValue object failed, status:%d", status)
        nativeCppParamSet = GenerateHksParamArray(env, *param.params.GetParamSet());
        HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false, "GenerateHksParamArray failed")
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false, "create string utf8 failed, status:%d", status)

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()) {
        status = napi_create_object(env, &nativeCppParamSet);
        HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false,
            "Create js NativeValue object failed, status:%d", status)
        HKS_EXT_IF_TRUE_LOGE_RETURN(!MakeJsNativeCppParamSet(env, param.params, nativeCppParamSet),
            false, "Make js CppParamSet failed")
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false, "create string utf8 failed, status:%d", status)

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()) {
        status = napi_create_object(env, &nativeCppParamSet);
        HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false,
            "Create js NativeValue object failed, status:%d", status)
        HKS_EXT_IF_TRUE_LOGE_RETURN(!MakeJsNativeCppParamSet(env, param.params, nativeCppParamSet),
            false, "Make js CppParamSet failed")
    }

    napi_value nativeInData = nullptr;
    HKS_EXT_IF_TRUE_LOGE_RETURN(!MakeJsNativeVectorInData(env, inData, nativeInData),
        false, "Make js CppParamSet failed")
    status = napi_set_named_property(env, nativeCppParamSet, "inData", nativeInData);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false,
        "Set property to nativeCppParamSet failed, status:%d", status)

    argv[ARGC_ZERO] = nativeHandle;
    argv[ARGC_ONE] = nativeCppParamSet;
    argc = ARGC_TWO;
    return true;
}

bool BuildParam(const napi_env &env, const CppParamSet &param, napi_value *argv, size_t &argc)
{
    napi_value nativeCppParamSet = nullptr;
    if (param.GetParamSet()) {
        auto status = napi_create_object(env, &nativeCppParamSet);
        HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false,
            "Create js NativeValue object failed, status:%d", status)
        nativeCppParamSet = GenerateHksParamArray(env, *param.GetParamSet());
        HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false, "GenerateHksParamArray failed")
    }

    argv[ARGC_ZERO] = nativeCppParamSet;
    argc = ARGC_ONE;
    return true;
}

bool BuildPropertyData(const napi_env &env, const std::string &propertyId, const HandleInfoParam &param,
    napi_value *argv, size_t &argc)
{
    napi_value nativeHandle = nullptr;
    auto status = napi_create_string_utf8(env, param.handle.c_str(), param.handle.length(), &nativeHandle);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false, "create string utf8 failed, status:%d", status)

    napi_value nativePropertyId = nullptr;
    status = napi_create_string_utf8(env, propertyId.c_str(), propertyId.length(), &nativePropertyId);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false, "create string utf8 failed, status:%d", status)

    napi_value nativeCppParamSet = nullptr;
    if (param.params.GetParamSet()) {
        status = napi_create_object(env, &nativeCppParamSet);
        HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false,
            "Create js NativeValue object failed, status:%d", status)
        nativeCppParamSet = GenerateHksParamArray(env, *param.params.GetParamSet());
        HKS_EXT_IF_TRUE_RETURN(nativeCppParamSet == nullptr, false)
    }

    argv[ARGC_ZERO] = nativeHandle;
    argv[ARGC_ONE] = nativePropertyId;
    argv[ARGC_TWO] = nativeCppParamSet;
    argc = ARGC_THREE;
    return true;
}

int32_t DoCallJsMethod(std::shared_ptr<CallJsParam> param)
{
    HKS_EXT_IF_TRUE_LOGE_RETURN(param == nullptr || param->jsRuntime == nullptr,
        HKS_ERROR_EXT_NULLPTR, "failed to get jsRuntime.")
    AbilityRuntime::JsRuntime *jsRuntime = param->jsRuntime;

    OHOS::AbilityRuntime::HandleEscape handleEscape(*jsRuntime);
    auto &nativeEngine = jsRuntime->GetNativeEngine();
    auto env = reinterpret_cast<napi_env>(&nativeEngine);
    size_t argc = 0;
    napi_value argv[MAX_ARG_COUNT] = { nullptr };
    HKS_EXT_IF_TRUE_LOGE_RETURN(!param->argParser(env, argv, argc),
        HKS_ERROR_EXT_PARSE_FUNC_FAILED, "failed to get params.")

    napi_value value = nullptr;
    auto ref = reinterpret_cast<napi_ref>(param->jsObj);
    auto status = napi_get_reference_value(env, ref, &value);
    HKS_EXT_IF_TRUE_LOGE_RETURN(value == nullptr,
        HKS_ERROR_EXT_GET_VALUE_FAILED, "failed to get native value object, status:%d", status)
    napi_value method = nullptr;
    status = napi_get_named_property(env, value, param->funcName.c_str(), &method);
    HKS_EXT_IF_TRUE_LOGE_RETURN(method == nullptr || status != napi_ok,
        HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED, "failed to get %s from FileExtAbility object.status:%d",
        param->funcName.c_str(), status)
    HKS_EXT_IF_TRUE_LOGE_RETURN(param->retParser == nullptr,
        HKS_ERROR_EXT_PARSE_FUNC_FAILED, "ResultValueParser must not null.")
    napi_value result = nullptr;
    status = napi_call_function(env, value, method, argc, argv, &result);
    HKS_EXT_IF_TRUE_LOGE_RETURN(result == nullptr || status != napi_ok,
        HKS_ERROR_EXT_CALL_FUNCTION_FAILED, "Napi call function fail, status:%d", status)
    HKS_EXT_IF_TRUE_LOGE_RETURN(!param->retParser(env, handleEscape.Escape(result)),
        HKS_ERROR_EXT_PARSE_FUNC_FAILED, "Parser js result fail.")
    return HKS_SUCCESS;
}

int32_t GetStringValue(napi_env env, napi_value value, std::string &result)
{
    size_t tempSize = 0;
    auto status = napi_get_value_string_utf8(env, value, nullptr, 0, &tempSize);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        HKS_ERROR_EXT_GET_VALUE_FAILED, "get_length_string_utf8 failed, status:%d", status)
    HKS_EXT_IF_TRUE_LOGE_RETURN(tempSize > MAX_CERT_SIZE,
        HKS_ERROR_EXT_EXCEED_MAX_SIZE, "exceed the max size")
    result.reserve(tempSize + 1);
    result.resize(tempSize + 1);
    status = napi_get_value_string_utf8(env, value, result.data(), tempSize + 1, &tempSize);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        HKS_ERROR_EXT_GET_VALUE_FAILED, "get_value_string_utf8 failed, status:%d", status)
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
    auto status = napi_get_typedarray_info(env, value, &type, &length, &data, &array, &offset);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status,
        "napi_get_typedarray_info failed %d", int32_t(status))
    HKS_EXT_IF_TRUE_LOGE_RETURN(type != napi_uint8_array,
        napi_invalid_arg, "TypeArray is not napi_uint8_array.")

    uint8_t *uint8Data = nullptr;
    void *tmp = nullptr;
    size_t byte_length = 0;
    status = napi_get_arraybuffer_info(env, array, &tmp, &byte_length);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status,
        "napi_get_typedarray_info %d", int32_t(status))
    uint8Data = static_cast<uint8_t*>(tmp);
    HKS_EXT_IF_TRUE_LOGE_RETURN(byte_length > UINT32_MAX,
        napi_invalid_arg, "byte_length is out of uint32_t.")
    result.size = static_cast<uint32_t>(byte_length);
    result.data = uint8Data;
    return napi_ok;
}

int32_t GetHksCertInfoValue(napi_env env, napi_value value, HksCertInfo &certInfo)
{
    napi_value napiPurpose = nullptr;
    auto status = napi_get_named_property(env, value, "purpose", &napiPurpose);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status,
        "napi_get_named_property failed, status %d", status)
    HKS_EXT_IF_TRUE_LOGE_RETURN(napiPurpose == nullptr,
        napi_invalid_arg, "napi_get_named_property get napiPurpose is nullptr.")
    status = napi_get_value_int32(env, napiPurpose, &certInfo.purpose);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status,
        "GetHksCertInfoValue js value napiPurpose failed, status %d", status)

    napi_value napiIndex = nullptr;
    status = napi_get_named_property(env, value, "resourceId", &napiIndex);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status
        "napi_get_named_property failed, status %d", status)
    HKS_EXT_IF_TRUE_LOGE_RETURN(napiIndex == nullptr,
        napi_invalid_arg, "napi_get_named_property get napiIndex is nullptr.")
    auto result = GetStringValue(env, napiIndex, certInfo.index);
    HKS_EXT_IF_TRUE_LOGE_RETURN(result != HKS_SUCCESS, result
        "GetHksCertInfoValue js value napiIndex failed, result %d", result)
    
    napi_value napiCerts = nullptr;
    status = napi_get_named_property(env, value, "cert", &napiCerts);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status,
        "napi_get_named_property failed, status %d", status)
    HKS_EXT_IF_TRUE_LOGE_RETURN(napiCerts == nullptr,
        napi_invalid_arg, "napi_get_named_property get napiCerts is nullptr.")
    status = GetUint8ArrayValue(env, napiCerts, certInfo.certsArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status,
        "GetHksCertInfoValue js value napiCerts failed, status %d", status)
    return napi_ok;
}

napi_status GetHksParamsfromValue(napi_env env, napi_value value, HksParam &param)
{
    napi_value napiTag = nullptr;
    auto status = napi_get_named_property(env, value, "tag", &napiTag);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status, "tag get failed, status %d", status)
    HKS_EXT_IF_TRUE_LOGE_RETURN(napiTag == nullptr,
        napi_invalid_arg, "napi_get_named_property get napiTag is nullptr.")
    status = napi_get_value_uint32(env, napiTag, &param.tag);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status, "tag get failed, status %d", status)

    napi_value napiValue = nullptr;
    status = napi_get_named_property(env, value, "value", &napiValue);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status, "napi_get_named_property failed, status %d", status)
    HKS_EXT_IF_TRUE_LOGE_RETURN(napiValue == nullptr,
        napi_invalid_arg, "napi_get_named_property get napiValue is nullptr.")
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || !lossLess, status, "value get failed, lossLess: %d", lossLess)
    return napi_ok;
}

int32_t CallJsMethod(const std::string &funcName, AbilityRuntime::JsRuntime &jsRuntime,
    NativeReference *jsObj, InputArgsParser argParser, ResultValueParser retParser)
{
    auto param = std::make_shared<CallJsParam>(funcName, &jsRuntime, jsObj, argParser, retParser);
    HKS_EXT_IF_TRUE_LOGE_RETURN(param == nullptr, EINVAL, "failed to new param.")

    auto weakPtrParam = std::weak_ptr<CallJsParam>(param);
    auto task = [weakPtrParam]() {
        auto param = weakPtrParam.lock();
        HKS_EXT_IF_TRUE_LOGE_RETURN(param == nullptr || param->jsRuntime == nullptr,
            (void)0, "failed to get CallJsParam.")

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
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != napi_ok,
        HKS_ERROR_EXT_SEND_EVENT_FAILED, "failed to napi_send_event, ret:%d.", ret)
    const auto maxWaitTime = std::chrono::seconds(MAX_WAIT_TIME);
    std::unique_lock<std::mutex> lock(param->CryptoOperateMutex);
    if (!param->isReady) {
        param->CryptoOperateCondition.wait_for(lock, maxWaitTime, [param]() { return param->isReady; });
    }
    return param->errcode;
}

void GetErrorInfoParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    napi_value napiErrInfo = nullptr;
    std::string errMsg = "No error message.";
    auto status = napi_get_named_property(env, funcResult, "errInfo", &napiErrInfo);
    if (status != napi_ok || napiErrInfo == nullptr) {
        LOGE("GetErrorInfoParams::errInfo not found in result");
        resultParams.errInfo = HksCreateExternalErrorInfo(resultParams.errCode, errMsg.c_str());
        return;
    }
    napi_value napiErrno = nullptr;
    status = napi_get_named_property(env, napiErrInfo, "errno", &napiErrno);
    if (status != napi_ok || napiErrno == nullptr) {
        LOGE("GetErrorInfoParams::napi_get_named_property errno failed, status:%d", status);
        resultParams.errInfo = HksCreateExternalErrorInfo(resultParams.errCode, errMsg.c_str());
        return;
    }
    int32_t errnoValue = 0;
    status = napi_get_value_int32(env, napiErrno, &errnoValue);
    if (status != napi_ok) {
        LOGE("GetErrorInfoParams::get errno value failed, status:%d", status);
        resultParams.errInfo = HksCreateExternalErrorInfo(resultParams.errCode, errMsg.c_str());
        return;
    }
    napi_value napiErrorDesc = nullptr;
    status = napi_get_named_property(env, napiErrInfo, "errorDesc", &napiErrorDesc);
    if (status != napi_ok || napiErrorDesc == nullptr) {
        LOGE("GetErrorInfoParams::napi_get_named_property errorDesc failed, status:%d", status);
        resultParams.errInfo = HksCreateExternalErrorInfo(resultParams.errCode, errMsg.c_str());
        return;
    }
    std::string errorDesc;
    auto result = GetStringValue(env, napiErrorDesc, errorDesc);
    if (result != HKS_SUCCESS) {
        LOGE("GetErrorInfoParams::GetStringValue errorDesc failed, result:%d", result);
        resultParams.errInfo = HksCreateExternalErrorInfo(resultParams.errCode, errMsg.c_str());
        return;
    }
    resultParams.errInfo = HksCreateExternalErrorInfo(errnoValue, errorDesc.c_str());
    if (resultParams.errInfo == nullptr) {
        LOGE("GetErrorInfoParams::CreateExternalErrorInfo failed");
    }
}

void GetOpenRemoteHandleParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    GetErrorInfoParams(env, funcResult, resultParams);
    napi_value napiHandle = nullptr;
    auto status = napi_get_named_property(env, funcResult, "handle", &napiHandle);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || napiHandle == nullptr, (void)0,
        "GetOpenRemoteHandleParams::napi_get_named_property failed, status:%d", status)
    auto result = GetStringValue(env, napiHandle, resultParams.handle);
    if (result != HKS_SUCCESS) {
        LOGE("GetOpenRemoteHandleParams::Convert js napiHandle fail.result:%d", result);
    }
}

void GetResourceIdParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    GetErrorInfoParams(env, funcResult, resultParams);
    napi_value napiHandle = nullptr;
    auto status = napi_get_named_property(env, funcResult, "resourceId", &napiHandle);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || napiHandle == nullptr, (void)0,
        "GetResourceIdParams::napi_get_named_property failed, status:%d", status)
    auto result = GetStringValue(env, napiHandle, resultParams.handle);
    if (result != HKS_SUCCESS) {
        LOGE("GetResourceIdParams::Convert js napiHandle fail.result:%d", result);
    }
}

void GetAuthUkeyPinParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    GetErrorInfoParams(env, funcResult, resultParams);
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || napiRetryCnt == nullptr, (void)0,
        "napi_get_named_property failed, status:%d", status)
    status = napi_get_value_uint32(env, napiRetryCnt, &resultParams.retryCnt);
    if (status != napi_ok) {
        LOGE("Convert js value retryCnt failed.status:%d", status);
    }
}

void GetUkeyPinAuthStateParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    GetErrorInfoParams(env, funcResult, resultParams);
    napi_value napiAuthState = nullptr;
    auto status = napi_get_named_property(env, funcResult, "authState", &napiAuthState);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || napiAuthState == nullptr, (void)0,
        "napi_get_named_property failed, status:%d", status)
    status = napi_get_value_int32(env, napiAuthState, &resultParams.authState);
    if (status != napi_ok) {
        LOGE("napi_get_value_int32 failed.status:%d", status);
    }
}

void HksCertInfoToString(std::vector<HksCertInfo> &certInfoVec, std::string &jsonStr)
{
    auto jsonObj = CommJsonObject::CreateArray();
    HKS_EXT_IF_TRUE_LOGE_RETURN(jsonObj.IsNull(), (void)0, "jsonObj is null")
    
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(jsonStr.empty(), (void)0, "jsonStr is empty")
}

void GetExportCertificateParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    GetErrorInfoParams(env, funcResult, resultParams);
    napi_value nativeArray = nullptr;
    auto status = napi_create_array(env, &nativeArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, (void)0, "create_array failed, status %d", status)

    status = napi_get_named_property(env, funcResult, "certs", &nativeArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(nativeArray == nullptr || status != napi_ok, (void)0,
        "napi_get_named_property failed. status:%d", status)

    uint32_t length = 0;
    status = napi_get_array_length(env, nativeArray, &length);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, (void)0, "Get nativeArray length fail. status:%d", status)
    for (uint32_t i = 0; i < length; i++) {
        napi_value queryResult = nullptr;
        status = napi_get_element(env, nativeArray, i, &queryResult);
        HKS_EXT_IF_TRUE_LOGE_RETURN(queryResult == nullptr, (void)0,
            "Get native queryResult fail. status:%d", status)

        HksCertInfo certInfo;
        auto result = GetHksCertInfoValue(env, queryResult, certInfo);
        HKS_EXT_IF_TRUE_LOGE_RETURN(result != napi_ok, (void)0, "Convert js certInfo fail. result:%d", result)
        resultParams.certs.emplace_back(std::move(certInfo));
    }
}

void GetSessionParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    GetErrorInfoParams(env, funcResult, resultParams);
    napi_value napiOutData = nullptr;
    auto status = napi_create_array(env, &napiOutData);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, (void)0, "create_array failed, status:%d", status)
    status = napi_get_named_property(env, funcResult, "outData", &napiOutData);
    HKS_EXT_IF_TRUE_LOGE_RETURN(napiOutData == nullptr || status != napi_ok, (void)0,
        "Convert js array object fail, status:%d", status)

    napi_typedarray_type type;
    napi_value nativeArray;
    size_t byte_offset;
    size_t length;
    status = napi_get_typedarray_info(env, napiOutData, &type, &length, nullptr, &nativeArray, &byte_offset);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, (void)0, "get typedarray info failed, status:%d", status)

    void *data;
    size_t byte_length;
    status = napi_get_arraybuffer_info(env, nativeArray, &data, &byte_length);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || data == nullptr, (void)0,
        "get arraybuffer info failed, status:%d", status)

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
    GetErrorInfoParams(env, funcResult, resultParams);
    napi_value nativeArray = nullptr;
    auto status = napi_create_array(env, &nativeArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, (void)0, "create_array failed, status:%d", status)
    status = napi_get_named_property(env, funcResult, "property", &nativeArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(nativeArray == nullptr || status != napi_ok, (void)0,
        "Convert js array object fail.status:%d", status)

    uint32_t length = 0;
    status = napi_get_array_length(env, nativeArray, &length);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, (void)0, "Get nativeArray length fail.status:%d", status)
    std::vector<HksParam> paramVec {};
    for (uint32_t i = 0; i < length; ++i) {
        napi_value queryResult = nullptr;
        status = napi_get_element(env, nativeArray, i, &queryResult);
        HKS_EXT_IF_TRUE_LOGE_RETURN(queryResult == nullptr, (void)0,
            "Get native queryResult fail.status:%d", status)

        HksParam param;
        status = GetHksParamsfromValue(env, queryResult, param);
        HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, (void)0, "Convert js param fail.status:%d", status)
        paramVec.emplace_back(std::move(param));
    }
    CppParamSet cppParamSetTemp(paramVec);
    resultParams.paramSet = std::move(cppParamSetTemp);
}

int32_t ConvertFunctionResult(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    HKS_EXT_IF_TRUE_LOGE_RETURN(funcResult == nullptr,
        HKS_ERROR_EXT_NULLPTR, "The funcResult is error.")
    napi_value napiCode = nullptr;
    auto status = napi_get_named_property(env, funcResult, "resultCode", &napiCode);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || napiCode == nullptr,
        HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED, "napi_get_named_property failed, status:%d", status)
    status = napi_get_value_int32(env, napiCode, &resultParams.errCode);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        HKS_ERROR_EXT_GET_VALUE_FAILED, "Convert js value napiCode failed.status:%d", status)
    switch (resultParams.paramType) {
        case CryptoResultParamType::OPEN_REMOTE_HANDLE:
        case CryptoResultParamType::INIT_SESSION:
            GetOpenRemoteHandleParams(env, funcResult, resultParams);
            break;
        case CryptoResultParamType::GET_RESOURCE_ID:
            GetResourceIdParams(env, funcResult, resultParams);
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
        case CryptoResultParamType::EXPORT_PUBLIC_KEY:
            GetSessionParams(env, funcResult, resultParams);
            break;
        case CryptoResultParamType::SET_OR_GET_PROPERTY:
            GetGetPropertyParams(env, funcResult, resultParams);
            break;
        default:
            GetErrorInfoParams(env, funcResult, resultParams);
            break;
    }
    return HKS_SUCCESS;
}

napi_value PromiseCallback(napi_env env, napi_callback_info info)
{
    HKS_EXT_IF_TRUE_LOGE_RETURN(info == nullptr, nullptr, "PromiseCallback, invalid input info")
 
    size_t argc = 1;
    napi_value argv[1] = {nullptr};
    void *data = nullptr;
 
    auto status = napi_get_cb_info(env, info, &argc, &argv[ARGC_ZERO], nullptr, &data);
    HKS_EXT_IF_TRUE_LOGE_RETURN(data == nullptr, nullptr, "PromiseCallback, invalid data, status:%d", status)
    auto *callbackInfo = static_cast<PromiseCallbackInfo *>(data);
    HKS_EXT_IF_TRUE_LOGE_RETURN(callbackInfo == nullptr, nullptr, "PromiseCallback, invalid callbackInfo")
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || promiseThen == nullptr,
        HKS_ERROR_EXT_SET_NAME_PROPERTY_FAILED, "get then from promiseValue failed, status:%d", status)
 
    bool isCallable = false;
    status = napi_is_callable(env, promiseThen, &isCallable);
    HKS_EXT_IF_TRUE_LOGE_RETURN(!isCallable,
        HKS_ERROR_EXT_THEN_IS_NOT_CALLABLE, "property then is not callable, status:%d", status)
 
    napi_value promiseCallback = nullptr;
    auto *callbackInfo = PromiseCallbackInfo::Create(dataParam);
    HKS_EXT_IF_TRUE_LOGE_RETURN(callbackInfo == nullptr,
        HKS_ERROR_EXT_NULLPTR, "Failed to new promise callbackInfo.")
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(abilityInfo_ == nullptr, (void)0, "abilityInfo_ is nullptr")
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
    
    HKS_EXT_IF_TRUE_LOGE_RETURN(jsObj_ == nullptr, (void)0, "Failed to get jsObj_")

    HKS_EXT_IF_TRUE_LOGE_RETURN(jsObj_->GetNapiValue() == nullptr, (void)0, "Failed to get JsHksCryptoExtAbility value")
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(remoteObject == nullptr, nullptr, "No memory allocated for HksCryptoExtStubImpl")
    AbilityRuntime::HandleScope handleScope(jsRuntime_);
    napi_env env = reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine());
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    napi_value argv[] = { napiWant };
    CallObjectMethod("onConnect", argv, ARGC_ONE);
    HKS_EXT_IF_TRUE_LOGE_RETURN(!jsObj_, nullptr,
        "CallObjectMethod jsObj Not found HksCryptoExtAbility.js in OnConnect.")
    return remoteObject->AsObject();
}

napi_value JsHksCryptoExtAbility::CallObjectMethod(const char *name, napi_value const *argv, size_t argc)
{
    HKS_EXT_IF_TRUE_LOGE_RETURN(!jsObj_, nullptr, "CallObjectMethod jsObj Not found HksCryptoExtAbility.js")

    OHOS::AbilityRuntime::HandleEscape handleEscape(jsRuntime_);
    auto &nativeEngine = jsRuntime_.GetNativeEngine();
    auto env = reinterpret_cast<napi_env>(&nativeEngine);

    napi_value value = jsObj_->GetNapiValue();
    HKS_EXT_IF_TRUE_LOGE_RETURN(value == nullptr, nullptr, "Failed to get HksCryptoExtAbility value")

    napi_value method = nullptr;
    auto status = napi_get_named_property(env, value, name, &method);
    HKS_EXT_IF_TRUE_LOGE_RETURN(method == nullptr || status != napi_ok, nullptr,
        "Failed to get '%s' from HksCryptoExtAbility object, status:%d", name, status)

    napi_value result = nullptr;
    status = napi_call_function(env, value, method, argc, argv, &result);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, nullptr, "Call function fail, status:%d", status)
    return handleEscape.Escape(result);
}

int32_t JsHksCryptoExtAbility::OpenRemoteHandle(const std::string &index, const CppParamSet &params,
    std::string &handle, struct HksExternalErrorInfo **errInfo)
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    handle = std::move(dataParam->handle);
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    if (errInfo != nullptr) {
        if (dataParam->errInfo != nullptr) {
            *errInfo = dataParam->errInfo;
            dataParam->errInfo = nullptr;
        } else {
            *errInfo = HksCreateExternalErrorInfo(HKS_ERROR_EXT_CALL_JS_TIME_OUT, "");
        }
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::CloseRemoteHandle(const std::string &handle, const CppParamSet &params,
    struct HksExternalErrorInfo **errInfo)
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::AuthUkeyPin(const std::string &handle, const CppParamSet &params,
    struct HksExternalErrorInfo **errInfo, int32_t &authState, uint32_t &retryCnt)
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    authState = std::move(dataParam->authState);
    retryCnt = std::move(dataParam->retryCnt);

    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::GetUkeyPinAuthState(const std::string &handle, const CppParamSet &params,
    int32_t &state, struct HksExternalErrorInfo **errInfo)
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    state = std::move(dataParam->authState);
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::ExportCertificate(const std::string &index, const CppParamSet &params,
    std::string &certJsonArr, struct HksExternalErrorInfo **errInfo)
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    HksCertInfoToString(dataParam->certs, certJsonArr);
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::ExportProviderCertificates(const CppParamSet &params, std::string &certJsonArr,
    struct HksExternalErrorInfo **errInfo)
{
    auto argParser = [params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        napi_value nativeCppParamSet = nullptr;
        napi_create_object(env, &nativeCppParamSet);
        HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false, "Create js NativeValue object failed")
        nativeCppParamSet = GenerateHksParamArray(env, *params.GetParamSet());
        HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false, "GenerateHksParamArray failed")
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    HksCertInfoToString(dataParam->certs, certJsonArr);
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::ImportCertificate(const std::string &index, const HksExtCertInfoIdl &certInfo,
    const CppParamSet &params, struct HksExternalErrorInfo **errInfo)
{
    auto argParser = [index, &certInfo, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        napi_value nativeIndex = nullptr;
        auto status = napi_create_string_utf8(env, index.c_str(), index.length(), &nativeIndex);
        HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || nativeIndex == nullptr, false,
            "create string utf8 for index failed, status:%d", status)
        argv[ARGC_ZERO] = nativeIndex;

        napi_value nativeCppParamSet = nullptr;
        if (params.GetParamSet()) {
            nativeCppParamSet = GenerateHksParamArray(env, *params.GetParamSet());
            HKS_EXT_IF_TRUE_LOGE_RETURN(nativeCppParamSet == nullptr, false, "GenerateHksParamArray failed")
        } else {
            status = napi_get_undefined(env, &nativeCppParamSet);
            HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, false, "get undefined failed")
        }
        argv[ARGC_ONE] = nativeCppParamSet;

        napi_value certObj = nullptr;
        auto ret = ConvertCertInfoIdlToJsObject(env, certInfo, certObj);
        HKS_EXT_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, false, "ConvertCertInfoIdlToJsObject failed, ret:%d", ret)
        argv[ARGC_TWO] = certObj;

        argc = ARGC_THREE;
        return true;
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::IMPORT_CERTIFICATE;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onImportCertificate", jsRuntime_, jsObj_.get(), argParser, retParser);
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)

    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::InitSession(const std::string &index, const CppParamSet &params, std::string &handle,
    struct HksExternalErrorInfo **errInfo)
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    handle = std::move(dataParam->handle);
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::GenerateKey(const std::string &handle, const CppParamSet &params,
    struct HksExternalErrorInfo **errInfo)
{
    auto argParser = [handle, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct IndexInfoParam param = {
            handle,
            params,
        };
        return BuildIndexInfoParam(env, param, argv, argc);
    };

    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::GENERATE_KEY;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onGenerateKeyItem", jsRuntime_, jsObj_.get(), argParser, retParser);
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::UpdateSession(const std::string &handle, const CppParamSet &params,
    const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData, struct HksExternalErrorInfo **errInfo)
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    outData = std::move(dataParam->outData);
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::FinishSession(const std::string &handle, const CppParamSet &params,
    const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData, struct HksExternalErrorInfo **errInfo)
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    outData = std::move(dataParam->outData);
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::SetOrGetProperty(uint32_t operation, const std::string &handle,
    const std::string &propertyId, CppParamSet &params, struct HksExternalErrorInfo **errInfo)
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
    dataParam->paramType = CryptoResultParamType::SET_OR_GET_PROPERTY;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    const char *jsMethodName = (operation == HKS_EXT_PROPERTY_OPERATION_SET)
        ? "onSetProperty" : "onGetProperty";
    int32_t ret = CallJsMethod(jsMethodName, jsRuntime_, jsObj_.get(), argParser, retParser);
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    if (dataParam->paramSet.GetParamSet() == nullptr) {
        LOGE("paramSet is nullptr. HksInitParamSet:%d", HksInitParamSet(&defaultParamSet));
        dataParam->paramSet = CppParamSet(defaultParamSet, true);
    }
    params = std::move(dataParam->paramSet);

    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::ClearUkeyPinAuthState(const std::string &handle, const CppParamSet &params,
    struct HksExternalErrorInfo **errInfo)
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::ImportWrappedKey(const std::string &index, const std::string &wrappingKeyIndex,
    const CppParamSet &params, const std::vector<uint8_t> &wrappedData, struct HksExternalErrorInfo **errInfo)
{
    auto argParser = [index, wrappingKeyIndex, params, wrappedData]
        (napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct ImportWrappedKeyParam param = {
            index,
            wrappingKeyIndex,
            params,
            wrappedData,
        };
        return BuildImportWrappedKeyParam(env, param, argv, argc);
    };
    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::IMPORT_WRAPPED_KEY;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onImportWrappedKeyItem", jsRuntime_, jsObj_.get(), argParser, retParser);
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::ExportPublicKey(const std::string &index, const CppParamSet &params,
    std::vector<uint8_t> &outData, struct HksExternalErrorInfo **errInfo)
{
    auto argParser = [index, params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        struct IndexInfoParam param = {
            index,
            params,
        };
        return BuildIndexInfoParam(env, param, argv, argc);
    };
    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::EXPORT_PUBLIC_KEY;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onExportKeyItem", jsRuntime_, jsObj_.get(), argParser, retParser);
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    if (dataParam->hksErrorCode == HKS_SUCCESS) {
        outData = dataParam->outData;
    }
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
    return dataParam->hksErrorCode;
}

int32_t JsHksCryptoExtAbility::GetResourceId(const CppParamSet &params, std::string &resourceId,
    struct HksExternalErrorInfo **errInfo)
{
    auto argParser = [params](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        return BuildParam(env, params, argv, argc);
    };
    std::shared_ptr<CryptoResultParam> dataParam = std::make_shared<CryptoResultParam>();
    dataParam->paramType = CryptoResultParamType::GET_RESOURCE_ID;
    auto retParser = [dataParam](napi_env &env, napi_value result) -> bool {
        return CheckAndCallPromise(env, result, dataParam);
    };

    dataParam->callJsExMethodDone.store(false);
    auto ret = CallJsMethod("onGetResourceId", jsRuntime_, jsObj_.get(), argParser, retParser);
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != ERR_OK, ret, "CallJsMethod error, code:%d", ret)
    
    WAIT_FOR_CALL_JS_METHOD(dataParam, MAX_WAIT_TIME);
    if (dataParam->hksErrorCode == HKS_SUCCESS) {
        resourceId = dataParam->handle;
    }
    if (dataParam->errInfo != nullptr && errInfo != nullptr) {
        *errInfo = dataParam->errInfo;
        dataParam->errInfo = nullptr;
    }
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
