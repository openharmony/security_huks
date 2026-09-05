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

#include "js_ext_param_parser.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "hks_template.h"
#include "hks_mem.h"
#include "hks_external_error_info.h"
#include "hks_error_code.h"
#include "log_utils.h"
#include "hks_json_wrapper.h"
#include "securec.h"
#include "hks_ukey_common.h"

namespace OHOS {
namespace Security {
namespace Huks {

namespace {

constexpr size_t MAX_CERT_SIZE = 5 * 8196;

// ============================================================
// Common helpers (shared by all param parsers)
// ============================================================

int32_t GetStringValue(napi_env env, napi_value value, std::string &result)
{
    size_t tempSize = 0;
    auto status = napi_get_value_string_utf8(env, value, nullptr, 0, &tempSize);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        HKS_ERROR_EXT_GET_VALUE_FAILED, "get_length_string_utf8 failed, status:%d", status);
    HKS_EXT_IF_TRUE_LOGE_RETURN(tempSize > MAX_CERT_SIZE,
        HKS_ERROR_EXT_EXCEED_MAX_SIZE, "exceed the max size");
    result.reserve(tempSize + 1);
    result.resize(tempSize + 1);
    status = napi_get_value_string_utf8(env, value, result.data(), tempSize + 1, &tempSize);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        HKS_ERROR_EXT_GET_VALUE_FAILED, "get_value_string_utf8 failed, status:%d", status);
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status, "napi_get_typedarray_info failed %d", int32_t(status));
    HKS_EXT_IF_TRUE_LOGE_RETURN(type != napi_uint8_array, napi_invalid_arg, "TypeArray is not napi_uint8_array.");

    uint8_t *uint8Data = nullptr;
    void *tmp = nullptr;
    size_t byte_length = 0;
    status = napi_get_arraybuffer_info(env, array, &tmp, &byte_length);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status, "napi_get_typedarray_info %d", int32_t(status));
    uint8Data = static_cast<uint8_t*>(tmp);
    HKS_EXT_IF_TRUE_LOGE_RETURN(byte_length > UINT32_MAX, napi_invalid_arg, "byte_length is out of uint32_t.");
    result.size = static_cast<uint32_t>(byte_length);
    result.data = uint8Data;
    return napi_ok;
}

int32_t GetHksCertInfoValue(napi_env env, napi_value value, HksCertInfo &certInfo)
{
    napi_value napiPurpose = nullptr;
    auto status = napi_get_named_property(env, value, "purpose", &napiPurpose);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status, "napi_get_named_property failed, status %d", status);
    HKS_EXT_IF_TRUE_LOGE_RETURN(napiPurpose == nullptr,
        napi_invalid_arg, "napi_get_named_property get napiPurpose is nullptr.");
    status = napi_get_value_int32(env, napiPurpose, &certInfo.purpose);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status,
        "GetHksCertInfoValue js value napiPurpose failed, status %d", status);

    napi_value napiIndex = nullptr;
    status = napi_get_named_property(env, value, "resourceId", &napiIndex);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status, "napi_get_named_property failed, status %d", status);
    HKS_EXT_IF_TRUE_LOGE_RETURN(napiIndex == nullptr,
        napi_invalid_arg, "napi_get_named_property get napiIndex is nullptr.");
    auto result = GetStringValue(env, napiIndex, certInfo.index);
    HKS_EXT_IF_TRUE_LOGE_RETURN(result != HKS_SUCCESS, result,
        "GetHksCertInfoValue js value napiIndex failed, result %d", result);

    napi_value napiCerts = nullptr;
    status = napi_get_named_property(env, value, "cert", &napiCerts);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status,
        "napi_get_named_property failed, status %d", status);
    HKS_EXT_IF_TRUE_LOGE_RETURN(napiCerts == nullptr,
        napi_invalid_arg, "napi_get_named_property get napiCerts is nullptr.");
    status = GetUint8ArrayValue(env, napiCerts, certInfo.certsArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status,
        "GetHksCertInfoValue js value napiCerts failed, status %d", status);
    return napi_ok;
}

napi_status GetHksParamsfromValue(napi_env env, napi_value value, HksParam &param)
{
    napi_value napiTag = nullptr;
    auto status = napi_get_named_property(env, value, "tag", &napiTag);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status, "tag get failed, status %d", status);
    HKS_EXT_IF_TRUE_LOGE_RETURN(napiTag == nullptr,
        napi_invalid_arg, "napi_get_named_property get napiTag is nullptr.");
    status = napi_get_value_uint32(env, napiTag, &param.tag);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status, "tag get failed, status %d", status);

    napi_value napiValue = nullptr;
    status = napi_get_named_property(env, value, "value", &napiValue);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, status, "napi_get_named_property failed, status %d", status);
    HKS_EXT_IF_TRUE_LOGE_RETURN(napiValue == nullptr,
        napi_invalid_arg, "napi_get_named_property get napiValue is nullptr.");
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
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || !lossLess, status, "value get failed, lossLess: %d", lossLess);
    return napi_ok;
}

// ============================================================
// Generic property extraction helpers (reduce duplication)
// ============================================================

// Extract a required string property from a JS object.
int32_t GetRequiredStringProp(const napi_env &env, const napi_value &obj, const char *propName, std::string &out)
{
    napi_value napiVal = nullptr;
    auto status = napi_get_named_property(env, obj, propName, &napiVal);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED,
        "napi_get_named_property %s failed, status:%d", propName, status);

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, napiVal, &valueType);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || valueType != napi_string,
        HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED, "%s is not a string, type:%d", propName, valueType);

    auto result = GetStringValue(env, napiVal, out);
    HKS_EXT_IF_TRUE_LOGE_RETURN(result != HKS_SUCCESS, result,
        "Convert js %s fail, result:%d", propName, result);
    return HKS_SUCCESS;
}

// Extract a required int32 property from a JS object.
int32_t GetRequiredInt32Prop(const napi_env &env, const napi_value &obj, const char *propName, int32_t &out)
{
    napi_value napiVal = nullptr;
    auto status = napi_get_named_property(env, obj, propName, &napiVal);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED,
        "napi_get_named_property %s failed, status:%d", propName, status);

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, napiVal, &valueType);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || valueType != napi_number,
        HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED, "%s is not a number, type:%d", propName, valueType);

    status = napi_get_value_int32(env, napiVal, &out);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_VALUE_FAILED,
        "Convert js %s failed, status:%d", propName, status);
    return HKS_SUCCESS;
}

// Extract an optional int32 property from a JS object.
// If the property does not exist (undefined), returns HKS_SUCCESS and leaves out unchanged.
int32_t GetOptionalInt32Prop(const napi_env &env, const napi_value &obj,
    const char *propName, int32_t &out)
{
    napi_value napiVal = nullptr;
    auto status = napi_get_named_property(env, obj, propName, &napiVal);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_SUCCESS,
        "napi_get_named_property %s failed, status:%d", propName, status);

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, napiVal, &valueType);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || valueType == napi_undefined, HKS_SUCCESS,
        "napi_typeof %s failed or undefined, status:%d", propName, status);

    HKS_EXT_IF_TRUE_LOGE_RETURN(valueType != napi_number, HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED,
        "%s is not a number, type:%d", propName, valueType);

    status = napi_get_value_int32(env, napiVal, &out);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_VALUE_FAILED,
        "Convert js %s failed, status:%d", propName, status);
    return HKS_SUCCESS;
}

// Extract a required uint32 property from a JS object.
int32_t GetRequiredUint32Prop(const napi_env &env, const napi_value &obj,
    const char *propName, uint32_t &out)
{
    napi_value napiVal = nullptr;
    auto status = napi_get_named_property(env, obj, propName, &napiVal);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED,
        "napi_get_named_property %s failed, status:%d", propName, status);

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, napiVal, &valueType);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || valueType != napi_number,
        HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED, "%s is not a number, type:%d", propName, valueType);

    status = napi_get_value_uint32(env, napiVal, &out);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_VALUE_FAILED,
        "Convert js %s failed, status:%d", propName, status);
    return HKS_SUCCESS;
}

// Extract outData as Uint8Array typedarray.
// isRequired: if true, undefined/empty data is an error; if false, it is allowed.
int32_t GetOutDataProp(const napi_env &env, const napi_value &obj,
    std::vector<uint8_t> &outData, bool isRequired)
{
    napi_value napiOutData = nullptr;
    auto status = napi_get_named_property(env, obj, "outData", &napiOutData);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok,
        isRequired ? HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED : HKS_SUCCESS,
        "napi_get_named_property outData failed, status:%d", status);

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, napiOutData, &valueType);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_VALUE_FAILED,
        "napi_typeof outData failed, status:%d", status);

    if (valueType == napi_undefined) {
        HKS_EXT_IF_TRUE_LOGE_RETURN(isRequired, HKS_ERROR_EXT_GET_VALUE_FAILED,
            "outData is required but not provided");
        return HKS_SUCCESS;
    }

    bool isTypedArray = false;
    status = napi_is_typedarray(env, napiOutData, &isTypedArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || !isTypedArray, HKS_ERROR_EXT_GET_VALUE_FAILED,
        "outData is not a typedarray, status:%d", status);

    napi_typedarray_type type;
    napi_value nativeArray;
    size_t byte_offset;
    size_t length;
    void *data = nullptr;
    status = napi_get_typedarray_info(env, napiOutData, &type, &length, &data, &nativeArray, &byte_offset);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_VALUE_FAILED,
        "napi_get_typedarray_info failed, status:%d", status);

    HKS_EXT_IF_TRUE_LOGE_RETURN(type != napi_uint8_array, HKS_ERROR_EXT_GET_VALUE_FAILED,
        "outData is not uint8 array, type:%d", type);

    if (length == 0 || data == nullptr) {
        HKS_EXT_IF_TRUE_LOGE_RETURN(isRequired, HKS_ERROR_EXT_GET_VALUE_FAILED,
            "outData is empty or data is null");
        return HKS_SUCCESS;
    }

    outData.resize(length);
    HKS_EXT_IF_TRUE_LOGE_RETURN(memcpy_s(outData.data(), length, data, length) != EOK,
        HKS_ERROR_EXT_GET_VALUE_FAILED, "memcpy_s outData failed");
    return HKS_SUCCESS;
}

} // anonymous namespace

// ============================================================
// Error info extraction (called by all param parsers)
// ============================================================

void GetErrorInfoParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    napi_value napiErrInfo = nullptr;
    std::string errMsg = HKS_DEFAULT_ERROR_DESC;
    bool isFailed = false;
    auto status = napi_get_named_property(env, funcResult, "errInfo", &napiErrInfo);
    napi_valuetype valueType;
    status = napi_typeof(env, napiErrInfo, &valueType);

    HKS_EXT_IF_TRUE_EXCU(resultParams.errCode != 0, isFailed = true);

    HKS_EXT_IF_TRUE_LOGE_EXCU_RETURN_VOID(status != napi_ok || valueType == napi_undefined || resultParams.errCode == 0,
        resultParams.errInfo = HksCreateExternalErrorInfoWithFlag(resultParams.errCode, errMsg.c_str(), isFailed),
        "GetErrorInfoParams::errInfo not found in result");

    errMsg = "";
    napi_value napiErrno = nullptr;
    status = napi_get_named_property(env, napiErrInfo, "errno", &napiErrno);
    HKS_EXT_IF_TRUE_LOGE_EXCU_RETURN_VOID(status != napi_ok || napiErrno == nullptr,
        resultParams.errInfo = HksCreateExternalErrorInfoWithFlag(resultParams.errCode, errMsg.c_str(), true),
        "GetErrorInfoParams::napi_get_named_property errno failed, status:%d", status);
    int32_t errnoValue = 0;
    status = napi_get_value_int32(env, napiErrno, &errnoValue);
    HKS_EXT_IF_TRUE_LOGE_EXCU_RETURN_VOID(status != napi_ok,
        resultParams.errInfo = HksCreateExternalErrorInfoWithFlag(resultParams.errCode, errMsg.c_str(), true),
        "GetErrorInfoParams::get errno value failed, status:%d", status);
    napi_value napiErrorDesc = nullptr;
    status = napi_get_named_property(env, napiErrInfo, "errorDesc", &napiErrorDesc);
    HKS_EXT_IF_TRUE_LOGE_EXCU_RETURN_VOID(status != napi_ok || napiErrorDesc == nullptr,
        resultParams.errInfo = HksCreateExternalErrorInfoWithFlag(resultParams.errCode, errMsg.c_str(), true),
        "GetErrorInfoParams::napi_get_named_property errorDesc failed, status:%d", status);
    std::string errorDesc;
    auto result = GetStringValue(env, napiErrorDesc, errorDesc);
    HKS_EXT_IF_TRUE_LOGE_EXCU_RETURN_VOID(result != HKS_SUCCESS,
        resultParams.errInfo = HksCreateExternalErrorInfoWithFlag(resultParams.errCode, errMsg.c_str(), true),
        "GetErrorInfoParams::GetStringValue errorDesc failed, result:%d", result);
    resultParams.errInfo = HksCreateExternalErrorInfoWithFlag(errnoValue, errorDesc.c_str(), true);
    HKS_EXT_IF_TRUE_LOGE(resultParams.errInfo == nullptr, "GetErrorInfoParams::CreateExternalErrorInfo failed");
}

// ============================================================
// Per-operation param parsers
// ============================================================

int32_t GetOpenRemoteHandleParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    HKS_EXT_IF_TRUE_RETURN(resultParams.errCode != 0, HKS_SUCCESS);
    return GetRequiredStringProp(env, funcResult, "handle", resultParams.handle);
}

int32_t GetResourceIdParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    HKS_EXT_IF_TRUE_RETURN(resultParams.errCode != 0, HKS_SUCCESS);
    return GetRequiredStringProp(env, funcResult, "resourceId", resultParams.handle);
}

int32_t GetAuthUkeyPinParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    HKS_EXT_IF_TRUE_RETURN(resultParams.errCode != 0 && resultParams.errCode != EXTENSION_ERRCODE_PIN_CODE_ERROR,
        HKS_SUCCESS);
    // retryCount: required
    int32_t ret = GetRequiredUint32Prop(env, funcResult, "retryCount", resultParams.retryCnt);
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "GetAuthUkeyPinParams: retryCount failed");
    // Convert retryCnt via int32 path for consistency with original code
    resultParams.retryCnt = static_cast<uint32_t>(resultParams.retryCnt);

    // authState: optional
    return GetOptionalInt32Prop(env, funcResult, "authState", resultParams.authState);
}

int32_t GetUkeyPinAuthStateParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    HKS_EXT_IF_TRUE_RETURN(resultParams.errCode != 0, HKS_SUCCESS);
    return GetRequiredInt32Prop(env, funcResult, "authState", resultParams.authState);
}

int32_t GetExportCertificateParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    HKS_EXT_IF_TRUE_RETURN(resultParams.errCode != 0, HKS_SUCCESS);
    napi_value nativeArray = nullptr;
    auto status = napi_get_named_property(env, funcResult, "certs", &nativeArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED,
        "napi_get_named_property certs failed, status:%d", status);

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, nativeArray, &valueType);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || valueType != napi_object,
        HKS_ERROR_EXT_GET_VALUE_FAILED, "certs is not an object(array), type:%d", valueType);

    bool isArray = false;
    status = napi_is_array(env, nativeArray, &isArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || !isArray,
        HKS_ERROR_EXT_GET_VALUE_FAILED, "certs is not an array, status:%d", status);

    uint32_t length = 0;
    status = napi_get_array_length(env, nativeArray, &length);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_VALUE_FAILED,
        "Get array length fail, status:%d", status);

    for (uint32_t i = 0; i < length; i++) {
        napi_value queryResult = nullptr;
        status = napi_get_element(env, nativeArray, i, &queryResult);
        HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_VALUE_FAILED,
            "napi_get_element fail, index:%d, status:%d", i, status);

        HksCertInfo certInfo;
        auto result = GetHksCertInfoValue(env, queryResult, certInfo);
        HKS_EXT_IF_TRUE_LOGE_RETURN(result != napi_ok, HKS_ERROR_EXT_RETURN_VALUE_INCORRECT,
            "Convert js certInfo fail, index:%d, result:%d", i, result);
        resultParams.certs.emplace_back(std::move(certInfo));
    }
    return HKS_SUCCESS;
}

int32_t GetSessionParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    HKS_EXT_IF_TRUE_RETURN(resultParams.errCode != 0, HKS_SUCCESS);
    return GetOutDataProp(env, funcResult, resultParams.outData, false);
}

int32_t GetExportPublicKeyParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    HKS_EXT_IF_TRUE_RETURN(resultParams.errCode != 0, HKS_SUCCESS);
    return GetOutDataProp(env, funcResult, resultParams.outData, true);
}

int32_t GetGetPropertyParams(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    HKS_EXT_IF_TRUE_RETURN(resultParams.errCode != 0, HKS_SUCCESS);
    napi_value nativeArray = nullptr;
    auto status = napi_get_named_property(env, funcResult, "property", &nativeArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED,
        "napi_get_named_property property failed, status:%d", status);

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, nativeArray, &valueType);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_VALUE_FAILED,
        "napi_typeof property failed, status:%d", status);

    HKS_EXT_IF_TRUE_RETURN(valueType == napi_undefined, HKS_SUCCESS);

    bool isArray = false;
    status = napi_is_array(env, nativeArray, &isArray);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok || !isArray,
        HKS_ERROR_EXT_GET_VALUE_FAILED, "property is not an array, status:%d", status);

    uint32_t length = 0;
    status = napi_get_array_length(env, nativeArray, &length);
    HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_VALUE_FAILED,
        "Get array length fail, status:%d", status);

    std::vector<HksParam> paramVec {};
    for (uint32_t i = 0; i < length; ++i) {
        napi_value queryResult = nullptr;
        status = napi_get_element(env, nativeArray, i, &queryResult);
        HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_GET_VALUE_FAILED,
            "napi_get_element fail, index:%d, status:%d", i, status);

        HksParam param;
        status = GetHksParamsfromValue(env, queryResult, param);
        HKS_EXT_IF_TRUE_LOGE_RETURN(status != napi_ok, HKS_ERROR_EXT_RETURN_VALUE_INCORRECT,
            "Convert js param fail, index:%d, status:%d", i, status);
        paramVec.emplace_back(std::move(param));
    }

    CppParamSet cppParamSetTemp(paramVec);
    int32_t ret = HksCheckParamSetTag(cppParamSetTemp.GetParamSet());
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, HKS_ERROR_EXT_RETURN_VALUE_INCORRECT, "HksCheckParamSetTag failed");
    resultParams.paramSet = std::move(cppParamSetTemp);
    return HKS_SUCCESS;
}

// ============================================================
// Dispatch: resultCode + per-type parser
// ============================================================

int32_t ConvertFunctionResult(const napi_env &env, const napi_value &funcResult, CryptoResultParam &resultParams)
{
    HKS_EXT_IF_TRUE_LOGE_RETURN(funcResult == nullptr, HKS_ERROR_EXT_NULLPTR, "The funcResult is error.");

    int32_t ret = GetRequiredInt32Prop(env, funcResult, "resultCode", resultParams.errCode);
    HKS_EXT_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "ConvertFunctionResult: resultCode failed");

    GetErrorInfoParams(env, funcResult, resultParams);

    switch (resultParams.paramType) {
        case CryptoResultParamType::OPEN_REMOTE_HANDLE:
        case CryptoResultParamType::INIT_SESSION:
            return GetOpenRemoteHandleParams(env, funcResult, resultParams);
        case CryptoResultParamType::GET_RESOURCE_ID:
            return GetResourceIdParams(env, funcResult, resultParams);
        case CryptoResultParamType::AUTH_UKEY_PIN:
            return GetAuthUkeyPinParams(env, funcResult, resultParams);
        case CryptoResultParamType::GET_UKEY_PIN_AUTH_STATE:
            return GetUkeyPinAuthStateParams(env, funcResult, resultParams);
        case CryptoResultParamType::EXPORT_CERTIFICATE:
        case CryptoResultParamType::EXPORT_PROVIDER_CERTIFICATES:
            return GetExportCertificateParams(env, funcResult, resultParams);
        case CryptoResultParamType::UPDATE_SESSION:
        case CryptoResultParamType::FINISH_SESSION:
            return GetSessionParams(env, funcResult, resultParams);
        case CryptoResultParamType::EXPORT_PUBLIC_KEY:
            return GetExportPublicKeyParams(env, funcResult, resultParams);
        case CryptoResultParamType::SET_OR_GET_PROPERTY:
            return GetGetPropertyParams(env, funcResult, resultParams);
        default:
            break;
    }
    return HKS_SUCCESS;
}

} // namespace Huks
} // namespace Security
} // namespace OHOS
