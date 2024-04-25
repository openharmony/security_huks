/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "huks_napi_common_item.h"

#include <string>
#include <vector>

#include "hks_errcode_adapter.h"
#include "hks_log.h"
#include "hks_param.h"
#include "hks_type.h"
#include "securec.h"

namespace HuksNapiItem {
namespace {
constexpr int HKS_MAX_DATA_LEN = 0x6400000; // The maximum length is 100M
constexpr size_t ASYNCCALLBACK_ARGC = 2;
}  // namespace

napi_value ParseKeyAlias(napi_env env, napi_value object, HksBlob *&alias)
{
    napi_valuetype valueType = napi_valuetype::napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &valueType));

    if (valueType != napi_valuetype::napi_string) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "the type of alias isn't string");
        HKS_LOG_E("no string type");
        return nullptr;
    }

    size_t length = 0;
    napi_status status = napi_get_value_string_utf8(env, object, nullptr, 0, &length);
    if (status != napi_ok) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get string length");
        HKS_LOG_E("could not get string length %" LOG_PUBLIC "d", status);
        return nullptr;
    }

    if (length > HKS_MAX_DATA_LEN) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "the length of alias is too long");
        HKS_LOG_E("input key alias length %" LOG_PUBLIC "zu too large", length);
        return nullptr;
    }

    char *data = static_cast<char *>(HksMalloc(length + 1));
    if (data == nullptr) {
        HksNapiThrowInsufficientMemory(env);
        HKS_LOG_E("could not alloc memory");
        return nullptr;
    }
    (void)memset_s(data, length + 1, 0, length + 1);

    size_t result = 0;
    status = napi_get_value_string_utf8(env, object, data, length + 1, &result);
    if (status != napi_ok) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get string");
        HKS_FREE(data);
        HKS_LOG_E("could not get string %" LOG_PUBLIC "d", status);
        return nullptr;
    }

    alias = static_cast<HksBlob *>(HksMalloc(sizeof(HksBlob)));
    if (alias == nullptr) {
        HksNapiThrowInsufficientMemory(env);
        HKS_FREE(data);
        HKS_LOG_E("could not alloc memory");
        return nullptr;
    }
    alias->data = reinterpret_cast<uint8_t *>(data);
    alias->size = static_cast<uint32_t>(length & UINT32_MAX);

    return GetInt32(env, 0);
}

napi_value GetUint8Array(napi_env env, napi_value object, HksBlob &arrayBlob)
{
    napi_typedarray_type arrayType;
    napi_value arrayBuffer = nullptr;
    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;

    NAPI_CALL(
        env, napi_get_typedarray_info(env, object, &arrayType, &length, &rawData, &arrayBuffer, &offset));
    if (arrayType != napi_uint8_array) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            "the type of data is not Uint8Array");
        HKS_LOG_E("the type of  data is not Uint8Array");
        return nullptr;
    }

    if (length > HKS_MAX_DATA_LEN) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            "the length of data is too long");
        HKS_LOG_E("data len is too large, len = %" LOG_PUBLIC "zx", length);
        return nullptr;
    }
    if (length == 0) {
        HKS_LOG_I("the created memory length just 1 Byte");
        // the created memory length just 1 Byte
        arrayBlob.data = static_cast<uint8_t *>(HksMalloc(1));
    } else {
        arrayBlob.data = static_cast<uint8_t *>(HksMalloc(length));
    }
    if (arrayBlob.data == nullptr) {
        return nullptr;
    }

    (void)memcpy_s(arrayBlob.data, length, rawData, length);
    arrayBlob.size = static_cast<uint32_t>(length);

    return GetInt32(env, 0);
}

static napi_value CheckParamValueType(napi_env env, uint32_t tag, napi_value value)
{
    napi_value result = nullptr;
    napi_valuetype valueType = napi_valuetype::napi_undefined;
    NAPI_CALL(env, napi_typeof(env, value, &valueType));

    switch (tag & HKS_TAG_TYPE_MASK) {
        case HKS_TAG_TYPE_INT:
            if (valueType == napi_valuetype::napi_number) {
                result = GetInt32(env, 0);
            }
            break;
        case HKS_TAG_TYPE_UINT:
            if (valueType == napi_valuetype::napi_number) {
                result = GetInt32(env, 0);
            }
            break;
        case HKS_TAG_TYPE_ULONG:
            if (valueType == napi_valuetype::napi_number) {
                result = GetInt32(env, 0);
            }
            break;
        case HKS_TAG_TYPE_BOOL:
            if (valueType == napi_valuetype::napi_boolean) {
                result = GetInt32(env, 0);
            }
            break;
        case HKS_TAG_TYPE_BYTES:
            if (valueType == napi_valuetype::napi_object) {
                result = GetInt32(env, 0);
            }
            break;
        default:
            HKS_LOG_E("invalid tag value 0x%" LOG_PUBLIC "x", tag);
            break;
    }

    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            "the value of the tag is of an incorrect type");
        HKS_LOG_E("invalid tag or the type of value, tag = 0x%" LOG_PUBLIC "x, type = %" LOG_PUBLIC "u",
            tag, valueType);
    }
    return result;
}

static napi_value GetHksParam(napi_env env, napi_value object, HksParam &param)
{
    napi_value tag = GetPropertyFromOptions(env, object, HKS_PARAM_PROPERTY_TAG);
    if (tag == nullptr) {
        HKS_LOG_E("get param tag failed");
        return nullptr;
    }
    NAPI_CALL(env, napi_get_value_uint32(env, tag, &param.tag));

    napi_value value = GetPropertyFromOptions(env, object, HKS_PARAM_PROPERTY_VALUE);
    if (value == nullptr) {
        HKS_LOG_E("get param value failed");
        return nullptr;
    }

    if (CheckParamValueType(env, param.tag, value) == nullptr) {
        return nullptr;
    }

    napi_value result = nullptr;
    switch (param.tag & HKS_TAG_TYPE_MASK) {
        case HKS_TAG_TYPE_INT:
            NAPI_CALL(env, napi_get_value_int32(env, value, &param.int32Param));
            result = GetInt32(env, 0);
            break;
        case HKS_TAG_TYPE_UINT:
            NAPI_CALL(env, napi_get_value_uint32(env, value, &param.uint32Param));
            result = GetInt32(env, 0);
            break;
        case HKS_TAG_TYPE_ULONG:
            NAPI_CALL(env, napi_get_value_int64(env, value, reinterpret_cast<int64_t *>(&param.uint64Param)));
            result = GetInt32(env, 0);
            break;
        case HKS_TAG_TYPE_BOOL:
            NAPI_CALL(env, napi_get_value_bool(env, value, &param.boolParam));
            result = GetInt32(env, 0);
            break;
        case HKS_TAG_TYPE_BYTES:
            result = GetUint8Array(env, value, param.blob);
            if (result == nullptr) {
                HKS_LOG_E("get uint8 array fail.");
            } else {
                HKS_LOG_D("tag 0x%" LOG_PUBLIC "x, len 0x%" LOG_PUBLIC "x", param.tag, param.blob.size);
            }
            break;
        default:
            HKS_LOG_E("invalid tag value 0x%" LOG_PUBLIC "x", param.tag);
            break;
    }

    return result;
}

void FreeParsedParams(std::vector<HksParam> &params)
{
    for (HksParam &p : params) {
        if (GetTagType(static_cast<HksTag>(p.tag)) == HKS_TAG_TYPE_BYTES) {
            HKS_FREE_BLOB(p.blob);
        }
    }
}

napi_value ParseParams(napi_env env, napi_value object, std::vector<HksParam> &params)
{
    bool hasNextElement = false;
    napi_value result = nullptr;
    size_t index = 0;
    while ((napi_has_element(env, object, index, &hasNextElement) == napi_ok) && hasNextElement) {
        napi_value element = nullptr;
        NAPI_CALL(env, napi_get_element(env, object, index, &element));

        HksParam param = { 0 };
        result = GetHksParam(env, element, param);
        if (result == nullptr) {
            HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "GetHksParam fail");
            HKS_LOG_E("get param failed when parse input params.");
            return nullptr;
        }

        params.push_back(param);
        index++;
    }
    return GetInt32(env, 0);
}

napi_value ParseHksParamSetAndAddParam(napi_env env, napi_value object, HksParamSet *&paramSet,
    const std::vector<HksParam> &addParams)
{
    if (paramSet != nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "paramSet is nullptr");
        HKS_LOG_E("param input invalid");
        return nullptr;
    }

    std::vector<HksParam> params{};
    HksParamSet *outParamSet = nullptr;
    do {
        if (HksInitParamSet(&outParamSet) != HKS_SUCCESS) {
            HksNapiThrowInsufficientMemory(env);
            HKS_LOG_E("paramset init failed");
            break;
        }

        if (ParseParams(env, object, params) == nullptr) {
            HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "ParseParams fail");
            HKS_LOG_E("parse params failed");
            break;
        }

        if (!addParams.empty()) {
            // the memory of some blobs in addParams is allocated before stepping into current function,
            // and we will FreeParsedParams(params) later, therefore we can not append addParams into params.
            if (HksAddParams(outParamSet, addParams.data(), addParams.size()) != HKS_SUCCESS) {
                HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "HksAddParams addParams fail");
                HKS_LOG_E("add params addParams failed");
                break;
            }
        }

        if (!params.empty()) {
            if (HksAddParams(outParamSet, params.data(), params.size()) != HKS_SUCCESS) {
                HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "HksAddParams fail");
                HKS_LOG_E("add params failed");
                break;
            }
        }

        if (HksBuildParamSet(&outParamSet) != HKS_SUCCESS) {
            HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "HksBuildParamSet fail");
            HKS_LOG_E("HksBuildParamSet failed");
            break;
        }

        FreeParsedParams(params);
        paramSet = outParamSet;
        return GetInt32(env, 0);
    } while (0);

    HksFreeParamSet(&outParamSet);
    FreeParsedParams(params);
    return nullptr;
}

napi_value ParseHksParamSetWithToken(napi_env env, struct HksBlob *&token, napi_value object, HksParamSet *&paramSet)
{
    std::vector<HksParam> params {};
    if (CheckBlob(token) == HKS_SUCCESS) { /* has token param */
        params.emplace_back(HksParam{
            .tag = HKS_TAG_AUTH_TOKEN,
            .blob = *token
        });
    }
    return ParseHksParamSetAndAddParam(env, object, paramSet, params);
}

napi_ref GetCallback(napi_env env, napi_value object)
{
    napi_valuetype valueType = napi_valuetype::napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &valueType));

    if (valueType != napi_valuetype::napi_function) {
        HKS_LOG_I("no callback fun, process as promise func");
        return nullptr;
    }

    napi_ref ref = nullptr;
    napi_status status = napi_create_reference(env, object, 1, &ref);
    if (status != napi_ok) {
        HKS_LOG_E("could not create reference");
        return nullptr;
    }
    return ref;
}

static napi_value GenerateArrayBuffer(napi_env env, uint8_t *data, uint32_t size)
{
    uint8_t *buffer = static_cast<uint8_t *>(HksMalloc(size));
    if (buffer == nullptr) {
        return nullptr;
    }

    napi_value outBuffer = nullptr;
    (void)memcpy_s(buffer, size, data, size);

    napi_status status = napi_create_external_arraybuffer(
        env, buffer, size, [](napi_env env, void *data, void *hint) { HKS_FREE(data); }, nullptr, &outBuffer);
    if (status == napi_ok) {
        // free by finalize callback
        buffer = nullptr;
    } else {
        HKS_FREE(buffer);
    }

    return outBuffer;
}

static napi_value GenerateHksParam(napi_env env, const HksParam &param)
{
    napi_value hksParam = nullptr;
    NAPI_CALL(env, napi_create_object(env, &hksParam));

    napi_value tag = nullptr;
    NAPI_CALL(env, napi_create_uint32(env, param.tag, &tag));
    NAPI_CALL(env, napi_set_named_property(env, hksParam, HKS_PARAM_PROPERTY_TAG.c_str(), tag));

    napi_value value = nullptr;
    switch (param.tag & HKS_TAG_TYPE_MASK) {
        case HKS_TAG_TYPE_INT:
            NAPI_CALL(env, napi_create_int32(env, param.int32Param, &value));
            break;
        case HKS_TAG_TYPE_UINT:
            NAPI_CALL(env, napi_create_uint32(env, param.uint32Param, &value));
            break;
        case HKS_TAG_TYPE_ULONG:
            NAPI_CALL(env, napi_create_int64(env, param.uint64Param, &value));
            break;
        case HKS_TAG_TYPE_BOOL:
            NAPI_CALL(env, napi_get_boolean(env, param.boolParam, &value));
            break;
        case HKS_TAG_TYPE_BYTES:
            value = GenerateArrayBuffer(env, param.blob.data, param.blob.size);
            break;
        default:
            value = GetNull(env);
            break;
    }
    NAPI_CALL(env, napi_set_named_property(env, hksParam, HKS_PARAM_PROPERTY_VALUE.c_str(), value));

    return hksParam;
}

static napi_value GenerateHksParamArray(napi_env env, const HksParamSet &paramSet)
{
    napi_value paramArray = nullptr;
    NAPI_CALL(env, napi_create_array(env, &paramArray));

    for (uint32_t i = 0; i < paramSet.paramsCnt; i++) {
        napi_value element = nullptr;
        element = GenerateHksParam(env, paramSet.params[i]);
        napi_set_element(env, paramArray, i, element);
    }

    return paramArray;
}

static napi_value GenerateStringArray(napi_env env, const struct HksBlob *blob, uint32_t blobCount)
{
    if (blobCount == 0 || blob == nullptr) {
        return nullptr;
    }
    napi_value array = nullptr;
    NAPI_CALL(env, napi_create_array(env, &array));
    for (uint32_t i = 0; i < blobCount; i++) {
        napi_value element = nullptr;
        napi_create_string_latin1(env, (const char *)blob[i].data, blob[i].size, &element);
        napi_set_element(env, array, i, element);
    }
    return array;
}

void FreeHksCertChain(HksCertChain *&certChain, uint32_t certChainCapacity)
{
    if (certChain == nullptr) {
        return;
    }

    if (certChainCapacity > 0 && certChain->certs != nullptr) {
        for (uint32_t i = 0; i < certChainCapacity; i++) {
            if (certChain->certs[i].data != nullptr) {
                HKS_FREE(certChain->certs[i].data);
                certChain->certs[i].data = nullptr;
            }
        }
    }
    HKS_FREE(certChain->certs);
    HKS_FREE(certChain);
    certChain = nullptr;
}

void FreeHksKeyAliasSet(HksKeyAliasSet *&keyAliasSet, uint32_t cnt)
{
    if (keyAliasSet == nullptr) {
        return;
    }

    if (cnt > 0 && keyAliasSet->aliases != nullptr) {
        for (uint32_t i = 0; i < cnt; i++) {
            HKS_FREE_BLOB(keyAliasSet->aliases[i]);
        }
    }
    HKS_FREE(keyAliasSet->aliases);
    HKS_FREE(keyAliasSet);
    keyAliasSet = nullptr;
}

napi_value GetHandleValue(napi_env env, napi_value object, struct HksBlob *&handleBlob)
{
    if (handleBlob != nullptr) {
        HKS_LOG_E("param input invalid");
        return nullptr;
    }

    napi_valuetype valueType = napi_valuetype::napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &valueType));

    if (valueType != napi_valuetype::napi_number) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            "the type of handle isn't number");
        return nullptr;
    }

    uint32_t handleTmp = 0;
    napi_status status = napi_get_value_uint32(env, object, &handleTmp);
    if (status != napi_ok) {
        HKS_LOG_E("Retrieve field failed");
        return nullptr;
    }

    uint64_t handle = static_cast<uint64_t>(handleTmp);

    handleBlob = static_cast<struct HksBlob *>(HksMalloc(sizeof(struct HksBlob)));
    if (handleBlob == nullptr) {
        HKS_LOG_E("could not alloc memory");
        return nullptr;
    }

    handleBlob->data = static_cast<uint8_t *>(HksMalloc(sizeof(uint64_t)));
    if (handleBlob->data == nullptr) {
        HKS_FREE(handleBlob);
        HKS_LOG_E("could not alloc memory");
        return nullptr;
    }
    handleBlob->size = sizeof(uint64_t);

    if (memcpy_s(handleBlob->data, sizeof(uint64_t), &handle, sizeof(uint64_t)) != EOK) {
        // the memory of handleBlob free by finalize callback
        return nullptr;
    }

    return GetInt32(env, 0);
}

napi_value GetUserIdValue(napi_env env, napi_value object, int &userId)
{
    napi_valuetype valueType = napi_valuetype::napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &valueType));

    if (valueType != napi_valuetype::napi_number) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "the type of userId isn't number");
        HKS_LOG_E("valueType %" LOG_PUBLIC "d not napi_number", valueType);
        return nullptr;
    }

    napi_status status = napi_get_value_int32(env, object, &userId);
    if (status != napi_ok) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "get int32 userId failed");
        HKS_LOG_E("get int32 userId failed %" LOG_PUBLIC "d", status);
        return nullptr;
    }

    return GetInt32(env, 0);
}

void DeleteCommonAsyncContext(napi_env env, napi_async_work &asyncWork, napi_ref &callback,
    struct HksBlob *&blob, struct HksParamSet *&paramSet)
{
    if (asyncWork != nullptr) {
        napi_delete_async_work(env, asyncWork);
        asyncWork = nullptr;
    }

    if (callback != nullptr) {
        napi_delete_reference(env, callback);
        callback = nullptr;
    }

    if (blob != nullptr) {
        FreeHksBlob(blob);
    }

    if (paramSet != nullptr) {
        HksFreeParamSet(&paramSet);
    }
}

napi_value GetPropertyFromOptions(napi_env env, napi_value value, const std::string propertyStr)
{
    napi_valuetype valueType = napi_valuetype::napi_undefined;
    NAPI_CALL(env, napi_typeof(env, value, &valueType));

    if (valueType != napi_valuetype::napi_object) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            "the type is not object");
        HKS_LOG_E("no object type");
        return nullptr;
    }

    napi_value property = nullptr;
    napi_status status = napi_get_named_property(env, value,
        propertyStr.c_str(), &property);
    if (status != napi_ok || property == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT,
            "get value failed, maybe the target does not exist");
        HKS_LOG_E("could not get property %" LOG_PUBLIC "s", propertyStr.c_str());
        return nullptr;
    }

    return property;
}

napi_value ParseGetHksParamSet(napi_env env, napi_value value, HksParamSet *&paramSet)
{
    napi_value property = GetPropertyFromOptions(env, value, HKS_OPTIONS_PROPERTY_PROPERTIES);
    if (property == nullptr) {
        return nullptr;
    }

    napi_value result = ParseHksParamSetAndAddParam(env, property, paramSet);
    if (result == nullptr) {
        HKS_LOG_E("could not get paramset");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static napi_value ParseGetHksParamSetAsUser(napi_env env, int userId, napi_value value, HksParamSet *&paramSet)
{
    napi_value property = GetPropertyFromOptions(env, value, HKS_OPTIONS_PROPERTY_PROPERTIES);
    if (property == nullptr) {
        return nullptr;
    }

    napi_value result = ParseHksParamSetAndAddParam(env, property, paramSet,
        {{.tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = userId}});
    if (result == nullptr) {
        HKS_LOG_E("could not get paramset");
        return nullptr;
    }

    return GetInt32(env, 0);
}

napi_value ParseKeyAliasAndHksParamSet(napi_env env, napi_value *argv, size_t &index,
    HksBlob *&keyAliasBlob, HksParamSet *&paramSet)
{
    // the index is controlled by the caller and needs to ensure that it does not overflow
    if (argv == nullptr || keyAliasBlob != nullptr || paramSet != nullptr) {
        HKS_LOG_E("param input invalid");
        return nullptr;
    }

    napi_value result = ParseKeyAlias(env, argv[index], keyAliasBlob);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get key alias");
        HKS_LOG_E("could not get keyAlias");
        return nullptr;
    }

    index++;
    result = ParseGetHksParamSet(env, argv[index], paramSet);
    if (result == nullptr) {
        HKS_LOG_E("get hksParamSet failed");
        return nullptr;
    }

    return GetInt32(env, 0);
}

napi_value ParseKeyAliasAndHksParamSetAsUser(napi_env env, int userId, napi_value *argv, size_t &index,
    std::pair<HksBlob *&, HksParamSet *&> out)
{
    auto &[ keyAliasBlob, paramSet ] = out;
    // the index is controlled by the caller and needs to ensure that it does not overflow
    if (argv == nullptr || keyAliasBlob != nullptr || paramSet != nullptr) {
        HKS_LOG_E("param input invalid");
        return nullptr;
    }

    napi_value result = ParseKeyAlias(env, argv[index], keyAliasBlob);
    if (result == nullptr) {
        HksNapiThrow(env, HUKS_ERR_CODE_ILLEGAL_ARGUMENT, "could not get key alias");
        HKS_LOG_E("could not get keyAlias");
        return nullptr;
    }

    index++;
    result = ParseGetHksParamSetAsUser(env, userId, argv[index], paramSet);
    if (result == nullptr) {
        HKS_LOG_E("get hksParamSet failed");
        return nullptr;
    }

    return GetInt32(env, 0);
}

napi_value ParseKeyData(napi_env env, napi_value value, HksBlob *&keyDataBlob)
{
    if (keyDataBlob != nullptr) {
        HKS_LOG_E("param input invalid");
        return nullptr;
    }

    napi_value inData = GetPropertyFromOptions(env, value, HKS_OPTIONS_PROPERTY_INDATA);
    if (inData == nullptr) {
        HKS_LOG_E("get indata property failed");
        return nullptr;
    }

    keyDataBlob = static_cast<struct HksBlob *>(HksMalloc(sizeof(HksBlob)));
    if (keyDataBlob == nullptr) {
        HKS_LOG_E("could not alloc memory");
        return nullptr;
    }
    (void)memset_s(keyDataBlob, sizeof(HksBlob), 0, sizeof(HksBlob));

    if (GetUint8Array(env, inData, *keyDataBlob) == nullptr) {
        FreeHksBlob(keyDataBlob);
        HKS_LOG_E("could not get indata");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static napi_value AddHandleOrChallenge(napi_env env, napi_value &object,
    const struct HksBlob *handle, const struct HksBlob *challenge)
{
    napi_value addResult = nullptr;

    // add handle
    if ((handle != nullptr) && (handle->data != nullptr) && (handle->size == sizeof(uint64_t))) {
        void *handleData = static_cast<void *>(handle->data);
        uint64_t tempHandle = *(static_cast<uint64_t *>(handleData));
        uint32_t handleValue = static_cast<uint32_t>(tempHandle); /* Temporarily only use 32 bit handle */
        napi_value handlejs = nullptr;
        NAPI_CALL(env, napi_create_uint32(env, handleValue, &handlejs));
        NAPI_CALL(env, napi_set_named_property(env, object, HKS_HANDLE_PROPERTY_HANDLE.c_str(), handlejs));
        addResult = GetInt32(env, 0);
    }

    // add challenge
    if ((challenge != nullptr) && (challenge->size != 0) && (challenge->data != nullptr)) {
        napi_value challengejs = nullptr;
        napi_value outBuffer = GenerateArrayBuffer(env, challenge->data, challenge->size);
        if (outBuffer == nullptr) {
            HKS_LOG_E("add token failed");
            return nullptr;
        }

        NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, challenge->size, outBuffer, 0, &challengejs));
        NAPI_CALL(env, napi_set_named_property(env, object, HKS_HANDLE_PROPERTY_CHALLENGE.c_str(), challengejs));
        addResult = GetInt32(env, 0);
    }

    return addResult;
}

static napi_value AddOutDataParamSetOrCertChain(napi_env env, napi_value &object,
    const struct HksBlob *outData, const HksParamSet *paramSet, const struct HksCertChain *certChain)
{
    napi_value addResult = nullptr;

    // add outData
    if ((outData != nullptr) && (outData->data != nullptr) && (outData->size != 0)) {
        napi_value outDataJs = nullptr;
        napi_value outBuffer = GenerateArrayBuffer(env, outData->data, outData->size);
        if (outBuffer == nullptr) {
            HKS_LOG_E("add outData failed");
            return nullptr;
        }
        NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, outData->size, outBuffer, 0, &outDataJs));
        NAPI_CALL(env, napi_set_named_property(env, object, HKS_RESULT_PROPERTY_OUTDATA.c_str(), outDataJs));
        addResult = GetInt32(env, 0);
    }

    // add paramSet
    if (paramSet != nullptr) {
        napi_value properties = nullptr;
        properties = GenerateHksParamArray(env, *paramSet);
        if (properties == nullptr) {
            HKS_LOG_E("add paramSet failed");
            return nullptr;
        }
        NAPI_CALL(env, napi_set_named_property(env, object, HKS_RESULT_PRPPERTY_PROPERTIES.c_str(), properties));
        addResult = GetInt32(env, 0);
    }

    // add certChain
    if ((certChain != nullptr) && (certChain->certs != nullptr) && (certChain->certsCount != 0)) {
        napi_value certChainJs = GenerateStringArray(env, certChain->certs, certChain->certsCount);
        if (certChainJs == nullptr) {
            HKS_LOG_E("add certChain failed");
            return nullptr;
        }
        NAPI_CALL(env, napi_set_named_property(env, object, HKS_RESULT_PRPPERTY_CERTCHAINS.c_str(), certChainJs));
        addResult = GetInt32(env, 0);
    }

    return addResult;
}

static napi_value GenerateResult(napi_env env, const struct HksSuccessReturnResult resultData)
{
    napi_value result = nullptr;

    if (resultData.isOnlyReturnBoolResult) {
        if (napi_get_boolean(env, resultData.boolReturned, &result) != napi_ok) {
            return GetNull(env);
        }
        return result;
    }

    if (napi_create_object(env, &result) != napi_ok) {
        return GetNull(env);
    }

    napi_value status1 = AddHandleOrChallenge(env, result, resultData.handle, resultData.challenge);
    napi_value status2 = AddOutDataParamSetOrCertChain(env, result,
        resultData.outData, resultData.paramSet, resultData.certChain);
    if (status1 == nullptr && status2 == nullptr) {
        return GetNull(env);
    }

    return result;
}

static napi_value GenerateBusinessError(napi_env env, int32_t errorCode)
{
    napi_value businessError = nullptr;
    napi_status status = napi_create_object(env, &businessError);
    if (status != napi_ok) {
        HKS_LOG_E("create object failed");
        return GetNull(env);
    }

    struct HksResult errInfo = HksConvertErrCode(errorCode);
    // add errorCode
    napi_value code = nullptr;
    status = napi_create_int32(env, errInfo.errorCode, &code);
    if (status != napi_ok || code == nullptr) {
        code = GetNull(env);
    }
    status = napi_set_named_property(env, businessError, BUSINESS_ERROR_PROPERTY_CODE.c_str(), code);
    if (status != napi_ok) {
        HKS_LOG_E("set errorCode failed");
        return GetNull(env);
    }

    // add errorMessage
    napi_value msg = GetNull(env);
    if (errInfo.errorMsg != nullptr) {
#ifdef HUKS_NAPI_ERRORCODE_WITH_MESSAGE
        uint32_t errorMsgLen = strlen(errInfo.errorMsg);
        uint8_t errorMsgBuf[errorMsgLen];
        (void)memcpy_s(errorMsgBuf, errorMsgLen, errInfo.errorMsg, errorMsgLen);
        struct HksBlob msgBlob = { errorMsgLen, errorMsgBuf };
        msg = GenerateStringArray(env, &msgBlob, 1);
        msg = ((msg == nullptr) ? GetNull(env) : msg);
#endif
    }
    status = napi_set_named_property(env, businessError, BUSINESS_ERROR_PROPERTY_MESSAGE.c_str(), msg);
    if (status != napi_ok) {
        HKS_LOG_E("set errorMsg failed");
        return GetNull(env);
    }

    // add errorData
    napi_value data = GetNull(env);
    status = napi_set_named_property(env, businessError, BUSINESS_ERROR_PROPERTY_DATA.c_str(), data);
    if (status != napi_ok) {
        HKS_LOG_E("set errorData failed");
        return GetNull(env);
    }

    return businessError;
}

static void CallbackResultFailure(napi_env env, napi_ref callback, int32_t error)
{
    if (error == HKS_SUCCESS) {
        HKS_LOG_E("callback: failure cannot be executed");
        return;
    }

    napi_value func = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, callback, &func));

    napi_value recv = nullptr;
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &recv));

    napi_value businessError = GenerateBusinessError(env, error);
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, recv, func, 1, &businessError, &result));
}

static void CallbackResultSuccess(napi_env env, napi_ref callback, const struct HksSuccessReturnResult resultData)
{
    napi_value params[ASYNCCALLBACK_ARGC] = { GetNull(env), GenerateResult(env, resultData) };
    napi_value func = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, callback, &func));

    napi_value recv = nullptr;
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &recv));
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, recv, func, ASYNCCALLBACK_ARGC, params, &result));
}

static void PromiseResultFailure(napi_env env, napi_deferred deferred, int32_t error)
{
    if (error == HKS_SUCCESS) {
        HKS_LOG_E("promise: failure cannot be executed");
        return;
    }
    napi_value result = nullptr;
    result = GenerateBusinessError(env, error);
    napi_reject_deferred(env, deferred, result);
}

static void PromiseResultSuccess(napi_env env, napi_deferred deferred,
    const struct HksSuccessReturnResult resultData)
{
    napi_value result = nullptr;
    result = GenerateResult(env, resultData);
    napi_resolve_deferred(env, deferred, result);
}

void SuccessReturnResultInit(struct HksSuccessReturnResult &resultData)
{
    resultData.isOnlyReturnBoolResult = false;
    resultData.boolReturned = false;
    resultData.handle = nullptr;
    resultData.challenge = nullptr;
    resultData.outData = nullptr;
    resultData.paramSet = nullptr;
    resultData.certChain = nullptr;
}

void SuccessListAliasesReturnResultInit(struct HksSuccessListAliasesResult &resultData)
{
    resultData.aliasSet = nullptr;
}

void HksReturnNapiResult(napi_env env, napi_ref callback, napi_deferred deferred, int32_t errorCode,
    const struct HksSuccessReturnResult resultData)
{
    if (callback == nullptr) {
        if (errorCode == HKS_SUCCESS) {
            PromiseResultSuccess(env, deferred, resultData);
        } else {
            PromiseResultFailure(env, deferred, errorCode);
        }
    } else {
        if (errorCode == HKS_SUCCESS) {
            CallbackResultSuccess(env, callback, resultData);
        } else {
            CallbackResultFailure(env, callback, errorCode);
        }
    }
}

void HksReturnKeyExistResult(napi_env env, napi_ref callback, napi_deferred deferred, int32_t errorCode,
    const struct HksSuccessReturnResult resultData)
{
    if (callback == nullptr) {
        if (errorCode == HKS_SUCCESS || errorCode == HKS_ERROR_NOT_EXIST) {
            PromiseResultSuccess(env, deferred, resultData);
        } else {
            PromiseResultFailure(env, deferred, errorCode);
        }
    } else {
        if (errorCode == HKS_SUCCESS || errorCode == HKS_ERROR_NOT_EXIST) {
            CallbackResultSuccess(env, callback, resultData);
        } else {
            CallbackResultFailure(env, callback, errorCode);
        }
    }
}

napi_value CreateJsError(napi_env env, int32_t errCode, const char *errorMsg)
{
    napi_value code = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &code));

    napi_value message = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, errorMsg, strlen(errorMsg), &message));

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_error(env, code, message, &result));
    return result;
}

static napi_value GenerateListAliasesResult(napi_env env, const struct HksSuccessListAliasesResult resultData)
{
    napi_value result = nullptr;

    if (napi_create_object(env, &result) != napi_ok) {
        return GetNull(env);
    }
    // add aliases
    if ((resultData.aliasSet != nullptr) && (resultData.aliasSet->aliases != nullptr) &&
        (resultData.aliasSet->aliasesCnt != 0)) {
        napi_value keyAliasesJs = GenerateStringArray(env, resultData.aliasSet->aliases,
            resultData.aliasSet->aliasesCnt);
        if (keyAliasesJs == nullptr) {
            HKS_LOG_E("add keyAliases failed");
            return GetNull(env);
        }
        NAPI_CALL(env, napi_set_named_property(env, result, HKS_RESULT_PRPPERTY_ALIASES.c_str(), keyAliasesJs));
    } else {
        napi_value array = nullptr;
        NAPI_CALL(env, napi_create_array(env, &array));
        NAPI_CALL(env, napi_set_named_property(env, result, HKS_RESULT_PRPPERTY_ALIASES.c_str(), array));
    }
    return result;
}

static void PromiseListAliasesResultSuccess(napi_env env, napi_deferred deferred,
    const struct HksSuccessListAliasesResult resultData)
{
    napi_value result = nullptr;
    result = GenerateListAliasesResult(env, resultData);
    napi_resolve_deferred(env, deferred, result);
}

void HksReturnListAliasesResult(napi_env env, napi_ref callback, napi_deferred deferred, int32_t errorCode,
    const struct HksSuccessListAliasesResult resultData)
{
    // now not support callback
    if (callback == nullptr) {
        if (errorCode == HKS_SUCCESS) {
            PromiseListAliasesResultSuccess(env, deferred, resultData);
        } else {
            PromiseResultFailure(env, deferred, errorCode);
        }
    }
}
}  // namespace HuksNapiItem
