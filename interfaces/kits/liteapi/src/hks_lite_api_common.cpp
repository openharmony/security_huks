/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_lite_api_common.h"
#include "hks_lite_api.h"
#include "hks_log.h"
#include "hks_errcode_adapter.h"
#include "jsi.h"
#include "jsi_types.h"
#include "js_app_context.h"

#include "hks_api.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type_inner.h"

#include "securec.h"

#include <cstring>
#include <vector>

namespace OHOS {
namespace ACELite {
#define RELEASE_JSI_VALUE_IF_NOT_NULL(jsiValue) \
do { \
    if ((jsiValue) != nullptr) { \
        JSI::ReleaseValue(jsiValue); \
        jsiValue = nullptr; \
    } \
} while (0)

#define RELEASE_JSI_STRING_IF_NOT_NULL(jsiString) \
do { \
    if ((jsiString) != nullptr) { \
        JSI::ReleaseString(jsiString); \
        jsiString = nullptr; \
    } \
} while (0)

static int32_t CheckIsNumberAndAssignIntParam(const JSIValue paramProperty, uint32_t paramTag,
    struct HksParam *outParam)
{
    int32_t ret = HKS_ERROR_INVALID_ARGUMENT;
    JSIValue valueJSIValue = JSI::GetNamedProperty(paramProperty, HKS_PARAM_PROPERTY_VALUE);
    if (JSI::ValueIsNumber(valueJSIValue)) {
        int32_t paramValue = (int32_t)JSI::ValueToNumber(valueJSIValue);
        outParam->tag = paramTag;
        outParam->int32Param = paramValue;
        ret = HKS_SUCCESS;
    }
    RELEASE_JSI_VALUE_IF_NOT_NULL(valueJSIValue);
    return ret;
}

static int32_t CheckIsNumberAndAssignUintParam(const JSIValue paramProperty, uint32_t paramTag,
    struct HksParam *outParam)
{
    int32_t ret = HKS_ERROR_INVALID_ARGUMENT;
    JSIValue valueJSIValue = JSI::GetNamedProperty(paramProperty, HKS_PARAM_PROPERTY_VALUE);
    if (JSI::ValueIsNumber(valueJSIValue)) {
        uint32_t paramValue = (uint32_t)JSI::ValueToNumber(valueJSIValue);
        outParam->tag = paramTag;
        outParam->uint32Param = paramValue;
        ret = HKS_SUCCESS;
    }
    RELEASE_JSI_VALUE_IF_NOT_NULL(valueJSIValue);
    return ret;
}

static int32_t CheckIsNumberAndAssignUlongParam(const JSIValue paramProperty, uint32_t paramTag,
    struct HksParam *outParam)
{
    int32_t ret = HKS_ERROR_INVALID_ARGUMENT;
    JSIValue valueJSIValue = JSI::GetNamedProperty(paramProperty, HKS_PARAM_PROPERTY_VALUE);
    if (JSI::ValueIsNumber(valueJSIValue)) {
        uint64_t paramValue = (uint64_t)JSI::ValueToNumber(valueJSIValue);
        outParam->tag = paramTag;
        outParam->uint64Param = paramValue;
        ret = HKS_SUCCESS;
    }
    RELEASE_JSI_VALUE_IF_NOT_NULL(valueJSIValue);
    return ret;
}

static int32_t CheckIsBoolAndAssignBoolParam(const JSIValue paramProperty, uint32_t paramTag,
    struct HksParam *outParam)
{
    int32_t ret = HKS_ERROR_INVALID_ARGUMENT;
    JSIValue valueJSIValue = JSI::GetNamedProperty(paramProperty, HKS_PARAM_PROPERTY_VALUE);
    if (JSI::ValueIsBoolean(valueJSIValue)) {
        bool paramValue = (bool)JSI::ValueToBoolean(valueJSIValue);
        outParam->tag = paramTag;
        outParam->boolParam = paramValue;
        ret = HKS_SUCCESS;
    }
    RELEASE_JSI_VALUE_IF_NOT_NULL(valueJSIValue);
    return ret;
}

static int32_t ParseUint8ArrayToHksBlob(JSIValue value, struct HksBlob *outData)
{
    if (!JSI::ValueIsTypedArray(value)) {
        HKS_LOG_E("value is not a typed array");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    TypedArrayType arrayType;
    size_t arraySize = 0;
    size_t byteOffset = 0;
    JSIValue arrayBuffer;
    uint8_t *dataArray;
    int32_t ret = HKS_SUCCESS;
    do {
        dataArray = JSI::GetTypedArrayInfo(value, arrayType, arraySize, arrayBuffer, byteOffset);
        if (dataArray == nullptr) {
            ret = HKS_FAILURE;
            break;
        }
        if (arrayType != TypedArrayType::JSI_UINT8_ARRAY) {
            HKS_LOG_E("value is not a uint8 array");
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }
        outData->data = (uint8_t *)HksMalloc(arraySize);
        if (outData->data == nullptr) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        memcpy_s(outData->data, arraySize, dataArray + byteOffset, arraySize);
        outData->size = arraySize;
    } while (0);
    RELEASE_JSI_VALUE_IF_NOT_NULL(arrayBuffer);
    return ret;
}

static int32_t CheckIsBytesAndAssignBlobParam(const JSIValue paramProperty, uint32_t paramTag,
    struct HksParam *outParam)
{
    int32_t ret = HKS_ERROR_INVALID_ARGUMENT;
    JSIValue valueJSIValue = JSI::GetNamedProperty(paramProperty, HKS_PARAM_PROPERTY_VALUE);
    do {
        if (!JSI::ValueIsTypedArray(valueJSIValue)) {
            HKS_LOG_E("value is not array");
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }
        ret = ParseUint8ArrayToHksBlob(valueJSIValue, &(outParam->blob));
        outParam->tag = paramTag;
    } while (0);
    RELEASE_JSI_VALUE_IF_NOT_NULL(valueJSIValue);
    return ret;
}

static int32_t HksParseParam(const JSIValue paramProperty, struct HksParam *outParam)
{
    uint32_t paramTag = (uint32_t)JSI::GetNumberProperty(paramProperty, HKS_PARAM_PROPERTY_TAG);
    int32_t ret;
    switch (paramTag & HKS_TAG_TYPE_MASK) {
        case HKS_TAG_TYPE_INT:
            ret = CheckIsNumberAndAssignIntParam(paramProperty, paramTag, outParam);
            break;
        case HKS_TAG_TYPE_UINT:
            ret = CheckIsNumberAndAssignUintParam(paramProperty, paramTag, outParam);
            break;
        case HKS_TAG_TYPE_ULONG:
            ret = CheckIsNumberAndAssignUlongParam(paramProperty, paramTag, outParam);
            break;
        case HKS_TAG_TYPE_BOOL:
            ret = CheckIsBoolAndAssignBoolParam(paramProperty, paramTag, outParam);
            break;
        case HKS_TAG_TYPE_BYTES:
            ret = CheckIsBytesAndAssignBlobParam(paramProperty, paramTag, outParam);
            break;
        default:
            HKS_LOG_E("invalid tag value 0x%" LOG_PUBLIC "x", paramTag);
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
    }
    return ret;
}

static int32_t HksParseParamsToVector(const JSIValue paramSetValue, std::vector<HksParam> &params)
{
    int32_t ret = HKS_SUCCESS;
    do {
        if (!JSI::ValueIsArray(paramSetValue)) {
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }
        uint32_t paramCnt = JSI::GetArrayLength(paramSetValue);
        if (paramCnt == 0) {
            break;
        }
        for (uint32_t i = 0; i < paramCnt; ++i) {
            JSIValue paramProperty = JSI::GetPropertyByIndex(paramSetValue, i);
            struct HksParam param = { 0 };
            ret = HksParseParam(paramProperty, &param);
            if (ret != HKS_SUCCESS) {
                RELEASE_JSI_VALUE_IF_NOT_NULL(paramProperty);
                break;
            }
            params.push_back(param);
            RELEASE_JSI_VALUE_IF_NOT_NULL(paramProperty);
        }
    } while (0);
    return ret;
}

static void HksReleaseParamVectors(std::vector<HksParam> &params)
{
    struct HksParam *param = params.data();
    size_t paramCount = params.size();
    if (param == nullptr) {
        return;
    }
    while (paramCount > 0) {
        paramCount--;
        if ((param->tag & HKS_TAG_TYPE_MASK) == HKS_TAG_TYPE_BYTES) {
            HKS_FREE(param->blob.data);
            param->blob.size = 0;
        }
        ++param;
    }
}

static int32_t HksParseParamsToParamSet(const std::vector<HksParam> &paramsVector, struct HksParamSet **outParamSet)
{
    int32_t ret;
    struct HksParamSet *paramSet = nullptr;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)
        for (auto &param : paramsVector) {
            ret = HksAddParams(paramSet, &param, 1);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("add param.tag[%" LOG_PUBLIC "u] failed", param.tag);
                break;
            }
        }
        ret = HksBuildParamSet(&paramSet);
        *outParamSet = paramSet;
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
    }
    return ret;
}

static int32_t GetAndPushBundleNameToVector(std::vector<HksParam> &paramsVector)
{
    JsAppContext *appContext = JsAppContext::GetInstance();
    if (appContext == nullptr) {
        HKS_LOG_E("appContext is null.");
        return HKS_FAILURE;
    }
    const char *curBundleName = appContext->GetCurrentBundleName();
    if (curBundleName == nullptr) {
        return HKS_FAILURE;
    }

    struct HksParam curBundleNameParam = { 0 };
    curBundleNameParam.tag = HKS_TAG_BUNDLE_NAME;
    curBundleNameParam.blob.data = (uint8_t *)HksMalloc(strlen(curBundleName) + 1);
    if (curBundleNameParam.blob.data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    curBundleNameParam.blob.size = strlen(curBundleName) + 1; // the last \0 need to be counted

    (void)memcpy_s(curBundleNameParam.blob.data, strlen(curBundleName), curBundleName, strlen(curBundleName));
    curBundleNameParam.blob.data[strlen(curBundleName)] = '\0';
    paramsVector.push_back(curBundleNameParam);
    return HKS_SUCCESS;
}

int32_t HksParseParamSetWithAdd(const JSIValue* args, uint32_t index, struct HksParamSet **outParamSet,
    struct HksParam *paramsToAdd, uint32_t paramsToAddSize)
{
    std::vector<HksParam> paramsVector;

    JSIValue paramSetValue = nullptr;
    int32_t ret;
    do {
        paramSetValue = JSI::GetNamedProperty(args[index], HKS_OPTIONS_PROPERTY_PROPERTIES);
        if (paramSetValue == nullptr) {
            HKS_LOG_I("no properties setted, but it is tolerable");
        } else {
            ret = HksParseParamsToVector(paramSetValue, paramsVector);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("parse params to vector failed");
                break;
            }
        }

        ret = GetAndPushBundleNameToVector(paramsVector);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("add bundle name failed");
            break;
        }

        if (paramsToAdd != nullptr && paramsToAddSize != 0) {
            for (uint32_t i = 0; i < paramsToAddSize; ++i) {
                paramsVector.push_back(paramsToAdd[i]);
            }
        }

        ret = HksParseParamsToParamSet(paramsVector, outParamSet);
    } while (0);
    HksReleaseParamVectors(paramsVector);
    RELEASE_JSI_VALUE_IF_NOT_NULL(paramSetValue);
    return ret;
}

int32_t HksParseKeyAlias(const JSIValue* args, uint32_t index, struct HksBlob *outKeyAliasBlob)
{
    if (!JSI::ValueIsString(args[index])) {
        HKS_LOG_E("keyAlias is not a string");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    char *keyAlias = JSI::ValueToString(args[index]);
    if (keyAlias == nullptr) {
        HKS_LOG_E("convert keyAlias jsivalue to string failed");
        return HKS_FAILURE;
    }
    outKeyAliasBlob->size = strlen(keyAlias);
    outKeyAliasBlob->data = (uint8_t *)HksMalloc(outKeyAliasBlob->size);
    if (outKeyAliasBlob->data == nullptr) {
        RELEASE_JSI_STRING_IF_NOT_NULL(keyAlias);
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(outKeyAliasBlob->data, outKeyAliasBlob->size, keyAlias, outKeyAliasBlob->size);
    RELEASE_JSI_STRING_IF_NOT_NULL(keyAlias);
    return HKS_SUCCESS;
}

int32_t HksParseHandle(const JSIValue* args, uint32_t index, struct HksBlob *outHandle)
{
    if (!JSI::ValueIsNumber(args[index])) {
        HKS_LOG_E("handle is not a number");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    uint64_t handle = (uint64_t)JSI::ValueToNumber(args[index]);
    outHandle->data = (uint8_t *)HksMalloc(sizeof(uint64_t));
    if (outHandle->data == nullptr) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(outHandle->data, sizeof(uint64_t), &handle, sizeof(uint64_t));
    outHandle->size = sizeof(uint64_t);
    return HKS_SUCCESS;
}

int32_t HksParseInData(const JSIValue* args, uint32_t index, struct HksBlob *outInData)
{
    JSIValue valueJSIValue = JSI::GetNamedProperty(args[index], HKS_OPTIONS_PROPERTY_INDATA);
    int32_t ret = ParseUint8ArrayToHksBlob(valueJSIValue, outInData);
    RELEASE_JSI_VALUE_IF_NOT_NULL(valueJSIValue);
    return ret;
}

// convert from huks inner error code to jsi err
JSIValue HksConvertErrorCodeToError(int32_t rawErrorCode)
{
    struct HksResult result = HksConvertErrCode(rawErrorCode);
    JSIValue res = JSI::CreateObject();
    JSI::SetNumberProperty(res, BUSINESS_ERROR_PROPERTY_CODE, (double)result.errorCode);
    JSI::SetStringProperty(res, BUSINESS_ERROR_PROPERTY_MESSAGE, result.errorMsg);
    return res;
}

// HuksReturnResult, only outData is used in lite system
JSIValue HksConstructJSIReturnResult(const struct HksLiteApiResult *result)
{
    if (result->isBoolean) {
        // the only possible res for result is boolean only for success case is the true
        return JSI::CreateBoolean(true);
    }
    JSIValue res;
    do {
        res = JSI::CreateObject();
        if (res == nullptr) {
            break;
        }
        if (result->outData != nullptr) {
            uint8_t *arrayBuffer = nullptr;
            JSIValue buffer = JSI::CreateArrayBuffer(result->outData->size, arrayBuffer);
            if (arrayBuffer == nullptr) {
                HKS_LOG_E("create jsi array buffer failed");
                JSI::ReleaseValue(buffer);
                return res;
            }
            (void)memcpy_s(arrayBuffer, result->outData->size, result->outData->data, result->outData->size);
            JSIValue typedArray = JSI::CreateTypedArray(TypedArrayType::JSI_UINT8_ARRAY, result->outData->size,
                buffer, 0);
            JSI::ReleaseValue(buffer);
            JSI::SetNamedProperty(res, HKS_RESULT_PROPERTY_OUTDATA, typedArray);
        }
        if (result->handle != nullptr) {
            JSI::SetNumberProperty(res, HKS_HANDLE_PROPERTY_HANDLE, *((uint64_t *)result->handle->data));
        }
    } while (0);
    return res;
}

void HksCallbackResultFailure(const JSIValue thisVal, const JSIValue callback, int32_t error)
{
    JSIValue params[2] = { HksConvertErrorCodeToError(error), JSI::CreateNull()};
    JSI::CallFunction(callback, thisVal, params, HKS_ARRAY_SIZE(params));
    RELEASE_JSI_VALUE_IF_NOT_NULL(params[0]);
    RELEASE_JSI_VALUE_IF_NOT_NULL(params[1]);
}

void HksCallbackResultSuccess(const JSIValue thisVal, JSIValue callback, const struct HksLiteApiResult *result)
{
    JSIValue params[2] = { JSI::CreateNull(), HksConstructJSIReturnResult(result) };
    JSI::CallFunction(callback, thisVal, params, HKS_ARRAY_SIZE(params));
    RELEASE_JSI_VALUE_IF_NOT_NULL(params[0]);
    RELEASE_JSI_VALUE_IF_NOT_NULL(params[1]);
}

int32_t InitHuksModule(void)
{
    return HksInitialize();
}
}
}