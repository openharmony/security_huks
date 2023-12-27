/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef HKS_LITE_API_COMMON_H
#define HKS_LITE_API_COMMON_H

#include "jsi.h"

#include "hks_type.h"
#include "hks_mem.h"
#include "hks_log.h"

namespace OHOS {
namespace ACELite {
#define HKS_HANDLE_SIZE 8

static const char *HKS_OPTIONS_PROPERTY_PROPERTIES = "properties";
static const char *HKS_OPTIONS_PROPERTY_INDATA = "inData";
static const char *HKS_PARAM_PROPERTY_TAG = "tag";
static const char *HKS_PARAM_PROPERTY_VALUE = "value";
static const char *HKS_HANDLE_PROPERTY_HANDLE = "handle";
static const char *HKS_RESULT_PROPERTY_OUTDATA = "outData";
static const char *BUSINESS_ERROR_PROPERTY_CODE = "code";
static const char *BUSINESS_ERROR_PROPERTY_MESSAGE = "message";

const uint32_t ARGS_INDEX_0 = 0;
const uint32_t ARGS_INDEX_1 = 1;
const uint32_t ARGS_INDEX_2 = 2;

struct HksLiteApiResult {
    struct HksBlob *outData;
    struct HksBlob *handle;
    bool isBoolean;
};

int32_t HksParseParamSetWithAdd(const JSIValue* args, uint32_t index, struct HksParamSet **outParamSet,
    struct HksParam *paramsToAdd, uint32_t paramsToAddSize);

int32_t HksParseKeyAlias(const JSIValue* args, uint32_t index, struct HksBlob *outKeyAliasBlob);

int32_t HksParseHandle(const JSIValue* args, uint32_t index, struct HksBlob *outHandle);

int32_t HksParseInData(const JSIValue* args, uint32_t index, struct HksBlob *outInData);

JSIValue HksConvertErrorCodeToError(int32_t rawErrorCode);

JSIValue HksConstructJSIResult(void);

void HksCallbackResultFailure(const JSIValue thisVal, const JSIValue callback, int32_t error);

void HksCallbackResultSuccess(const JSIValue thisVal, JSIValue callback, const struct HksLiteApiResult *result);

int32_t InitHuksModule(void);
} // namespace ACELite
} // namespace OHOS
#endif // HKS_LITE_API_COMMON_H
