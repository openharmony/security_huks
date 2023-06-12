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

#include "hks_lite_api.h"
#include "hks_log.h"
#include "jsi.h"
#include "jsi_types.h"

#include "hks_api.h"
#include "hks_param.h"
#include "hks_lite_api_common.h"

namespace OHOS {
namespace ACELite {
// key size 512 plus aead 16
#define RESERVED_PADDING_AREA 528

typedef int32_t (*HksCallSessionFunc)(struct HksBlob *handle, struct HksParamSet *paramSet, struct HksBlob *inData,
    struct HksBlob *outData);

static int32_t HksCallUpdateSession(struct HksBlob *handle, struct HksParamSet *paramSet, struct HksBlob *inData,
    struct HksBlob *outData)
{
    int32_t ret = InitHuksModule();
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("init huks failed");
        return ret;
    }
    ret = HksUpdate(handle, paramSet, inData, outData);
    return ret;
}

static int32_t HksCallFinishSession(struct HksBlob *handle, struct HksParamSet *paramSet, struct HksBlob *inData,
    struct HksBlob *outData)
{
    int32_t ret = InitHuksModule();
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("init huks failed");
        return ret;
    }
    ret = HksFinish(handle, paramSet, inData, outData);
    return ret;
}

static int32_t InitOutDataBuffer(struct HksBlob *inData, struct HksBlob *outData)
{
    outData->size = inData->size + RESERVED_PADDING_AREA;
    outData->data = static_cast<uint8_t *>(HksMalloc(outData->size));
    if (outData->data == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    return HKS_SUCCESS;
}

static JSIValue InnerUpdateFinishSession(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum,
    HksCallSessionFunc func)
{
    JSIValue undefValue = JSI::CreateUndefined();
    uint32_t minNumArgs = 3;
    if ((argsNum < minNumArgs) || args == nullptr) {
        HKS_LOG_E("updateSession args invalid, args num(%{public}d).", argsNum);
        return undefValue;
    }

    struct HksParamSet *paramSet = nullptr;
    struct HksBlob handle = { 0, nullptr };
    struct HksBlob outData = { 0, nullptr };
    struct HksBlob inData = { 0, nullptr };
    int32_t ret;
    do {
        ret = HksParseHandle(args, ARGS_INDEX_0, &handle);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("parse handle failed!");
            break;
        }

        ret = HksParseParamSetWithAdd(args, ARGS_INDEX_1, &paramSet, nullptr, 0);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("parse paramset failed!");
            break;
        }
        ret = HksParseInData(args, ARGS_INDEX_1, &inData);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("parse indata failed!");
            break;
        }
        ret = InitOutDataBuffer(&inData, &outData);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("init outdata buffer failed!");
            break;
        }
        ret = func(&handle, paramSet, &inData, &outData);
    } while (0);
    if (ret == HKS_SUCCESS) {
        struct HksLiteApiResult result = { &outData, nullptr, false };
        HksCallbackResultSuccess(thisVal, args[ARGS_INDEX_2], &result);
    } else {
        HksCallbackResultFailure(thisVal, args[ARGS_INDEX_2], ret);
    }

    HKS_FREE_BLOB(handle);
    HKS_FREE_BLOB(inData);
    HKS_FREE_BLOB(outData);
    HksFreeParamSet(&paramSet);
    return undefValue;
}

JSIValue HksLiteModule::updateSession(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    return InnerUpdateFinishSession(thisVal, args, argsNum, HksCallUpdateSession);
}

JSIValue HksLiteModule::finishSession(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    return InnerUpdateFinishSession(thisVal, args, argsNum, HksCallFinishSession);
}
}
}