/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hks_ipc_slice.h"

#include <stdbool.h>
#include <stddef.h>

#include "hks_client_ipc_serialization.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_request.h"
#include "hks_template.h"

static bool IsSliceCmd(uint32_t cmdId)
{
    return (cmdId == HKS_MSG_SIGN) || (cmdId == HKS_MSG_VERIFY) || (cmdId == HKS_MSG_ENCRYPT) ||
        (cmdId == HKS_MSG_DECRYPT) || (cmdId == HKS_MSG_MAC);
}

static uint32_t GetBlobBufSize(const struct HksBlob *blob, uint32_t *bufSize)
{
    HKS_IF_TRUE_RETURN(IsAdditionOverflow(blob->size, DEFAULT_ALIGN_MASK_SIZE), HKS_ERROR_INVALID_ARGUMENT)
    HKS_IF_TRUE_RETURN(IsAdditionOverflow(ALIGN_SIZE(blob->size), sizeof(blob->size)), HKS_ERROR_INVALID_ARGUMENT)
    *bufSize = ALIGN_SIZE(blob->size) + sizeof(blob->size);
    return HKS_SUCCESS;
}

static uint32_t GetParamSize(const struct HksBlob *key, const struct HksParamSet *paramSet, uint32_t *bufSize)
{
    HKS_IF_TRUE_RETURN(key->size > MAX_PROCESS_SIZE || paramSet->paramSetSize > MAX_PROCESS_SIZE,
        HKS_ERROR_INVALID_ARGUMENT)

    *bufSize = ALIGN_SIZE(key->size) + sizeof(key->size) + ALIGN_SIZE(paramSet->paramSetSize);
    return HKS_SUCCESS;
}

static uint32_t GetDataSize(uint32_t cmdId, const struct HksBlob *inData, const struct HksBlob *outData,
    uint32_t *bufSize)
{
    uint32_t inBuffData;
    HKS_IF_NOT_SUCC_RETURN(GetBlobBufSize(inData, &inBuffData), HKS_ERROR_INVALID_ARGUMENT)

    uint32_t bufOutDataSize;
    if (cmdId == HKS_MSG_VERIFY) {
        HKS_IF_NOT_SUCC_RETURN(GetBlobBufSize(outData, &bufOutDataSize), HKS_ERROR_INVALID_ARGUMENT)
    } else {
        bufOutDataSize = sizeof(outData->size);
    }

    HKS_IF_TRUE_RETURN(IsAdditionOverflow(inBuffData, bufOutDataSize), HKS_ERROR_INVALID_ARGUMENT)
    *bufSize = inBuffData + bufOutDataSize;
    return HKS_SUCCESS;
}

static int32_t ProcessDataOnce(uint32_t cmdId, const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *inData, struct HksBlob *outData)
{
    HKS_LOG_D("invoke ProcessOnce cmdId %" LOG_PUBLIC "u", cmdId);

    uint32_t paramBufSize, dataBufSize;
    HKS_IF_TRUE_RETURN(GetParamSize(key, paramSet, &paramBufSize) != HKS_SUCCESS ||
        GetDataSize(cmdId, inData, outData, &dataBufSize) != HKS_SUCCESS, HKS_ERROR_INVALID_ARGUMENT)
    uint32_t totalBufSize = paramBufSize + dataBufSize;
    uint8_t *buffer = (uint8_t *)HksMalloc(totalBufSize);
    HKS_IF_NULL_RETURN(buffer, HKS_ERROR_MALLOC_FAIL)
    struct HksBlob ipcBlob = { totalBufSize, buffer };

    uint32_t offset = 0;
    int32_t ret = HksOnceParamPack(&ipcBlob, key, paramSet, &offset);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksOnceParamPack fail");
        HKS_FREE_BLOB(ipcBlob);
        return ret;
    }

    if (cmdId == HKS_MSG_VERIFY) {
        ret = HksOnceDataPack(&ipcBlob, inData, outData, NULL, &offset);
    } else {
        ret = HksOnceDataPack(&ipcBlob, inData, NULL, outData, &offset);
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksOnceDataPack fail");
        HKS_FREE_BLOB(ipcBlob);
        return ret;
    }

    if (cmdId == HKS_MSG_VERIFY) {
        ret = HksSendRequest(cmdId, &ipcBlob, NULL, paramSet);
    } else {
        ret = HksSendRequest(cmdId, &ipcBlob, outData, paramSet);
    }
    HKS_FREE_BLOB(ipcBlob);
    return ret;
}

int32_t HksSliceDataEntry(uint32_t cmdId, const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *inData, struct HksBlob *outData)
{
    HKS_IF_NOT_TRUE_LOGE_RETURN(IsSliceCmd(cmdId), HKS_ERROR_INVALID_ARGUMENT,
        "cmd %" LOG_PUBLIC "u not support slice!", cmdId)

    uint32_t paramBufSize;
    uint32_t dataBufSize;
    HKS_IF_TRUE_RETURN(GetParamSize(key, paramSet, &paramBufSize) != HKS_SUCCESS ||
        GetDataSize(cmdId, inData, outData, &dataBufSize) != HKS_SUCCESS, HKS_ERROR_INVALID_ARGUMENT)
    HKS_IF_TRUE_RETURN(IsAdditionOverflow(paramBufSize, dataBufSize), HKS_ERROR_INVALID_ARGUMENT)

    uint32_t totalBufSize = paramBufSize + dataBufSize;
    HKS_IF_TRUE_RETURN(totalBufSize > MAX_PROCESS_SIZE, HKS_ERROR_INVALID_ARGUMENT)
    return ProcessDataOnce(cmdId, key, paramSet, inData, outData);
}
 