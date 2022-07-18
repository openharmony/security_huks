/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_report.h"
#include "hks_type_inner.h"

#define EXTRA_DATA_SIZE 512

#define STRING_TAG_KEY_SIZE "keySize"
#define STRING_TAG_DIGEST "digest"
#define STRING_TAG_BLOCK_MODE "blockMode"
#define STRING_TAG_UNWRAP_ALGORITHM_SUITE "unwrapAlgorithmSuit"
#define STRING_TAG_ITERATION "iteration"
#define STRING_TAG_PURPOSE "purpose"

static const struct HksBlob g_tagKeySize = {sizeof(STRING_TAG_KEY_SIZE) - 1, (uint8_t *)STRING_TAG_KEY_SIZE};
static const struct HksBlob g_tagDigest = {sizeof(STRING_TAG_DIGEST) - 1, (uint8_t *)STRING_TAG_DIGEST};
static const struct HksBlob g_tagBlockMode = {sizeof(STRING_TAG_BLOCK_MODE) - 1, (uint8_t *)STRING_TAG_BLOCK_MODE};
static const struct HksBlob g_tagUnwrapAlgorithmSuit = {sizeof(STRING_TAG_UNWRAP_ALGORITHM_SUITE) - 1, 
    (uint8_t *)STRING_TAG_UNWRAP_ALGORITHM_SUITE};
static const struct HksBlob g_tagIteration = {sizeof(STRING_TAG_ITERATION) - 1, (uint8_t *)STRING_TAG_ITERATION};
static const struct HksBlob g_tagPurpose = {sizeof(STRING_TAG_PURPOSE) - 1, (uint8_t *)STRING_TAG_PURPOSE};

static int32_t AppendParamToExtra(const struct HksParam *paramIn, char *extraOut, uint32_t *index)
{
    switch (GetTagType(paramIn->tag))
    {
        case HKS_TAG_TYPE_UINT: {
            int32_t num = snprintf_s(extraOut + *index, EXTRA_DATA_SIZE - *index, EXTRA_DATA_SIZE - *index - 1, "%d",
                paramIn->uint32Param);
            if (num < 0) {
                HKS_LOG_E("snprintf_s failed!");
                return HKS_ERROR_BAD_STATE;
            }
            *index = *index + num;
            break;
        }
        default:
            break;
    }
    return HKS_SUCCESS;
}

static int32_t AppendToExtra(const struct HksBlob *tag, const struct HksParam *paramIn, char *extraOut,
    uint32_t *index) 
{
    if (*index > EXTRA_DATA_SIZE) {
        HKS_LOG_E("no enough space!");
        return HKS_ERROR_BAD_STATE;
    }
    if (memcpy_s(extraOut + *index, EXTRA_DATA_SIZE - *index, tag->data, tag->size) != EOK) {
        HKS_LOG_E("copy extra tag failed!");
        return HKS_ERROR_BAD_STATE;
    }
    *index += tag->size;
    char split = ':';
    if (*index > EXTRA_DATA_SIZE) {
        HKS_LOG_E("no enough space!");
        return HKS_ERROR_BAD_STATE;
    }
    if (memcpy_s(extraOut + *index, EXTRA_DATA_SIZE - *index, &split, sizeof(char)) != EOK) {
        HKS_LOG_E("copy split failed!");
        return HKS_ERROR_BAD_STATE;
    }
    *index += sizeof(char);
    if (*index > EXTRA_DATA_SIZE) {
        HKS_LOG_E("no enough space!");
        return HKS_ERROR_BAD_STATE;
    }
    uint32_t ret = AppendParamToExtra(paramIn, extraOut, index);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("append param to extra failed!");
        return ret;
    }
    split = ';';
    if (*index > EXTRA_DATA_SIZE) {
        HKS_LOG_E("no enough space!");
        return HKS_ERROR_BAD_STATE;
    }
    if (memcpy_s(extraOut + *index, EXTRA_DATA_SIZE - *index, &split, sizeof(char)) != EOK) {
        HKS_LOG_E("copy split failed!");
        return HKS_ERROR_BAD_STATE;
    }
    *index += sizeof(char);
    return HKS_SUCCESS;
}

static void AppendIfExist(uint32_t tag, const struct HksParamSet *paramSetIn, const struct HksBlob *tagString, 
    char *extraOut, uint32_t *index)
{
    struct HksParam *temp = NULL;
    int32_t ret = HksGetParam(paramSetIn, tag, &temp);
    if (ret == HKS_SUCCESS) {
        ret = AppendToExtra(tagString, temp, extraOut, index);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("Append extra data failed!");
        }
    } else {
        HKS_LOG_I("Tag not exist.");
    }
}

// return -1 if not exist
static void GetAlgorithmTag(const struct HksParamSet *paramSetIn ,uint32_t *algorithm)
{
    struct HksParam *algorithmParam = NULL;
    int32_t ret = HksGetParam(paramSetIn, HKS_TAG_ALGORITHM, &algorithmParam);
    if (ret == HKS_SUCCESS) {
        *algorithm = algorithmParam->uint32Param;
    } else {
        HKS_LOG_E("Get key type failed!");
    }
}

static void PackExtra(const struct HksParamSet *paramSetIn, char *extraOut)
{
    uint32_t index = 0;
    AppendIfExist(HKS_TAG_PURPOSE, paramSetIn, &g_tagPurpose, extraOut, &index);
    AppendIfExist(HKS_TAG_KEY_SIZE, paramSetIn, &g_tagKeySize, extraOut, &index);
    AppendIfExist(HKS_TAG_DIGEST, paramSetIn, &g_tagDigest, extraOut, &index);
    AppendIfExist(HKS_TAG_BLOCK_MODE, paramSetIn, &g_tagBlockMode, extraOut, &index);
    AppendIfExist(HKS_TAG_UNWRAP_ALGORITHM_SUITE, paramSetIn, &g_tagUnwrapAlgorithmSuit, extraOut, &index);
    AppendIfExist(HKS_TAG_ITERATION, paramSetIn, &g_tagIteration, extraOut, &index);
}

int32_t ReportFaultEvent(const char *funcName, const struct HksProcessInfo *processInfo, 
    const struct HksParamSet *paramSetIn, int32_t errorCode)
{
    if (errorCode == HKS_SUCCESS) {
        return HKS_SUCCESS;
    }
    char *extra = NULL;
    int32_t ret;
    do {
        extra = (char *)HksMalloc(EXTRA_DATA_SIZE);
        if (extra == NULL) {
            HKS_LOG_E("Malloc extra data failed!");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        (void)memset_s(extra, EXTRA_DATA_SIZE, 0, EXTRA_DATA_SIZE);

        // algorithmTag is 0 if no algorithm designed in paramset
        uint32_t algorithmTag = 0;
        if (paramSetIn != NULL) {
            if (HksCheckParamSet(paramSetIn, paramSetIn->paramSetSize) == HKS_SUCCESS) {
                GetAlgorithmTag(paramSetIn, &algorithmTag);
                PackExtra(paramSetIn, extra);
            }
        }

        // userId is 0 if no userId
        int userId = 0;

        // processName is 0 if no processName
        int processName = 0;
        if (processInfo != NULL) {
            if (memcpy_s(&userId, sizeof(userId), processInfo->userId.data, 
                processInfo->userId.size) != EOK) {
                HKS_LOG_E("copy user id failed!");
                ret = HKS_ERROR_BAD_STATE;
                break;
            }
            if (memcpy_s(&processName, sizeof(processName), processInfo->processName.data, 
                processInfo->processName.size) != EOK) {
                HKS_LOG_E("copy process name failed!");
                ret = HKS_ERROR_BAD_STATE;
                break;
            }
        }
        struct EventValues eventValues = { userId, processName, algorithmTag, errorCode };
        ret = WriteEvent(FAULT, funcName, &eventValues, extra);
    } while (0);
    HKS_FREE_PTR(extra);
    return ret;
}