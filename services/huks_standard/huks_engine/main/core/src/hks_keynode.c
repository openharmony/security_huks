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

#ifndef _CUT_AUTHENTICATE_

#include "hks_keynode.h"

#include "hks_core_service.h"
#include "hks_crypto_hal.h"
#include "hks_keyblob.h"
#include "hks_log.h"
#include "hks_mem.h"

static struct DoubleList g_keyNodeList = { NULL, NULL };
static uint64_t g_keyNodeHandle = 0;

struct DoubleList *GetKeyNodeList(void)
{
    return &g_keyNodeList;
}

static int32_t BuildRuntimeParamSet(const struct HksParamSet *inParamSet, struct HksParamSet **outParamSet)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("init keyNode param set fail");
        return ret;
    }

    if (inParamSet != NULL) {
        ret = HksAddParams(paramSet, inParamSet->params, inParamSet->paramsCnt);
        if (ret != HKS_SUCCESS) {
            HksFreeParamSet(&paramSet);
            HKS_LOG_E("add in params fail");
            return ret;
        }
    }

    struct HksParam params[] = {
        {
            .tag = HKS_TAG_ACCESS_TIME,
            .uint32Param = 0
        }, {
            .tag = HKS_TAG_USES_TIME,
            .uint32Param = 0
        }, {
            .tag = HKS_TAG_CRYPTO_CTX,
            .uint64Param = 0
        },
    };

    ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(params[0]));
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
        HKS_LOG_E("add runtime params fail");
        return ret;
    }

    ret = HksBuildParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSet);
        HKS_LOG_E("build paramSet fail");
        return ret;
    }

    *outParamSet = paramSet;
    return HKS_SUCCESS;
}

static void FreeKeyNodeParamSet(struct HksParamSet **paramSet)
{
    if ((paramSet == NULL) || (*paramSet == NULL)) {
        HKS_LOG_E("invalid keyNode get ctx param failed");
        return;
    }

    HksFreeParamSet(paramSet);
}

static int32_t GenerateKeyNodeHandle(uint64_t *handle)
{
    int32_t ret;
    if (g_keyNodeHandle == HKS_KEYNODE_HANDLE_INVALID_VALUE) {
        uint64_t handleData = 0;
        struct HksBlob opHandle = {
            .size = sizeof(uint64_t),
            .data = (uint8_t *)&handleData
        };

        ret = HksCryptoHalFillRandom(&opHandle);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("fill keyNode handle failed");
            return ret;
        }

        if (memcpy_s(&g_keyNodeHandle, sizeof(g_keyNodeHandle),
            opHandle.data, opHandle.size) != EOK) {
            HKS_LOG_E("memcpy handle failed");
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }

    *handle = g_keyNodeHandle++;
    return HKS_SUCCESS;
}

#ifdef _STORAGE_LITE_
struct HuksKeyNode *HksCreateKeyNode(const struct HksBlob *key, const struct HksParamSet *paramSet)
{
    struct HuksKeyNode *keyNode = (struct HuksKeyNode *)HksMalloc(sizeof(struct HuksKeyNode));
    if (keyNode == NULL) {
        HKS_LOG_E("malloc hks keyNode failed");
        return NULL;
    }

    int32_t ret = GenerateKeyNodeHandle(&keyNode->handle);
    if (ret != HKS_SUCCESS) {
        HksFree((void *)keyNode);
        HKS_LOG_E("get keynode handle failed");
        return NULL;
    }

    struct HksParamSet *runtimeParamSet = NULL;
    ret = BuildRuntimeParamSet(paramSet, &runtimeParamSet);
    if (ret != HKS_SUCCESS) {
        HksFree((void *)keyNode);
        HKS_LOG_E("get runtime paramSet failed");
        return NULL;
    }

    struct HksBlob rawKey = { 0, NULL };
    ret = HksGetRawKeyMaterial(key, &rawKey);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get raw key material failed, ret = %d", ret);
        HksFreeParamSet(&runtimeParamSet);
        HksFree((void *)keyNode);
        return NULL;
    }

    struct HksParamSet *keyBlobParamSet = NULL;
    ret = HksTranslateKeyInfoBlobToParamSet(&rawKey, key, &keyBlobParamSet);
    (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
    HKS_FREE_BLOB(rawKey);

    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("translate key info to paramset failed, ret = %d", ret);
        HksFreeParamSet(&runtimeParamSet);
        HksFree((void *)keyNode);
        return NULL;
    }

    keyNode->keyBlobParamSet = keyBlobParamSet;
    keyNode->runtimeParamSet = runtimeParamSet;
    HksMutexLock(HksCoreGetHuksMutex());
    AddNodeAfterDoubleListHead(&g_keyNodeList, &keyNode->listHead);
    HksMutexUnlock(HksCoreGetHuksMutex());

    return keyNode;
}
#else // _STORAGE_LITE_
struct HuksKeyNode *HksCreateKeyNode(const struct HksBlob *key, const struct HksParamSet *paramSet)
{
    struct HuksKeyNode *keyNode = (struct HuksKeyNode *)HksMalloc(sizeof(struct HuksKeyNode));
    if (keyNode == NULL) {
        HKS_LOG_E("malloc hks keyNode failed");
        return NULL;
    }

    int32_t ret = GenerateKeyNodeHandle(&keyNode->handle);
    if (ret != HKS_SUCCESS) {
        HksFree((void *)keyNode);
        HKS_LOG_E("get keynode handle failed");
        return NULL;
    }

    struct HksParamSet *runtimeParamSet = NULL;
    ret = BuildRuntimeParamSet(paramSet, &runtimeParamSet);
    if (ret != HKS_SUCCESS) {
        HksFree((void *)keyNode);
        HKS_LOG_E("get runtime paramSet failed");
        return NULL;
    }

    struct HksBlob aad = { 0, NULL };
    struct HksParamSet *keyBlobParamSet = NULL;
    ret = HksGetAadAndParamSet(key, &aad, &keyBlobParamSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&runtimeParamSet);
        HksFree((void *)keyNode);
        HKS_LOG_E("get aad and paramSet failed");
        return NULL;
    }

    ret = HksDecryptKeyBlob(&aad, keyBlobParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("decrypt keyBlob failed");
        HKS_FREE_BLOB(aad);
        HksFreeParamSet(&runtimeParamSet);
        HksFreeParamSet(&keyBlobParamSet);
        HksFree((void *)keyNode);
        return NULL;
    }

    keyNode->keyBlobParamSet = keyBlobParamSet;
    keyNode->runtimeParamSet = runtimeParamSet;
    HksMutexLock(HksCoreGetHuksMutex());
    AddNodeAfterDoubleListHead(&g_keyNodeList, &keyNode->listHead);
    HksMutexUnlock(HksCoreGetHuksMutex());
    HKS_FREE_BLOB(aad);
    return keyNode;
}
#endif // _STORAGE_LITE_

struct HuksKeyNode *HksQueryKeyNode(uint64_t handle)
{
    struct HuksKeyNode *keyNode = NULL;
    HksMutexLock(HksCoreGetHuksMutex());
    HKS_DLIST_ITER(keyNode, &g_keyNodeList) {
        if ((keyNode != NULL) && (keyNode->handle == handle)) {
            HksMutexUnlock(HksCoreGetHuksMutex());
            return keyNode;
        }
    }
    HksMutexUnlock(HksCoreGetHuksMutex());
    return NULL;
}

void HksDeleteKeyNode(uint64_t handle)
{
    struct HuksKeyNode *keyNode = NULL;
    HksMutexLock(HksCoreGetHuksMutex());
    HKS_DLIST_ITER(keyNode, &g_keyNodeList) {
        if ((keyNode != NULL) && (keyNode->handle == handle)) {
            RemoveDoubleListNode(&keyNode->listHead);
            HksFreeParamSet(&keyNode->keyBlobParamSet);
            FreeKeyNodeParamSet(&keyNode->runtimeParamSet);
            HksFree((void *)keyNode);
            keyNode = NULL;
            HksMutexUnlock(HksCoreGetHuksMutex());
            return;
        }
    }
    HksMutexUnlock(HksCoreGetHuksMutex());
}
#endif /* _CUT_AUTHENTICATE_ */
