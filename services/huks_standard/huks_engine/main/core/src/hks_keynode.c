/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#ifndef _CUT_AUTHENTICATE_

#include "hks_keynode.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>

#include "hks_crypto_hal.h"
#include "hks_keyblob.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_pthread_util.h"
#include "hks_template.h"
#include "securec.h"
#include "hks_util.h"
#include "hks_type_inner.h"

#define S_TO_MS 1000
#define MAX_RETRY_CHECK_UNIQUE_HANDLE_TIME 10
#define INVALID_TOKEN_ID 0U
#define MAX_KEY_NODES_COUNT 96

#ifdef HKS_SUPPORT_ACCESS_TOKEN
#define MAX_KEY_NODES_EACH_TOKEN_ID 32
#else
#define MAX_KEY_NODES_EACH_TOKEN_ID MAX_KEY_NODES_COUNT
#endif

static struct DoubleList g_keyNodeList = { &g_keyNodeList, &g_keyNodeList };
static volatile atomic_uint g_keyNodeCount = 0;
static pthread_mutex_t g_huksMutex = PTHREAD_MUTEX_INITIALIZER;  /* global mutex using in keynode */

static void FreeKeyBlobParamSet(struct HksParamSet **paramSet)
{
    if ((paramSet == NULL) || (*paramSet == NULL)) {
        HKS_LOG_E("invalid keyblob paramset");
        return;
    }
    struct HksParam *keyParam = NULL;
    int32_t ret = HksGetParam(*paramSet, HKS_TAG_KEY, &keyParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get key param failed!");
        HksFreeParamSet(paramSet);
        return;
    }
    (void)memset_s(keyParam->blob.data, keyParam->blob.size, 0, keyParam->blob.size);
    HksFreeParamSet(paramSet);
}

static int32_t SetAesCcmModeTag(struct HksParamSet *paramSet, const uint32_t alg, const uint32_t pur, bool *tag)
{
    if (alg != HKS_ALG_AES) {
        *tag = false;
        return HKS_SUCCESS;
    }

    if (pur != HKS_KEY_PURPOSE_ENCRYPT && pur != HKS_KEY_PURPOSE_DECRYPT) {
        *tag = false;
        return HKS_SUCCESS;
    }

    struct HksParam *modParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_BLOCK_MODE, &modParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("aes get block mode tag fail");
        return HKS_ERROR_UNKNOWN_ERROR;
    }

    *tag = (modParam->uint32Param == HKS_MODE_CCM);
    return HKS_SUCCESS;
}

static void FreeCachedData(void **ctx)
{
    struct HksBlob *cachedData = (struct HksBlob *)*ctx;
    if (cachedData == NULL) {
        return;
    }
    if (cachedData->data != NULL) {
        (void)memset_s(cachedData->data, cachedData->size, 0, cachedData->size);
        HKS_FREE(cachedData->data);
    }
    HKS_FREE(*ctx);
}

static void KeyNodeFreeCtx(uint32_t purpose, uint32_t alg, bool hasCalcHash, void **ctx)
{
    switch (purpose) {
        case HKS_KEY_PURPOSE_AGREE:
        case HKS_KEY_PURPOSE_DERIVE:
            FreeCachedData(ctx);
            break;
        case HKS_KEY_PURPOSE_SIGN:
        case HKS_KEY_PURPOSE_VERIFY:
            if (hasCalcHash) {
                HksCryptoHalHashFreeCtx(ctx);
            } else {
                FreeCachedData(ctx);
            }
            break;
        case HKS_KEY_PURPOSE_ENCRYPT:
        case HKS_KEY_PURPOSE_DECRYPT:
            if (alg != HKS_ALG_RSA) {
                HksCryptoHalEncryptFreeCtx(ctx, alg);
            } else {
                FreeCachedData(ctx);
            }
            break;
        case HKS_KEY_PURPOSE_MAC:
            HksCryptoHalHmacFreeCtx(ctx);
            break;
        default:
            return;
    }
}

static void FreeRuntimeParamSet(struct HksParamSet **paramSet)
{
    if ((paramSet == NULL) || (*paramSet == NULL)) {
        HKS_LOG_E("invalid keyblob paramset");
        return;
    }

    struct HksParam *ctxParam = NULL;
    int32_t ret = HksGetParam(*paramSet, HKS_TAG_CRYPTO_CTX, &ctxParam);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(paramSet);
        HKS_LOG_E("get ctx from keyNode failed!");
        return;
    }

    if (ctxParam->uint64Param != 0) {
        void *ctx = (void *)(uintptr_t)ctxParam->uint64Param;
        struct HksParam *param1 = NULL;
        struct HksParam *param2 = NULL;
        if (HksGetParam(*paramSet, HKS_TAG_PURPOSE, &param1) != HKS_SUCCESS ||
            HksGetParam(*paramSet, HKS_TAG_ALGORITHM, &param2) != HKS_SUCCESS) {
            HksFreeParamSet(paramSet);
            return;
        }
        struct HksParam *param3 = NULL;
        ret = HksGetParam(*paramSet, HKS_TAG_DIGEST, &param3);
        if (ret == HKS_ERROR_INVALID_ARGUMENT) {
            HksFreeParamSet(paramSet);
            return;
        }
        bool hasCalcHash = true;
        /* If the algorithm is ed25519, the plaintext is directly cached, and if the digest is HKS_DIGEST_NONE, the
           hash value has been passed in by the user. So the hash value does not need to be free.
        */
        if (ret == HKS_SUCCESS) {
            hasCalcHash = param3->uint32Param != HKS_DIGEST_NONE;
        }
        hasCalcHash &= (param2->uint32Param != HKS_ALG_ED25519);

        bool isAesCcm = false;
        ret = SetAesCcmModeTag(*paramSet, param2->uint32Param, param1->uint32Param, &isAesCcm);
        if (ret != HKS_SUCCESS) {
            HksFreeParamSet(paramSet);
            return;
        }

        if (isAesCcm) {
            HKS_LOG_D("FreeRuntimeParamSet fee ccm cache data!");
            FreeCachedData(&ctx);
        } else {
            KeyNodeFreeCtx(param1->uint32Param, param2->uint32Param, hasCalcHash, &ctx);
        }

        ctxParam->uint64Param = 0; /* clear ctx to NULL */
    }
    HksFreeParamSet(paramSet);
}

static void DeleteKeyNodeFree(struct HuksKeyNode *keyNode)
{
    if (keyNode->isInUse) {
        HKS_LOG_E("error! keyNode isInUse! can not delete! handle %" LOG_PUBLIC PRIu64, keyNode->handle);
        return;
    }
    RemoveDoubleListNode(&keyNode->listHead);
    FreeKeyBlobParamSet(&keyNode->keyBlobParamSet);
    FreeRuntimeParamSet(&keyNode->runtimeParamSet);
    FreeRuntimeParamSet(&keyNode->authRuntimeParamSet);
    HKS_FREE(keyNode);
    atomic_fetch_sub(&g_keyNodeCount, 1);
    HKS_LOG_I("delete keynode count:%" LOG_PUBLIC "u", atomic_load(&g_keyNodeCount));
}

static int32_t BuildRuntimeParamSet(const struct HksParamSet *inParamSet, struct HksParamSet **outParamSet)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "init keyNode param set fail")

    struct HksParam params[] = {
        {
            .tag = HKS_TAG_CRYPTO_CTX,
            .uint64Param = 0
        },
    };

    if (inParamSet != NULL) {
        ret = HksCheckIsTagAlreadyExist(params, HKS_ARRAY_SIZE(params), inParamSet);
        if (ret != HKS_SUCCESS) {
            HksFreeParamSet(&paramSet);
            HKS_LOG_E("check params fail");
            return ret;
        }

        ret = HksAddParams(paramSet, inParamSet->params, inParamSet->paramsCnt);
        if (ret != HKS_SUCCESS) {
            HksFreeParamSet(&paramSet);
            HKS_LOG_E("add in params fail");
            return ret;
        }
    }

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

static int32_t HksCheckUniqueHandle(uint64_t handle)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(HKS_LOCK_OR_FAIL(g_huksMutex), HKS_ERROR_PTHREAD_MUTEX_LOCK_FAIL,
        "lock in HksCheckUniqueHandle fail");
    struct HuksKeyNode *keyNode = NULL;
    HKS_DLIST_ITER(keyNode, &g_keyNodeList) {
        if ((keyNode != NULL) && (keyNode->handle == handle)) {
            HKS_LOG_E("The handle already exists!");
            HKS_UNLOCK_OR_FAIL(g_huksMutex);
            return HKS_FAILURE;
        }
    }
    HKS_UNLOCK_OR_FAIL(g_huksMutex);
    return HKS_SUCCESS;
}

static int32_t GenerateKeyNodeHandle(uint64_t *handle)
{
    uint32_t handleData = 0;
    struct HksBlob opHandle = {
        .size = sizeof(uint32_t),
        .data = (uint8_t *)&handleData
    };

    int32_t ret = HKS_FAILURE;
    for (uint32_t i = 0; i < MAX_RETRY_CHECK_UNIQUE_HANDLE_TIME; i++) {
        ret = HksCryptoHalFillRandom(&opHandle);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("fill keyNode handle failed");
            return ret;
        }
        ret = HksCheckUniqueHandle(handleData);
        if (ret == HKS_SUCCESS) {
            *handle = handleData; /* Temporarily only use 32 bit handle */
            return ret;
        }
    }
    return ret;
}

static void DeleteFirstTimeOutBatchKeyNode(void)
{
    if (atomic_load(&g_keyNodeCount) < MAX_KEY_NODES_COUNT) {
        return;
    }
    struct HuksKeyNode *keyNode = NULL;
    HKS_DLIST_ITER(keyNode, &g_keyNodeList) {
        if (keyNode == NULL || !keyNode->isBatchOperation) {
            continue;
        }
        uint64_t curTime = 0;
        int32_t ret = HksElapsedRealTime(&curTime);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("DeleteFirstTimeOutBatchKeyNode HksElapsedRealTime failed %" LOG_PUBLIC "d", ret);
            continue;
        }
        if (keyNode->batchOperationTimestamp >= curTime) {
            continue;
        }
        HKS_LOG_E("Batch operation timeout, delete keyNode!");
        DeleteKeyNodeFree(keyNode); // IAR iccarm can not compile `return DeleteKeyNodeFree(keyNode)`
        return; // IAR iccarm will report `a void function may not return a value`
    }
}

static uint32_t GetTokenIdFromParamSet(const struct HksParamSet *p)
{
    struct HksParam *accessTokenId = NULL;
    int32_t ret = HksGetParam(p, HKS_TAG_ACCESS_TOKEN_ID, &accessTokenId);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_W("find token id failed");
        return INVALID_TOKEN_ID;
    }
    return accessTokenId->uint32Param;
}

static bool DeleteFirstKeyNodeForTokenId(uint32_t tokenId)
{
    struct HuksKeyNode *keyNode = NULL;
    HKS_DLIST_ITER(keyNode, &g_keyNodeList) {
        if (keyNode == NULL) {
            continue;
        }
        if (GetTokenIdFromParamSet(keyNode->runtimeParamSet) != tokenId) {
            continue;
        }
        HKS_LOG_E("DeleteFirstKeyNodeForTokenId delete old not using key node!");
        DeleteKeyNodeFree(keyNode);
        return true;
    }
    return false;
}

static int32_t DeleteKeyNodeForTokenIdIfExceedLimit(uint32_t tokenId)
{
    if (atomic_load(&g_keyNodeCount) < MAX_KEY_NODES_EACH_TOKEN_ID) {
        return HKS_SUCCESS;
    }
    uint32_t ownedNodeCount = 0;
    struct HuksKeyNode *keyNode = NULL;
    HKS_DLIST_ITER(keyNode, &g_keyNodeList) {
        if (keyNode != NULL && GetTokenIdFromParamSet(keyNode->runtimeParamSet) == tokenId) {
            ++ownedNodeCount;
        }
    }
    if (ownedNodeCount >= MAX_KEY_NODES_EACH_TOKEN_ID) {
        HKS_LOG_E_IMPORTANT("current token id %" LOG_PUBLIC "u have owned too"
            "many %" LOG_PUBLIC "u nodes", tokenId, ownedNodeCount);
        if (DeleteFirstKeyNodeForTokenId(tokenId)) {
            return HKS_SUCCESS;
        }
        return HKS_ERROR_SESSION_REACHED_LIMIT;
    }
    return HKS_SUCCESS;
}

static bool DeleteFirstKeyNode(void)
{
    struct HuksKeyNode *keyNode = NULL;
    HKS_DLIST_ITER(keyNode, &g_keyNodeList) {
        HKS_LOG_E("DeleteFirstKeyNode delete old not using key node!");
        DeleteKeyNodeFree(keyNode);
        return true;
    }
    return false;
}

static int32_t AddKeyNode(struct HuksKeyNode *keyNode, uint32_t tokenId)
{
    int32_t ret = HKS_SUCCESS;
    HKS_IF_NOT_SUCC_LOGE_RETURN(HKS_LOCK_OR_FAIL(g_huksMutex), HKS_ERROR_PTHREAD_MUTEX_LOCK_FAIL,
        "lock in AddKeyNode fail");
    do {
        DeleteFirstTimeOutBatchKeyNode();

        ret = DeleteKeyNodeForTokenIdIfExceedLimit(tokenId);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "CheckKeyNodeEachTokenId fail %" LOG_PUBLIC "d", ret)

        if (atomic_load(&g_keyNodeCount) >= MAX_KEY_NODES_COUNT) {
            HKS_LOG_E("maximum number of keyNode reached");
            if (!DeleteFirstKeyNode()) {
                HKS_LOG_E("DeleteFirstKeyNode fail!");
                ret = HKS_ERROR_SESSION_REACHED_LIMIT;
                break;
            }
        }

        AddNodeAtDoubleListTail(&g_keyNodeList, &keyNode->listHead);
        atomic_fetch_add(&g_keyNodeCount, 1);
        HKS_LOG_I("add keynode count:%" LOG_PUBLIC "u", atomic_load(&g_keyNodeCount));
    } while (0);

    HKS_UNLOCK_OR_FAIL(g_huksMutex);
    return ret;
}


//create batch update keynode
struct HuksKeyNode *HksCreateBatchKeyNode(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet)
{
    struct HuksKeyNode *updateKeyNode = (struct HuksKeyNode *)HksMalloc(sizeof(struct HuksKeyNode));
    HKS_IF_NULL_LOGE_RETURN(updateKeyNode, NULL, "malloc hks keyNode failed")

    int32_t ret;
    struct HksParamSet *runtimeParamSet = NULL;

    ret = BuildRuntimeParamSet(paramSet, &runtimeParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(updateKeyNode);
        HKS_LOG_E("get runtime paramSet failed");
        return NULL;
    }

    updateKeyNode->keyBlobParamSet = keyNode->keyBlobParamSet;
    updateKeyNode->runtimeParamSet = runtimeParamSet;
    updateKeyNode->authRuntimeParamSet = keyNode->authRuntimeParamSet;
    return updateKeyNode;
}

#ifdef _STORAGE_LITE_
struct HuksKeyNode *HksCreateKeyNode(const struct HksBlob *key, const struct HksParamSet *paramSet)
{
    struct HuksKeyNode *keyNode = (struct HuksKeyNode *)HksMalloc(sizeof(struct HuksKeyNode));
    HKS_IF_NULL_LOGE_RETURN(keyNode, NULL, "malloc hks keyNode failed")

    int32_t ret = GenerateKeyNodeHandle(&keyNode->handle);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(keyNode);
        HKS_LOG_E("get keynode handle failed");
        return NULL;
    }

    struct HksParamSet *runtimeParamSet = NULL;
    ret = BuildRuntimeParamSet(paramSet, &runtimeParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(keyNode);
        HKS_LOG_E("get runtime paramSet failed");
        return NULL;
    }

    struct HksBlob rawKey = { 0, NULL };
    ret = HksGetRawKeyMaterial(key, &rawKey);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get raw key material failed, ret = %" LOG_PUBLIC "d", ret);
        HksFreeParamSet(&runtimeParamSet);
        HKS_FREE(keyNode);
        return NULL;
    }

    struct HksParamSet *keyBlobParamSet = NULL;
    ret = HksTranslateKeyInfoBlobToParamSet(&rawKey, key, &keyBlobParamSet);
    (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
    HKS_FREE_BLOB(rawKey);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("translate key info to paramset failed, ret = %" LOG_PUBLIC "d", ret);
        HksFreeParamSet(&runtimeParamSet);
        HKS_FREE(keyNode);
        return NULL;
    }

    ret = AddKeyNode(keyNode, GetTokenIdFromParamSet(runtimeParamSet));
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("add keyNode failed");
        HksFreeParamSet(&runtimeParamSet);
        HKS_FREE(keyNode);
        return NULL;
    }

    keyNode->keyBlobParamSet = keyBlobParamSet;
    keyNode->runtimeParamSet = runtimeParamSet;
    return keyNode;
}
#else // _STORAGE_LITE_
static void FreeParamsForBuildKeyNode(struct HksBlob *aad, struct HksParamSet **runtimeParamSet,
    struct HksParamSet **keyblobParamSet, struct HuksKeyNode *keyNode)
{
    if (aad != NULL && aad->data != NULL) {
        HKS_FREE_BLOB(*aad);
    }

    if (runtimeParamSet != NULL && *runtimeParamSet != NULL) {
        HksFreeParamSet(runtimeParamSet);
    }

    if (keyblobParamSet != NULL && *keyblobParamSet != NULL) {
        FreeKeyBlobParamSet(keyblobParamSet);
    }

    if (keyNode != NULL) {
        HKS_FREE(keyNode);
    }
}

struct HuksKeyNode *HksCreateKeyNode(const struct HksBlob *key, const struct HksParamSet *paramSet)
{
    struct HuksKeyNode *keyNode = (struct HuksKeyNode *)HksMalloc(sizeof(struct HuksKeyNode));
    HKS_IF_NULL_LOGE_RETURN(keyNode, NULL, "malloc hks keyNode failed")

    int32_t ret;
    struct HksBlob aad = { 0, NULL };
    struct HksParamSet *runtimeParamSet = NULL;
    struct HksParamSet *keyBlobParamSet = NULL;
    do {
        ret = GenerateKeyNodeHandle(&keyNode->handle);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get keynode handle failed")

        ret = BuildRuntimeParamSet(paramSet, &runtimeParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get runtime paramSet failed")

        ret = HksGetAadAndParamSet(key, &aad, &keyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get aad and paramSet failed")

        ret = HksDecryptKeyBlob(&aad, keyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "decrypt keyBlob failed")

        ret = AddKeyNode(keyNode, GetTokenIdFromParamSet(runtimeParamSet));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add keyNode failed")
    } while (0);

    if (ret != HKS_SUCCESS) {
        FreeParamsForBuildKeyNode(&aad, &runtimeParamSet, &keyBlobParamSet, keyNode);
        return NULL;
    }

    keyNode->keyBlobParamSet = keyBlobParamSet;
    keyNode->runtimeParamSet = runtimeParamSet;
    keyNode->authRuntimeParamSet = NULL;

    HKS_FREE_BLOB(aad);
    return keyNode;
}
#endif // _STORAGE_LITE_

struct HuksKeyNode *HksQueryKeyNodeAndMarkInUse(uint64_t handle)
{
    struct HuksKeyNode *keyNode = NULL;
    HKS_IF_NOT_SUCC_LOGE_RETURN(HKS_LOCK_OR_FAIL(g_huksMutex), NULL, "lock in HksQueryKeyNodeAndMarkInUse fail");
    HKS_DLIST_ITER(keyNode, &g_keyNodeList) {
        if (keyNode != NULL && keyNode->handle == handle) {
            if (keyNode->isInUse) {
                HKS_LOG_E("keyNode is in progress and cannot be used in parallel!");
                HKS_UNLOCK_OR_FAIL(g_huksMutex);
                return NULL;
            }
            keyNode->isInUse = true;
            HKS_UNLOCK_OR_FAIL(g_huksMutex);
            return keyNode;
        }
    }
    HKS_UNLOCK_OR_FAIL(g_huksMutex);
    return NULL;
}

void HksDeleteKeyNode(uint64_t handle)
{
    struct HuksKeyNode *keyNode = NULL;
    HKS_IF_NOT_SUCC_LOGE_RETURN_VOID(HKS_LOCK_OR_FAIL(g_huksMutex), "lock in HksDeleteKeyNode fail");
    HKS_DLIST_ITER(keyNode, &g_keyNodeList) {
        if (keyNode != NULL && keyNode->handle == handle) {
            DeleteKeyNodeFree(keyNode);
            HKS_UNLOCK_OR_FAIL(g_huksMutex);
            return;
        }
    }
    HKS_UNLOCK_OR_FAIL(g_huksMutex);
}

void HksMarkKeyNodeUnuse(struct HuksKeyNode *keyNode)
{
    HKS_IF_NULL_RETURN_VOID(keyNode)
    HKS_IF_NOT_SUCC_LOGE_RETURN_VOID(HKS_LOCK_OR_FAIL(g_huksMutex), "lock in HksMarkKeyNodeUnuse fail");
    if (!keyNode->isInUse) {
        HKS_LOG_E("ERROR! unexpected scene! keyNode->isInUse is false!");
    }
    keyNode->isInUse = false;
    HKS_UNLOCK_OR_FAIL(g_huksMutex);
}

// free batch update keynode
void HksFreeUpdateKeyNode(struct HuksKeyNode *keyNode)
{
    if (keyNode == NULL) {
        return;
    }
    FreeRuntimeParamSet(&keyNode->runtimeParamSet);
    HKS_FREE(keyNode);
}
#endif /* _CUT_AUTHENTICATE_ */