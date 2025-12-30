/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_core_service_key_operate_three_stage.h"

#include <stdbool.h>
#include <stddef.h>

#include "hks_ability.h"
#include "dcm_attest.h"
#include "hks_auth.h"
#include "hks_base_check.h"
#include "hks_check_paramset.h"
#include "hks_client_service_adapter_common.h"
#include "hks_cmd_id.h"
#include "hks_common_check.h"
#include "hks_core_service_three_stage.h"
#include "hks_crypto_adapter.h"
#include "hks_crypto_hal.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_secure_access.h"
#include "hks_sm_import_wrap_key.h"
#include "hks_template.h"
#include "hks_type_inner.h"
#include "hks_util.h"

#include "securec.h"

#ifndef _HARDWARE_ROOT_KEY_
#include "hks_rkc.h"
#endif

#ifndef _CUT_AUTHENTICATE_

#define S_TO_MS 1000

static struct HksCoreInitHandler g_hksCoreInitHandler[] = {
    { HKS_KEY_PURPOSE_SIGN, HksCoreSignVerifyThreeStageInit },
    { HKS_KEY_PURPOSE_VERIFY, HksCoreSignVerifyThreeStageInit },
    { HKS_KEY_PURPOSE_ENCRYPT, HksCoreCryptoThreeStageInit },
    { HKS_KEY_PURPOSE_DECRYPT, HksCoreCryptoThreeStageInit },
    { HKS_KEY_PURPOSE_DERIVE, HksCoreDeriveThreeStageInit },
    { HKS_KEY_PURPOSE_AGREE, HksCoreAgreeThreeStageInit },
    { HKS_KEY_PURPOSE_MAC, HksCoreMacThreeStageInit }
};

static struct HksCoreUpdateHandler g_hksCoreUpdateHandler[] = {
    { HKS_KEY_PURPOSE_SIGN, HksCoreSignVerifyThreeStageUpdate },
    { HKS_KEY_PURPOSE_VERIFY, HksCoreSignVerifyThreeStageUpdate },
    { HKS_KEY_PURPOSE_ENCRYPT, HksCoreCryptoThreeStageUpdate },
    { HKS_KEY_PURPOSE_DECRYPT, HksCoreCryptoThreeStageUpdate },
    { HKS_KEY_PURPOSE_DERIVE, HksCoreDeriveThreeStageUpdate },
    { HKS_KEY_PURPOSE_AGREE, HksCoreAgreeThreeStageUpdate },
    { HKS_KEY_PURPOSE_MAC, HksCoreMacThreeStageUpdate }
};

static struct HksCoreFinishHandler g_hksCoreFinishHandler[] = {
    { HKS_KEY_PURPOSE_SIGN, HksCoreSignVerifyThreeStageFinish },
    { HKS_KEY_PURPOSE_VERIFY, HksCoreSignVerifyThreeStageFinish },
    { HKS_KEY_PURPOSE_ENCRYPT, HksCoreEncryptThreeStageFinish },
    { HKS_KEY_PURPOSE_DECRYPT, HksCoreDecryptThreeStageFinish },
    { HKS_KEY_PURPOSE_DERIVE, HksCoreDeriveThreeStageFinish },
    { HKS_KEY_PURPOSE_AGREE, HksCoreAgreeThreeStageFinish },
    { HKS_KEY_PURPOSE_MAC, HksCoreMacThreeStageFinish }
};

static struct HksCoreAbortHandler g_hksCoreAbortHandler[] = {
    { HKS_KEY_PURPOSE_SIGN, HksCoreSignVerifyThreeStageAbort },
    { HKS_KEY_PURPOSE_VERIFY, HksCoreSignVerifyThreeStageAbort },
    { HKS_KEY_PURPOSE_ENCRYPT, HksCoreCryptoThreeStageAbort },
    { HKS_KEY_PURPOSE_DECRYPT, HksCoreCryptoThreeStageAbort },
    { HKS_KEY_PURPOSE_DERIVE, HksCoreDeriveThreeStageAbort },
    { HKS_KEY_PURPOSE_AGREE, HksCoreAgreeThreeStageAbort },
    { HKS_KEY_PURPOSE_MAC, HksCoreMacThreeStageAbort }
};

static int32_t GetPurposeAndAlgorithm(const struct HksParamSet *paramSet, uint32_t *pur, uint32_t *alg)
{
    HKS_IF_NULL_LOGE_RETURN(paramSet, HKS_ERROR_NULL_POINTER, "paramSet == NULL")
    HKS_LOG_D("Get paramSet->paramsCnt %" LOG_PUBLIC "u", paramSet->paramsCnt);

    uint32_t i;

    for (i = 0; i < paramSet->paramsCnt; i++) {
        if (paramSet->params[i].tag == HKS_TAG_PURPOSE) {
            *pur = paramSet->params[i].uint32Param;
        }

        if (paramSet->params[i].tag == HKS_TAG_ALGORITHM) {
            *alg = paramSet->params[i].uint32Param;
        }

        if (*pur != 0 && *alg != 0) {
            HKS_LOG_E("found purpose : %" LOG_PUBLIC "u, algorithm : %" LOG_PUBLIC "u", *pur, *alg);
            break;
        }
    }

    if (i == paramSet->paramsCnt) {
        HKS_LOG_E("don't found purpose or algrithm");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (*alg == HKS_ALG_HMAC || *alg == HKS_ALG_SM3 || *pur == HKS_KEY_PURPOSE_SIGN || *pur == HKS_KEY_PURPOSE_VERIFY) {
        if (*alg == HKS_ALG_ED25519) {
            HKS_LOG_I("Algorithm is ed25519, not need to check digest");
            return HKS_SUCCESS;
        }
        for (i = 0; i < paramSet->paramsCnt; i++) {
            if (paramSet->params[i].tag ==  HKS_TAG_DIGEST) {
                *alg = paramSet->params[i].uint32Param;
                break;
            }
        }

        if (i == paramSet->paramsCnt) {
            HKS_LOG_E("don't found digest");
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }

    return HKS_SUCCESS;
}

static int32_t CoreInitPreCheck(const struct  HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *handle, const struct HksBlob *token)
{
    if (key == NULL || paramSet == NULL || handle == NULL || token == NULL) {
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    if (handle->size < sizeof(uint64_t)) {
        HKS_LOG_E("handle size is too small, size : %" LOG_PUBLIC "u", handle->size);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    if (HksCheckParamSet(paramSet, paramSet->paramSetSize) != HKS_SUCCESS ||
        HksCheckParamSetTag(paramSet) != HKS_SUCCESS) {
        HKS_LOG_E("paramSet is invalid");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

static int32_t HksBatchCheck(struct HuksKeyNode *keyNode)
{
    if (keyNode == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    int32_t ret = HKS_ERROR_PARAM_NOT_EXIST;
    if (keyNode->isBatchOperation) {
        struct HksParam *purposeParam = NULL;
        struct HksParam *batchPurposeParam = NULL;
        ret = HksGetParam(keyNode->runtimeParamSet, HKS_TAG_PURPOSE, &purposeParam);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT, "get purpose param failed!")
        ret = HksGetParam(keyNode->keyBlobParamSet, HKS_TAG_BATCH_PURPOSE, &batchPurposeParam);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT, "get batch purpose param failed!")
        if ((purposeParam->uint32Param | batchPurposeParam->uint32Param) != batchPurposeParam->uint32Param) {
            HKS_LOG_E("purposeParam should falll within the scope of batchPurposeParam");
            return HKS_ERROR_INVALID_PURPOSE;
        }
    }
    return ret;
}

static int32_t HksCoreInitProcess(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    uint32_t pur, uint32_t alg)
{
    if (keyNode == NULL || paramSet == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    uint32_t i;
    uint32_t size = HKS_ARRAY_SIZE(g_hksCoreInitHandler);
    int32_t ret = HKS_ERROR_BAD_STATE;
    for (i = 0; i < size; i++) {
        if (g_hksCoreInitHandler[i].pur == pur) {
            HKS_LOG_E("Core HksCoreInit pur = %" LOG_PUBLIC "d", pur);
            ret = g_hksCoreInitHandler[i].handler(keyNode, paramSet, alg);
            break;
        }
    }

    if (ret != HKS_SUCCESS || i == size) {
        HKS_LOG_E("CoreInit failed, pur : %" LOG_PUBLIC "u, ret : %" LOG_PUBLIC "d", pur, ret);
        ret = ((i == size) ? HKS_ERROR_INVALID_ARGUMENT : ret);
    }
    return ret;
}

static int32_t HksCoreUpdateProcess(struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    if (keyNode == NULL || paramSet == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    uint32_t i;
    uint32_t pur = 0;
    uint32_t alg = 0;
    int32_t ret = GetPurposeAndAlgorithm(keyNode->runtimeParamSet, &pur, &alg);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetPurposeAndAlgorithm failed")
    uint32_t size = HKS_ARRAY_SIZE(g_hksCoreUpdateHandler);
    for (i = 0; i < size; i++) {
        if (g_hksCoreUpdateHandler[i].pur == pur) {
            struct HksBlob appendInData = { 0, NULL };
            ret = HksCoreAppendAuthInfoBeforeUpdate(keyNode, pur, paramSet, inData, &appendInData);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "before update: append auth info failed")

            ret = g_hksCoreUpdateHandler[i].handler(keyNode, paramSet,
                appendInData.data == NULL ? inData : &appendInData, outData, alg);
            if (appendInData.data != NULL) {
                HKS_FREE_BLOB(appendInData);
            }
            break;
        }
    }

    if (ret != HKS_SUCCESS || i == size) {
        HKS_LOG_E("CoreUpdate failed, pur : %" LOG_PUBLIC "u, ret : %" LOG_PUBLIC "d", pur, ret);
        ret = ((i == size) ? HKS_ERROR_INVALID_ARGUMENT : ret);
    }
    return ret;
}

static int32_t HksCoreFinishProcess(struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    if (keyNode == NULL || paramSet == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    uint32_t i;
    uint32_t size = HKS_ARRAY_SIZE(g_hksCoreFinishHandler);
    uint32_t pur = 0;
    uint32_t alg = 0;
    int32_t ret = GetPurposeAndAlgorithm(keyNode->runtimeParamSet, &pur, &alg);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetPurposeAndAlgorithm failed")
    for (i = 0; i < size; i++) {
        if (g_hksCoreFinishHandler[i].pur == pur) {
            uint32_t outDataBufferSize = (outData == NULL) ? 0 : outData->size;
            struct HksBlob appendInData = { 0, NULL };
            ret = HksCoreAppendAuthInfoBeforeFinish(keyNode, pur, paramSet, inData, &appendInData);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "before finish: append auth info failed")

            ret = g_hksCoreFinishHandler[i].handler(keyNode, paramSet,
                appendInData.data == NULL ? inData : &appendInData, outData, alg);
            if (appendInData.data != NULL) {
                HKS_FREE_BLOB(appendInData);
            }
            HKS_IF_NOT_SUCC_BREAK(ret)

            ret = HksCoreAppendAuthInfoAfterFinish(keyNode, pur, paramSet, outDataBufferSize, outData);
            break;
        }
    }

    if (i == size) {
        HKS_LOG_E("don't found purpose, pur : %" LOG_PUBLIC "d", pur);
        ret = HKS_ERROR_INVALID_ARGUMENT;
    }
    return ret;
}

static int32_t HksAddBatchTimeToKeyNode(const struct HksParamSet *paramSet, struct HuksKeyNode *keyNode)
{
    if (keyNode == NULL || paramSet == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    uint64_t curTime = 0;
    int32_t ret = HksElapsedRealTime(&curTime);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksElapsedRealTime failed")
    keyNode->isBatchOperation = false;
    keyNode->batchOperationTimestamp = curTime + DEFAULT_BATCH_TIME_OUT * S_TO_MS;
    bool findOperation = false;
    bool findTimeout = false;
    for (uint32_t i = 0; i < paramSet->paramsCnt; i++) {
        if (paramSet->params[i].tag == HKS_TAG_IS_BATCH_OPERATION) {
            keyNode->isBatchOperation = paramSet->params[i].boolParam;
            findOperation = true;
            continue;
        }
        if (paramSet->params[i].tag == HKS_TAG_BATCH_OPERATION_TIMEOUT) {
            if ((uint64_t)paramSet->params[i].uint32Param > MAX_BATCH_TIME_OUT) {
                HKS_LOG_E("Batch time is too big.");
                return HKS_ERROR_NOT_SUPPORTED;
            }
            keyNode->batchOperationTimestamp = curTime + (uint64_t)paramSet->params[i].uint32Param * S_TO_MS;
            findTimeout = true;
            continue;
        }
        if (findOperation && findTimeout) {
            break;
        }
    }
    // HKS_TAG_IS_BATCH_OPERATION must be passed
    if (!findOperation && findTimeout) {
        keyNode->batchOperationTimestamp = 0;
        HKS_LOG_E("can not find HKS_TAG_IS_BATCH_OPERATION.");
        return HKS_ERROR_NOT_SUPPORTED;
    }
    if (!findOperation) {
        keyNode->batchOperationTimestamp = 0;
    }
    return ret;
}

int32_t HksCoreInit(const struct  HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *handle,
    struct HksBlob *token)
{
    HKS_LOG_D("HksCoreInit in Core start");
    uint32_t pur = 0;
    uint32_t alg = 0;

    int32_t ret = CoreInitPreCheck(key, paramSet, handle, token);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    struct HuksKeyNode *keyNode = HksCreateKeyNode(key, paramSet);
    if (keyNode == NULL || handle == NULL) {
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_BAD_STATE;
    }
    do {
        ret = HksAddBatchTimeToKeyNode(paramSet, keyNode);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksProcessIdentityVerify(keyNode->keyBlobParamSet, paramSet);
        HKS_IF_NOT_SUCC_BREAK(ret)

        handle->size = sizeof(uint64_t);
        if (memcpy_s(handle->data, handle->size, &(keyNode->handle), handle->size) != EOK) {
            HKS_LOG_E("memcpy handle data failed!");
            ret = HKS_ERROR_INSUFFICIENT_MEMORY;
            break;
        }

        ret = GetPurposeAndAlgorithm(paramSet, &pur, &alg);
        HKS_IF_NOT_SUCC_BREAK(ret)

        ret = HksCoreSecureAccessInitParams(keyNode, paramSet, token);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init secure access params failed")

        ret = HksBatchCheck(keyNode);
        if (ret == HKS_SUCCESS) {
            HKS_LOG_I("HksBatchCheck success");
            return HKS_SUCCESS;
        }
        if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
            ret = HksCoreInitProcess(keyNode, paramSet, pur, alg);
        }
    } while (0);
    if (ret != HKS_SUCCESS) {
        HksDeleteKeyNode(keyNode->handle);
    }
    HKS_LOG_D("HksCoreInit in Core end");
    return ret;
}

static int32_t GetParamsForUpdateAndFinish(const struct HksBlob *handle, uint64_t *sessionId,
    struct HuksKeyNode **keyNode)
{
    if (handle == NULL || sessionId == NULL || keyNode == NULL) {
        HKS_LOG_E("invalid input for GetSessionAndKeyNode");
        return HKS_ERROR_NULL_POINTER;
    }
    if (memcpy_s(sessionId, sizeof(*sessionId), handle->data, handle->size) != EOK) {
        HKS_LOG_E("memcpy handle value fail");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *keyNode = HksQueryKeyNodeAndMarkInUse(*sessionId);
    HKS_IF_NULL_LOGE_RETURN(*keyNode, HKS_ERROR_BAD_STATE, "HksCoreUpdate query keynode failed")

    return HKS_SUCCESS;
}

static int32_t HksCheckBatchUpdateTime(struct HuksKeyNode *keyNode)
{
    if (keyNode == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }
    uint64_t curTime = 0;
    int32_t ret = HksElapsedRealTime(&curTime);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksElapsedRealTime failed");
    if (keyNode->batchOperationTimestamp < curTime) {
        HKS_LOG_E("Batch operation timeout");
        return HKS_ERROR_INVALID_TIME_OUT;
    }
    return ret;
}

static int32_t HksBatchUpdate(struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    if (keyNode == NULL || paramSet == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    // enable verify authtoken when is multi batch operation
    struct HksParam *authResult = NULL;
    int32_t ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_KEY_AUTH_RESULT, &authResult);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_BAD_STATE, "get authResult failed!")
    authResult->uint32Param = HKS_AUTH_RESULT_INIT;
    struct HksParam *isNeedSecureSignInfo = NULL;
    ret = HksGetParam(keyNode->authRuntimeParamSet, HKS_TAG_IF_NEED_APPEND_AUTH_INFO, &isNeedSecureSignInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_BAD_STATE, "get is secure sign failed!")
    isNeedSecureSignInfo->boolParam = false;
    ret = HksCheckBatchUpdateTime(keyNode);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "HksCheckBatchUpdateTime failed!")
    struct HuksKeyNode *batchKeyNode = HksCreateBatchKeyNode(keyNode, paramSet);
    HKS_IF_NULL_LOGE_RETURN(batchKeyNode, HKS_ERROR_BAD_STATE, "the batchKeyNode is null")
    do {
        uint32_t pur = 0;
        uint32_t alg = 0;
        ret = GetPurposeAndAlgorithm(paramSet, &pur, &alg);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "GetPurposeAndAlgorithm failed")
        ret = HksCoreInitProcess(batchKeyNode, paramSet, pur, alg);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCoreInitProcess failed")
        ret = HksCoreFinishProcess(batchKeyNode, paramSet, inData, outData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCoreFinishProcess failed")
    } while (0);

    HksFreeUpdateKeyNode(batchKeyNode);
    return ret;
}

int32_t HksCoreUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    HKS_LOG_D("HksCoreUpdate in Core start");

    if (handle == NULL || paramSet == NULL || inData == NULL) {
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksCheckParamSetTag(paramSet);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    uint64_t sessionId;
    struct HuksKeyNode *keyNode = NULL;

    ret = GetParamsForUpdateAndFinish(handle, &sessionId, &keyNode);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetParamsForCoreUpdate failed")

    do {
        ret = CheckIfNeedIsDevicePasswordSet(keyNode->keyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check device password status failed %" LOG_PUBLIC "d", ret)

        ret = HksCoreSecureAccessVerifyParams(keyNode, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCoreUpdate secure access verify failed %" LOG_PUBLIC "d", ret)

        ret = HksBatchCheck(keyNode);
        if (ret == HKS_SUCCESS) {
            HKS_LOG_I("HksBatchCheck success");
            ret = HksBatchUpdate(keyNode, paramSet, inData, outData);
            HKS_IF_NOT_SUCC_BREAK(ret)
            HksMarkKeyNodeUnuse(keyNode);
            return ret;
        }
        HKS_IF_TRUE_EXCU(ret == HKS_ERROR_PARAM_NOT_EXIST,
            ret = HksCoreUpdateProcess(keyNode, paramSet, inData, outData));
        HKS_IF_NOT_SUCC_BREAK(ret)
        HksMarkKeyNodeUnuse(keyNode);
        return ret;
    } while (false);
    HksMarkKeyNodeUnuse(keyNode);
    HksDeleteKeyNode(sessionId);
    return ret;
}

int32_t HksCoreFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    HKS_LOG_D("HksCoreFinish in Core start");

    if (handle == NULL || inData == NULL || paramSet == NULL || HksCheckParamSetTag(paramSet) != HKS_SUCCESS) {
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    uint64_t sessionId;
    struct HuksKeyNode *keyNode = NULL;

    int32_t ret = GetParamsForUpdateAndFinish(handle, &sessionId, &keyNode);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "GetParamsForCoreUpdate failed")
    do {
        ret = CheckIfNeedIsDevicePasswordSet(keyNode->keyBlobParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check device password status failed %" LOG_PUBLIC "d", ret)

        ret = HksBatchCheck(keyNode);
        HKS_IF_TRUE_BREAK(ret != HKS_ERROR_PARAM_NOT_EXIST)

        ret = HksCoreSecureAccessVerifyParams(keyNode, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksCoreFinish secure access verify failed %" LOG_PUBLIC "d", ret)

        ret = HksCoreFinishProcess(keyNode, paramSet, inData, outData);
        HKS_LOG_D("HksCoreFinish in Core end");
    } while (false);
    HksMarkKeyNodeUnuse(keyNode);
    HksDeleteKeyNode(sessionId);
    return ret;
}

int32_t HksCoreAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet)
{
    HKS_LOG_D("HksCoreAbort in Core start");
    uint32_t pur = 0;
    uint32_t alg = 0;

    if (handle == NULL || paramSet == NULL) {
        HKS_LOG_E("the pointer param entered is invalid");
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HksCheckParamSetTag(paramSet);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    uint64_t sessionId;
    if (memcpy_s(&sessionId, sizeof(sessionId), handle->data, handle->size) != EOK) {
        HKS_LOG_E("memcpy handle fail");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    struct HuksKeyNode *keyNode = HksQueryKeyNodeAndMarkInUse(sessionId);
    HKS_IF_NULL_LOGE_RETURN(keyNode, HKS_SUCCESS, "abort get key node failed")

    do {
        ret = GetPurposeAndAlgorithm(keyNode->runtimeParamSet, &pur, &alg);
        HKS_IF_NOT_SUCC_BREAK(ret)

        uint32_t i;
        uint32_t size = HKS_ARRAY_SIZE(g_hksCoreAbortHandler);
        for (i = 0; i < size; i++) {
            if (g_hksCoreAbortHandler[i].pur == pur) {
                ret = g_hksCoreAbortHandler[i].handler(keyNode, paramSet, alg);
                break;
            }
        }
        if (i == size) {
            HKS_LOG_E("don't found purpose, pur : %" LOG_PUBLIC "d", pur);
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }

        HKS_LOG_D("HksCoreAbort in Core end");
    } while (false);
    HksMarkKeyNodeUnuse(keyNode);
    HksDeleteKeyNode(sessionId);
    return ret;
}

#endif /* _CUT_AUTHENTICATE_ */