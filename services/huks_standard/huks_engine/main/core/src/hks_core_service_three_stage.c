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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_core_service_three_stage.h"

#include "hks_auth.h"
#include "hks_check_paramset.h"
#include "hks_client_service_adapter.h"
#include "hks_cmd_id.h"
#include "hks_common_check.h"
#include "hks_core_service.h"
#include "hks_crypto_adapter.h"
#include "hks_crypto_hal.h"
#include "hks_keyblob.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

#ifndef _HARDWARE_ROOT_KEY_
#include "hks_rkc.h"
#endif

#ifdef HKS_SUPPORT_UPGRADE_STORAGE_DATA
#include "hks_upgrade_key_info.h"
#endif

#ifndef _CUT_AUTHENTICATE_
#define CURVE25519_KEY_BYTE_SIZE HKS_KEY_BYTES(HKS_CURVE25519_KEY_SIZE_256)

#ifdef HKS_SUPPORT_ED25519_TO_X25519

#endif
#define HKS_RSA_OAEP_DIGEST_NUM     2
#define HKS_AES_CBC_BLOCK_SIZE      16

static int32_t CheckRsaCipherData(bool isEncrypt, uint32_t keyLen, struct HksUsageSpec *usageSpec,
    const struct HksBlob *outData)
{
    uint32_t keySize = keyLen / HKS_BITS_PER_BYTE;
    uint32_t padding = usageSpec->padding;
    uint32_t digest = usageSpec->digest;

    if (padding == HKS_PADDING_NONE) {
        if (outData->size < keySize) {
            HKS_LOG_E("outData buffer too small size: %u, keySize: %u", outData->size, keySize);
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
    } else if (padding == HKS_PADDING_OAEP) {
        uint32_t digestLen;
        if (digest == HKS_DIGEST_NONE) {
            digest = HKS_DIGEST_SHA1;
        }
        int32_t ret = HksGetDigestLen(digest, &digestLen);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("GetDigestLen failed, ret = %x", ret);
            return ret;
        }
        if (keySize <= (HKS_RSA_OAEP_DIGEST_NUM * digestLen + HKS_RSA_OAEP_DIGEST_NUM)) {
            return HKS_ERROR_INVALID_KEY_FILE;
        }
        uint32_t size = keySize - HKS_RSA_OAEP_DIGEST_NUM * digestLen - HKS_RSA_OAEP_DIGEST_NUM;
        if (isEncrypt) {
            if (outData->size < keySize) {
                HKS_LOG_E("encrypt, outData buffer too small size: %u, keySize: %u", outData->size, keySize);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
        } else {
            if (outData->size < size) {
                HKS_LOG_E("decrypt, outData buffer too small size: %u, keySize: %u", outData->size, keySize);
                return HKS_ERROR_BUFFER_TOO_SMALL;
            }
        }
    }

    return HKS_SUCCESS;
}

static int32_t CheckAesCipherGCMCCM(bool isEncrypt, const struct HksBlob *inData,
    const struct HksBlob *outData)
{
    if (isEncrypt) {
        if (outData->size < (inData->size + HKS_AE_TAG_LEN)) {
            HKS_LOG_E("encrypt, out buffer too small size: %u, inSize: %u", outData->size, inData->size);
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
    } else {
        if (outData->size < inData->size) {
            HKS_LOG_E("decryptfinal, out buffer too small size: %u, inSize: %u", outData->size, inData->size);
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
    }

    return HKS_SUCCESS;
}

static int32_t CheckAesCipherOther(bool isEncrypt, uint32_t padding, const struct HksBlob *inData,
    const struct HksBlob *outData)
{
    uint32_t paddingSize = 0;

    if (isEncrypt) {
        if (padding == HKS_PADDING_NONE) {
            if (inData->size % HKS_AES_CBC_BLOCK_SIZE != 0) {
                HKS_LOG_E("encrypt cbc no-padding, invalid inSize: %u", inData->size);
                return HKS_ERROR_INVALID_ARGUMENT;
            }
        } else {
            paddingSize = HKS_AES_CBC_BLOCK_SIZE - inData->size % HKS_AES_CBC_BLOCK_SIZE;
            if (inData->size > (UINT32_MAX - paddingSize)) {
                HKS_LOG_E("encrypt, invalid inData size: %u", inData->size);
                return HKS_ERROR_INVALID_ARGUMENT;
            }
        }
        if (outData->size < (inData->size + paddingSize)) {
            HKS_LOG_E("encrypt, outData buffer too small size: %u, need: %u",
                outData->size, inData->size + paddingSize);
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
    } else {
        if (outData->size < inData->size) {
            HKS_LOG_E("decrypt, outData buffer too small size: %u, inDataSize: %u", outData->size, inData->size);
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
    }

    return HKS_SUCCESS;
}

static int32_t CheckAesCipherData(bool isEncrypt, uint32_t padding, uint32_t mode,
    const struct HksBlob *inData, const struct HksBlob *outData)
{
    int32_t ret = HKS_FAILURE;
    if ((mode == HKS_MODE_CBC) || (mode == HKS_MODE_CTR) || (mode == HKS_MODE_ECB)) {
        ret = CheckAesCipherOther(isEncrypt, padding, inData, outData);
    } else if ((mode == HKS_MODE_GCM) || (mode == HKS_MODE_CCM)) {
        ret = CheckAesCipherGCMCCM(isEncrypt, inData, outData);
    }

    return ret;
}

static int32_t HksCheckFinishOutSize(bool isEncrypt, struct HksParamSet *paramSet,
    const struct HksBlob *inData, const struct HksBlob *outData)
{
    struct HksUsageSpec usageSpec = { 0 };
    HksFillUsageSpec(paramSet, &usageSpec);
    struct HksKeySpec cihperSpec = { 0 };
    HksFillKeySpec(paramSet, &cihperSpec);
    uint32_t alg = usageSpec.algType;

    switch (alg) {
        case HKS_ALG_RSA:
            return CheckRsaCipherData(isEncrypt, cihperSpec.keyLen, &usageSpec, outData);
        case HKS_ALG_AES:
            return CheckAesCipherData(isEncrypt, usageSpec.padding, usageSpec.mode, inData, outData);
        default:
            return HKS_ERROR_INVALID_ALGORITHM;
    }
}

static int32_t GetHksInnerKeyFormat(const struct HksParamSet *paramSet, const struct HksBlob *key,
    struct HksBlob *outKey)
{
    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &algParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get alg param failed");
        return HKS_ERROR_CHECK_GET_ALG_FAIL;
    }

    switch (algParam->uint32Param) {
#ifdef HKS_SUPPORT_AES_C
        case HKS_ALG_AES:
            return TranslateToInnerAesFormat(key, outKey);
#endif
#if defined(HKS_SUPPORT_X25519_C) || defined(HKS_SUPPORT_ED25519_C)
        case HKS_ALG_ED25519:
        case HKS_ALG_X25519:
            return TranslateToInnerCurve25519Format(algParam->uint32Param, key, outKey);
#endif
#if defined(HKS_SUPPORT_RSA_C) || defined(HKS_SUPPORT_ECC_C) || defined(HKS_SUPPORT_DSA_C) || \
    defined(HKS_SUPPORT_DH_C)
        case HKS_ALG_RSA:
        case HKS_ALG_ECC:
        case HKS_ALG_ECDH:
        case HKS_ALG_DSA:
        case HKS_ALG_DH:
            return TranslateFromX509PublicKey(key, outKey);
#endif
        default:
            return HKS_ERROR_INVALID_ALGORITHM;
    }
}

static void FreeSignVerifyData(void *ctx)
{
    struct HksBlob *restoreData = (struct HksBlob *)ctx;

    if (restoreData == NULL) {
        HKS_LOG_E("FreeSignVerifyData ctx is null");
        return;
    }
    if (restoreData->data != NULL) {
        HksFree((void *)restoreData->data);
        restoreData->data = NULL;
    }
    HksFree((void *)restoreData);
    return;
}

static int32_t StoreSignVerifyMessage(const struct HksParamSet *paramSet, const struct HksBlob *srcData)
{
    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &algParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get param get 0x%x failed", HKS_TAG_ALGORITHM);
        return HKS_ERROR_CHECK_GET_ALG_FAIL;
    }

    struct HksParam *ctxParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_CRYPTO_CTX, &ctxParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("SignVerify get ctxParam failed!");
        return ret;
    }
    void *ctx = (void *)(uintptr_t)ctxParam->uint64Param;

    if (algParam->uint32Param != HKS_ALG_ED25519) {
        ret = HksCryptoHalHashUpdate(srcData, &ctx);
        ctxParam->uint64Param = (uint64_t)(uintptr_t)ctx;
        if (ret != HKS_SUCCESS)  {
            HKS_LOG_E("Sign HksCryptoHalHashUpdate fail ret : %d", ret);
            return ret;
        }
    } else {
        struct HksBlob *restoreData = (struct HksBlob *)ctx;
        struct HksBlob *newData = (struct HksBlob *)HksMalloc(sizeof(struct HksBlob));
        if (newData == NULL) {
            HKS_LOG_E("StoreSignVerifyMessage malloc fail.");
            return HKS_ERROR_MALLOC_FAIL;
        }
        newData->size = restoreData->size + srcData->size;
        newData->data = (uint8_t *)HksMalloc(newData->size);
        if (newData->data == NULL) {
            HksFree((void *)newData);
            HKS_LOG_E("StoreSignVerifyMessage malloc fail.");
            return HKS_ERROR_MALLOC_FAIL;
        }

        if (restoreData->data != NULL) {
            (void)memcpy_s(newData->data, restoreData->size, restoreData->data, restoreData->size);
        }
        (void)memcpy_s(newData->data + restoreData->size, srcData->size, srcData->data, srcData->size);
        if (restoreData->data != NULL) {
            HksFree((void *)restoreData->data);
        }
        HksFree((void *)restoreData);

        ctxParam->uint64Param = (uint64_t)(uintptr_t)newData;
    }
    return HKS_SUCCESS;
}

static int32_t SignVerifyAuth(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet)
{
    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &algParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("append cipher get alg param failed!");
        return ret;
    }

    if (algParam->uint32Param == HKS_ALG_RSA) {
        return HksThreeStageAuth(HKS_AUTH_ID_SIGN_VERIFY_RSA, keyNode);
    } else if (algParam->uint32Param == HKS_ALG_ECC) {
        return HksThreeStageAuth(HKS_AUTH_ID_SIGN_VERIFY_ECC, keyNode);
    } else if (algParam->uint32Param == HKS_ALG_DSA) {
        return HKS_SUCCESS;
    } else if (algParam->uint32Param == HKS_ALG_ED25519) {
        return HKS_SUCCESS;
    } else {
        return HKS_ERROR_INVALID_ALGORITHM;
    }
}

static int32_t CipherAuth(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet)
{
    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_ALGORITHM, &algParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("append cipher get alg param failed!");
        return ret;
    }

    if (algParam->uint32Param == HKS_ALG_AES) {
        return HksThreeStageAuth(HKS_AUTH_ID_SYM_CIPHER, keyNode);
    } else if (algParam->uint32Param == HKS_ALG_RSA) {
        return HksThreeStageAuth(HKS_AUTH_ID_ASYM_CIPHER, keyNode);
    } else {
        return HKS_ERROR_INVALID_ALGORITHM;
    }
}

static int32_t SetCryptoCtx(const struct HuksKeyNode *keyNode, void *ctx)
{
    struct HksParam *ctxParam = NULL;
    int32_t ret = HksGetParam(keyNode->runtimeParamSet, HKS_TAG_CRYPTO_CTX, &ctxParam);
    if (ret != HKS_SUCCESS || ctxParam == NULL) {
        HKS_LOG_E("Set ctx failed!");
        return HKS_FAILURE;
    }

    ctxParam->uint64Param = (uint64_t)(uintptr_t)ctx;
    return HKS_SUCCESS;
}

static void *GetCryptoCtx(const struct HuksKeyNode *keyNode)
{
    struct HksParam *ctxParam = NULL;
    int32_t ret = HksGetParam(keyNode->runtimeParamSet, HKS_TAG_CRYPTO_CTX, &ctxParam);

    return (ret != HKS_SUCCESS || ctxParam == NULL) ? NULL : (void *)(uintptr_t)ctxParam->uint64Param;
}

static void ClearCryptoCtx(const struct HuksKeyNode *keyNode)
{
    struct HksParam *ctxParam = NULL;
    int32_t ret = HksGetParam(keyNode->runtimeParamSet, HKS_TAG_CRYPTO_CTX, &ctxParam);
    if (ret != HKS_SUCCESS || ctxParam == NULL) {
        return;
    }

    ctxParam->uint64Param = (uint64_t)(uintptr_t)NULL;
    return;
}

static void FreeSignVerify(const struct HuksKeyNode *keyNode)
{
    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return;
    }

    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(keyNode->runtimeParamSet, HKS_TAG_ALGORITHM, &algParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("append cipher get alg param failed!");
        return;
    }

    if (algParam->uint32Param != HKS_ALG_ED25519) {
        HksCryptoHalHashFreeCtx(&ctx);
    } else {
        FreeSignVerifyData((void *)ctx);
    }

    ClearCryptoCtx(keyNode);
}

int32_t CoreSignVerifyHash(uint32_t alg, void **ctx, const struct HksBlob *inData, struct HksBlob *outData)
{
    if (alg != HKS_ALG_ED25519) {
        outData->size = MAX_HASH_SIZE;
        outData->data = (uint8_t *)HksMalloc(MAX_HASH_SIZE);
        if (outData->data == NULL) {
            HKS_LOG_E("malloc fail.");
            return HKS_ERROR_MALLOC_FAIL;
        }
        int32_t ret = HksCryptoHalHashFinal(inData, ctx, outData);
        if (ret != HKS_SUCCESS)  {
            HKS_LOG_E("Sign HksCryptoHalHashFinal fail ret : %d", ret);
            return ret;
        }
    } else {
        struct HksBlob *restoreData = (struct HksBlob *)*ctx;
        if (restoreData == NULL) {
            HKS_LOG_E("CoreSignVerifyHash ctx is null.");
            return HKS_FAILURE;
        }
        outData->size = restoreData->size + inData->size;
        outData->data = (uint8_t *)HksMalloc(outData->size);
        if (outData->data == NULL) {
            HKS_LOG_E("CoreSignVerifyHash melloc fail.");
            return HKS_ERROR_MALLOC_FAIL;
        }
        (void)memcpy_s(outData->data, restoreData->size, restoreData->data, restoreData->size);
        (void)memcpy_s(outData->data + restoreData->size, inData->size, inData->data, inData->size);
    }
    return HKS_SUCCESS;
}

int32_t HksCoreSignVerifyThreeStageInit(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    uint32_t alg)
{
    (void)paramSet;
    struct HksParam *algParam = NULL;
    int32_t ret = HksGetParam(keyNode->runtimeParamSet, HKS_TAG_ALGORITHM, &algParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get param get 0x%x failed", HKS_TAG_ALGORITHM);
        return HKS_ERROR_CHECK_GET_ALG_FAIL;
    }

    void *ctx = NULL;
    if (algParam->uint32Param != HKS_ALG_ED25519) {
        uint32_t digest = (alg == HKS_DIGEST_NONE) ? HKS_DIGEST_SHA256 : alg;
        ret = HksCryptoHalHashInit(digest, &ctx);
        if (ret != HKS_SUCCESS)  {
            HKS_LOG_E("HksCoreSignVerifyThreeStageInit HalHashInit fail ret : %d", ret);
            return ret;
        }
    } else {
        struct HksBlob *signVerifyData = (struct HksBlob *)HksMalloc(sizeof(struct HksBlob));
        if (signVerifyData == NULL) {
            HKS_LOG_E("HksCoreSignVerifyThreeStageInit malloc fail.");
            return HKS_ERROR_MALLOC_FAIL;
        }
        signVerifyData->size = 0;
        signVerifyData->data = NULL;
        ctx = (void *)signVerifyData;
    }

    ret = SetCryptoCtx(keyNode, ctx);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Set hks crypto ctx fail");
        FreeSignVerify(keyNode);
        return ret;
    }

    return HKS_SUCCESS;
}

int32_t HksCoreSignVerifyThreeStageUpdate(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature, uint32_t alg)
{
    (void)signature;
    (void)alg;
    (void)paramSet;

    int32_t ret = SignVerifyAuth(keyNode, keyNode->runtimeParamSet);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCoreSignVerifyThreeStageUpdate SignAuth fail ret : %d", ret);
        return ret;
    }

    struct HksParam *algParam = NULL;
    ret = HksGetParam(keyNode->runtimeParamSet, HKS_TAG_ALGORITHM, &algParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("append cipher get alg param failed!");
        return ret;
    }

    ret = StoreSignVerifyMessage(keyNode->runtimeParamSet, srcData);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksCoreSignVerifyThreeStageUpdate hash failed!");
        FreeSignVerify(keyNode);
        return ret;
    }

    return HKS_SUCCESS;
}

int32_t HksCoreSignVerifyThreeStageFinish(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData, uint32_t alg)
{
    (void)paramSet;
    (void)alg;
    int32_t ret;
    struct HksBlob signVerifyData = { 0, NULL };

    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksUsageSpec usageSpec = { 0 };
    HksFillUsageSpec(keyNode->runtimeParamSet, &usageSpec);

    do {
        ret = CoreSignVerifyHash(usageSpec.algType, &ctx, inData, &signVerifyData);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("SighVerifyHash failed!");
            break;
        }
        struct HksBlob rawKey = { 0, NULL };
        ret = HksGetRawKey(keyNode->keyBlobParamSet, &rawKey);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("SighVerify get raw key failed!");
            break;
        }

        usageSpec.digest = (usageSpec.digest == HKS_DIGEST_NONE) ? HKS_DIGEST_SHA256 : usageSpec.digest;
        if (usageSpec.purpose == HKS_KEY_PURPOSE_SIGN) {
            ret = HksCryptoHalSign(&rawKey, &usageSpec, &signVerifyData, outData);
        } else {
            ret = HksCryptoHalVerify(&rawKey, &usageSpec, &signVerifyData, outData);
        }

        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("SignVerify Finish HksCryptoHalSign/Verify fail ret : %d", ret);
        }

        (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
        HKS_FREE_PTR(rawKey.data);
    } while (0);

    if (usageSpec.algType == HKS_ALG_ED25519) {
        FreeSignVerifyData(ctx);
    }
    ClearCryptoCtx(keyNode);
    HKS_FREE_BLOB(signVerifyData);
    return ret;
}

int32_t HksCoreSignVerifyThreeStageAbort(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    uint32_t alg)
{
    (void)paramSet;
    (void)alg;

    FreeSignVerify(keyNode);

    return HKS_SUCCESS;
}

int32_t HksCoreCryptoThreeStageInit(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    uint32_t alg)
{
    (void)alg;
    int32_t ret;
    struct HksBlob rawKey = { 0, NULL };
    struct HksUsageSpec *usageSpec = NULL;

    do {
        ret = CipherAuth(keyNode, paramSet);
        if (ret != HKS_SUCCESS) {
            return ret;
        }

        struct HksParam *purposeParam = NULL;
        ret = HksGetParam(keyNode->runtimeParamSet, HKS_TAG_PURPOSE, &purposeParam);
        if (ret != HKS_SUCCESS) {
            break;
        }

        uint8_t tmpData[32];
        struct HksBlob tmpInData = {32, tmpData};
        if (purposeParam->uint32Param == HKS_KEY_PURPOSE_ENCRYPT) {
            ret = HksBuildCipherUsageSpec(paramSet, true, &tmpInData, &usageSpec);
        } else {
            ret = HksBuildCipherUsageSpec(paramSet, false, &tmpInData, &usageSpec);
        }
        if (ret != HKS_SUCCESS) {
            return ret;
        }

        ret = HksGetRawKey(keyNode->keyBlobParamSet, &rawKey);
        if (ret != HKS_SUCCESS) {
            HksFree(usageSpec);
            return ret;
        }

        void *ctx = NULL;
        if (purposeParam->uint32Param == HKS_KEY_PURPOSE_ENCRYPT) {
            ret = HksCryptoHalEncryptInit(&rawKey, usageSpec, &ctx);
        } else {
            ret = HksCryptoHalDecryptInit(&rawKey, usageSpec, &ctx);
        }
        if (ret != HKS_SUCCESS) {
            break;
        }

        ret = SetCryptoCtx(keyNode, ctx);
        if (ret != HKS_SUCCESS) {
            break;
        }
    } while (0);

    (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
    HKS_FREE_PTR(rawKey.data);
    HksFree(usageSpec);

    return ret;
}

int32_t HksCoreCryptoThreeStageUpdate(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData, uint32_t alg)
{
    HKS_LOG_D("HksCoreEncryptThreeStageUpdate start");
    int32_t ret = CipherAuth(keyNode, paramSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    if (alg == HKS_ALG_AES) {
        if (outData->size < inData->size) {
            HKS_LOG_E("decryptfinal, out buffer too small size: %u, inSize: %u", outData->size, inData->size);
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
    }

    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksParam *purposeParam = NULL;
    ret = HksGetParam(keyNode->runtimeParamSet, HKS_TAG_PURPOSE, &purposeParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("append cipher get purpose param failed!");
        return ret;
    }

    if (purposeParam->uint32Param == HKS_KEY_PURPOSE_ENCRYPT) {
        ret = HksCryptoHalEncryptUpdate(inData, ctx, outData, alg);
    } else {
        ret = HksCryptoHalDecryptUpdate(inData, ctx, outData, alg);
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("cipher failed! ret : %d", ret);
        return ret;
    }

    HKS_LOG_D("HksCoreEncryptThreeStageUpdate End");
    return HKS_SUCCESS;
}

int32_t HksCoreEncryptThreeStageFinish(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData, uint32_t alg)
{
    (void)paramSet;

    HKS_LOG_D("HksCoreEncryptThreeStageFinish start");

    struct HksBlob tag = { 0, NULL };
    int32_t ret = HksGetEncryptAeTag(paramSet, inData, outData, &tag);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("cipher encrypt get ae tag failed!");
        return ret;
    }

    ret = HksCheckFinishOutSize(true, keyNode->runtimeParamSet, inData, outData);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    ret = HksCryptoHalEncryptFinal(inData, &ctx, outData, &tag, alg);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("cipher DecryptFinish failed! ret : %d", ret);
        return ret;
    }

    outData->size += tag.size;
    ClearCryptoCtx(keyNode);

    HKS_LOG_D("HksCoreEncryptThreeStageFinish end");
    return HKS_SUCCESS;
}

int32_t HksCoreCryptoThreeStageAbort(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    uint32_t alg)
{
    (void)paramSet;
    (void)alg;

    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    HksCryptoHalEncryptFreeCtx(&ctx, alg);
    ClearCryptoCtx(keyNode);

    return HKS_SUCCESS;
}

int32_t HksCoreDecryptThreeStageFinish(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData, uint32_t alg)
{
    HKS_LOG_D("HksCoreDecryptThreeStageFinish start");

    bool isAes = false;
    bool isAeMode = false;

    int32_t ret = HksCheckAesAeMode(paramSet, &isAes, &isAeMode);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get aeMode failed!");
        return ret;
    }

    struct HksBlob tag = { 0, NULL };
    if (isAes && isAeMode) {
        struct HksParam *tagParam = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_AE_TAG, &tagParam);
        if (ret != HKS_SUCCESS || tagParam == NULL) {
            HKS_LOG_E("get tag failed!");
            return ret;
        }
        tag = tagParam->blob;
    }

    ret = HksCheckFinishOutSize(false, keyNode->runtimeParamSet, inData, outData);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    ret = HksCryptoHalDecryptFinal(inData, &ctx, outData, &tag, alg);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("cipher DecryptFinish failed! ret : %d", ret);
        return ret;
    }

    ClearCryptoCtx(keyNode);
    HKS_LOG_D("HksCoreDecryptThreeStageFinish end");
    return HKS_SUCCESS;
}

static int32_t GetRawkey(const struct HuksKeyNode *keyNode, struct HksBlob *rawKey)
{
    if (GetCryptoCtx(keyNode) != NULL) {
        HKS_LOG_E("avoid running into this function multiple times!");
        return HKS_FAILURE;
    }

    int32_t ret = HksThreeStageAuth(HKS_AUTH_ID_DERIVE, keyNode);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("derive auth failed!");
        return ret;
    }

    ret = HksGetRawKey(keyNode->keyBlobParamSet, rawKey);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Derive get raw key failed!");
        return ret;
    }

    return ret;
}

int32_t HksCoreDeriveThreeStageInit(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    uint32_t alg)
{
    (void)keyNode;
    (void)paramSet;
    (void)alg;

    HKS_LOG_D("HksCoreDeriveThreeStageInit start");
    return HKS_SUCCESS;
}

int32_t HksCoreDeriveThreeStageUpdate(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *derive, uint32_t alg)
{
    (void)srcData;
    (void)alg;
    (void)derive;
    int32_t ret;
    struct HksBlob rawKey = { 0, NULL };

    do {
        ret = GetRawkey(keyNode, &rawKey);
        if (ret != HKS_SUCCESS) {
            return ret;
        }

        struct HksBlob *srcDataTemp = (struct HksBlob *)HksMalloc(sizeof(struct HksBlob));
        if (srcDataTemp == NULL) {
            HKS_LOG_E("malloc srcDataTemp failed.");
            break;
        }
        srcDataTemp->size = rawKey.size;
        srcDataTemp->data = (uint8_t *)HksMalloc(rawKey.size);
        if (srcDataTemp->data == NULL) {
            HKS_FREE_PTR(srcDataTemp);
            ret = HKS_ERROR_MALLOC_FAIL;
            HKS_LOG_E("malloc srcDataTemp->data failed.");
            break;
        }

        struct HksKeyDerivationParam derParam = { { 0, NULL }, { 0, NULL }, 0, 0 };
        struct HksKeySpec derivationSpec = { 0, 0, &derParam };
        HksFillKeySpec(paramSet, &derivationSpec);
        HksFillKeyDerivationParam(paramSet, &derParam);
        ret = HksCryptoHalDeriveKey(&rawKey, &derivationSpec, srcDataTemp);
        if (ret != HKS_SUCCESS) {
            HKS_FREE_PTR(srcDataTemp->data);
            HKS_FREE_PTR(srcDataTemp);
            HKS_LOG_E("HksCryptoHalDeriveKey fail");
            break;
        }

        if (SetCryptoCtx(keyNode, (void *)srcDataTemp) != HKS_SUCCESS) {
            HKS_FREE_PTR(srcDataTemp->data);
            HKS_FREE_PTR(srcDataTemp);
            ret = HKS_FAILURE;
            break;
        }
    } while (0);

    (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
    HKS_FREE_PTR(rawKey.data);

    return ret;
}

int32_t HksCoreDeriveThreeStageFinish(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData, uint32_t alg)
{
    HKS_LOG_D("HksCoreDeriveThreeStageFinish start");
    (void)inData;
    (void)alg;
    int32_t ret;

    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksBlob *restoreData = (struct HksBlob *)ctx;
    if (restoreData == NULL) {
        HKS_LOG_E("derive restoreData is NULL!");
        return HKS_ERROR_NULL_POINTER;
    }

    bool needStore = false;
    struct HksParam *storage = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_KEY_STORAGE_FLAG, &storage);
    if (ret == HKS_SUCCESS) {
        if (storage != NULL && storage->uint32Param == HKS_STORAGE_PERSISTENT) {
            needStore = true;
        }
    }

    if (needStore) {
        ret = HksBuildKeyBlob(NULL, HKS_KEY_FLAG_DERIVE_KEY, restoreData, paramSet, outData);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksBuildKeyBlob failed! ret: %d", ret);
            return ret;
        }
    } else {
        outData->size = restoreData->size;
        (void)memcpy_s(outData->data, outData->size, restoreData->data, restoreData->size);
    }

    ClearCryptoCtx(keyNode);
    HKS_FREE_BLOB(*restoreData);
    HKS_FREE_PTR(restoreData);
    return HKS_SUCCESS;
}

int32_t HksCoreDeriveThreeStageAbort(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    uint32_t alg)
{
    (void)paramSet;
    (void)alg;

    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksBlob *restoreData = (struct HksBlob *)ctx;
    if (restoreData == NULL) {
        HKS_LOG_E("restoreData is NULL");
        return HKS_FAILURE;
    }

    ClearCryptoCtx(keyNode);
    HKS_FREE_BLOB(*restoreData);
    HKS_FREE_PTR(restoreData);
    return HKS_SUCCESS;
}

int32_t HksCoreAgreeThreeStageInit(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    uint32_t alg)
{
    (void)keyNode;
    (void)paramSet;
    (void)alg;

    return HKS_SUCCESS;
}

static int32_t HksCoreAgreeBuildData(struct HksBlob *signature, struct HksBlob **agreeTemp)
{
    *agreeTemp = (struct HksBlob *)HksMalloc(sizeof(struct HksBlob));
    if (*agreeTemp == NULL) {
        HKS_LOG_E("malloc agreeTemp failed.");
        return HKS_FAILURE;
    }

    (*agreeTemp)->size = signature->size;
    (*agreeTemp)->data = (uint8_t *)HksMalloc(signature->size);
    if ((*agreeTemp)->data == NULL) {
        HKS_LOG_E("malloc agreeTemp->data failed.");
        HKS_FREE_PTR(*agreeTemp);
        return HKS_FAILURE;
    }
    return HKS_SUCCESS;
}

static void HksCoreAgreeFreeData(struct HksBlob **agreeTemp)
{
    if (*agreeTemp != NULL) {
        HKS_FREE_PTR((*agreeTemp)->data);
        HKS_FREE_PTR(*agreeTemp);
    }
}

int32_t HksCoreAgreeThreeStageUpdate(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature, uint32_t alg)
{
    (void)paramSet;
    (void)alg;

    int32_t ret;
    struct HksBlob rawKey = { 0, NULL };
    struct HksBlob publicKey = { 0, NULL };

    do {
        if (GetCryptoCtx(keyNode) != NULL) {
            HKS_LOG_E("avoid running into this function multiple times!");
            return HKS_FAILURE;
        }

        ret = GetHksInnerKeyFormat(keyNode->runtimeParamSet, srcData, &publicKey);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get public key from x509 format failed, ret = %d.", ret);
            return ret;
        }

        struct HksBlob *agreeTemp = NULL;
        ret = HksCoreAgreeBuildData(signature, &agreeTemp);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksCoreAgreeBuildData failed, ret = %d.", ret);
            break;
        }

        ret = HksGetRawKey(keyNode->keyBlobParamSet, &rawKey);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("agree get raw key failed!");
            HksCoreAgreeFreeData(&agreeTemp);
            break;
        }

        struct HksKeySpec agreeSpec = { 0 };
        HksFillKeySpec(keyNode->runtimeParamSet, &agreeSpec);
        ret = HksCryptoHalAgreeKey(&rawKey, &publicKey, &agreeSpec, agreeTemp);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksCryptoHalAgreeKey failed, ret = %d.", ret);
            HksCoreAgreeFreeData(&agreeTemp);
            break;
        }

        ret = SetCryptoCtx(keyNode, (void *)agreeTemp);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("Set hks crypto ctx fail");
            HksCoreAgreeFreeData(&agreeTemp);
            break;
        }
    } while (0);

    HKS_FREE_PTR(rawKey.data);
    HKS_FREE_PTR(publicKey.data);
    return ret;
}

int32_t HksCoreAgreeThreeStageFinish(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData, uint32_t alg)
{
    (void)inData;
    (void)alg;
    int32_t ret;

    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksBlob *restoreData = (struct HksBlob *)ctx;
    if (restoreData == NULL) {
        HKS_LOG_E("agree restoreData is NULL!");
        return HKS_FAILURE;
    }

    bool needStore = false;
    struct HksParam *storage = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_KEY_STORAGE_FLAG, &storage);
    if (ret == HKS_SUCCESS) {
        if (storage != NULL && storage->uint32Param == HKS_STORAGE_PERSISTENT) {
            needStore = true;
        }
    }

    if (needStore) {
        ret = HksBuildKeyBlob(NULL, HKS_KEY_FLAG_AGREE_KEY, restoreData, paramSet, outData);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksBuildKeyBlob failed! ret: %d", ret);
            return ret;
        }
    } else {
        outData->size = restoreData->size;
        (void)memcpy_s(outData->data, outData->size, restoreData->data, outData->size);
    }

    ClearCryptoCtx(keyNode);
    HKS_FREE_BLOB(*restoreData);
    HKS_FREE_PTR(restoreData);
    return HKS_SUCCESS;
}

int32_t HksCoreAgreeThreeStageAbort(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet, uint32_t alg)
{
    (void)paramSet;
    (void)alg;

    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksBlob *restoreData = (struct HksBlob *)ctx;
    if (restoreData == NULL) {
        HKS_LOG_E("restoreData is NULL");
        return HKS_FAILURE;
    }

    ClearCryptoCtx(keyNode);
    HKS_FREE_BLOB(*restoreData);
    HKS_FREE_PTR(restoreData);
    return HKS_SUCCESS;
}

int32_t HksCoreMacThreeStageInit(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    uint32_t alg)
{
    (void)paramSet;
    struct HksBlob rawKey = { 0, NULL };

    do {
        int32_t ret = HksGetRawKey(keyNode->keyBlobParamSet, &rawKey);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("Derive get raw key failed!");
            return ret;
        }

        void *ctx = NULL;
        ret = HksCryptoHalHmacInit(&rawKey, alg, &ctx);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("hmac init failed! ret : %d", ret);
            break;
        }

        ret = SetCryptoCtx(keyNode, ctx);
        if (ret != HKS_SUCCESS) {
            HksCoreMacThreeStageAbort(keyNode, paramSet, alg);
            HKS_LOG_E("Set hks crypto ctx fail");
            break;
        }
    } while (0);

    (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
    HKS_FREE_PTR(rawKey.data);

    return HKS_SUCCESS;
}

int32_t HksCoreMacThreeStageUpdate(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac, uint32_t alg)
{
    (void)paramSet;
    (void)mac;
    (void)alg;
    int32_t ret;

    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    ret = HksCryptoHalHmacUpdate(srcData, ctx);
    if (ret != HKS_SUCCESS) {
        ClearCryptoCtx(keyNode);
        HKS_LOG_E("hmac update failed! ret : %d", ret);
        return ret;
    }

    return HKS_SUCCESS;
}

int32_t HksCoreMacThreeStageFinish(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData, uint32_t alg)
{
    (void)paramSet;
    (void)alg;
    int32_t ret;

    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    ret = HksCryptoHalHmacFinal(inData, &ctx, outData);
    if (ret != HKS_SUCCESS) {
        ClearCryptoCtx(keyNode);
        HKS_LOG_E("hmac final failed! ret : %d", ret);
        return ret;
    }
    ClearCryptoCtx(keyNode);

    return HKS_SUCCESS;
}

int32_t HksCoreMacThreeStageAbort(const struct HuksKeyNode *keyNode, const struct HksParamSet *paramSet, uint32_t alg)
{
    (void)alg;
    (void)paramSet;

    void *ctx = GetCryptoCtx(keyNode);
    if (ctx == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    HksCryptoHalHmacFreeCtx(&ctx);
    ClearCryptoCtx(keyNode);

    return HKS_SUCCESS;
}

#ifdef _STORAGE_LITE_
static int32_t GetMacKey(const struct HksBlob *salt, struct HksBlob *macKey)
{
    uint8_t keyBuf[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_256)] = {0};
    struct HksBlob mk = { HKS_KEY_BYTES(HKS_AES_KEY_SIZE_256), keyBuf };

    int32_t ret = HksCryptoHalGetMainKey(NULL, &mk);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get kek failed, ret = %d", ret);
        return ret;
    }

    struct HksKeyDerivationParam derParam = {
        .salt = *salt,
        .iterations = HKS_KEY_BLOB_DERIVE_CNT,
        .digestAlg = HKS_DIGEST_SHA256,
    };
    struct HksKeySpec derivationSpec = { HKS_ALG_PBKDF2, HKS_KEY_BYTES(HKS_AES_KEY_SIZE_256), &derParam };
    ret = HksCryptoHalDeriveKey(&mk, &derivationSpec, macKey);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get keyblob derive key failed!");
    }

    (void)memset_s(mk.data, mk.size, 0, mk.size);
    return ret;
}

int32_t HksCoreCalcMacHeaderThreeStage(const struct HksParamSet *paramSet, const struct HksBlob *salt,
    const struct HksBlob *srcData, struct HksBlob *mac)
{
    /* 1. get mac key by derive from salt */
    uint8_t keyBuf[HKS_KEY_BYTES(HKS_AES_KEY_SIZE_256)] = {0};
    struct HksBlob macKey = { HKS_KEY_BYTES(HKS_AES_KEY_SIZE_256), keyBuf };
    int32_t ret = GetMacKey(salt, &macKey);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get mac key failed, ret = %d", ret);
        return ret;
    }

    struct HksParam *digestParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_DIGEST, &digestParam);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("calc mac header get HKS_TAG_DIGEST param failed, ret = %d", ret);
        (void)memset_s(macKey.data, macKey.size, 0, macKey.size);
        return ret;
    }

    /* 2. do mac */
    ret = HksCryptoHalHmac(&macKey, digestParam->uint32Param, srcData, mac);
    (void)memset_s(macKey.data, macKey.size, 0, macKey.size);
    return ret;
}
#endif
#endif /* _CUT_AUTHENTICATE_ */
