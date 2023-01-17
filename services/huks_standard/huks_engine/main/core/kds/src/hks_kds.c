/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "hks_kds.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"

static const struct HksKeySpec kdsEccSpec = {
    .algType = HKS_ALG_ECC,
    .keyLen = HKS_ECC_KEY_SIZE_256,
    .algParam = NULL,
};

static const struct HksKeySpec kdsEcdhSpec = {
    .algType = HKS_ALG_ECDH,
    .keyLen = HKS_ECC_KEY_SIZE_256,
    .algParam = NULL,
};

static enum HksKeyDigest hmacDigest = HKS_DIGEST_SHA256;

static uint32_t g_kdsOrderedValidTags[] = {
    HKS_TAG_SALT,
    HKS_TAG_AGREE_PUBLIC_KEY,
    HKS_TAG_INFO,
    HKS_TAG_IV,
    HKS_TAG_ASSOCIATED_DATA,
    HKS_TAG_AE_TAG,
    HKS_TAG_CRYPTO_CTX,
};

static int32_t CheckKdsParams(const struct HksParamSet *paramSet)
{
    int32_t ret = HksCheckParamSet(paramSet, paramSet->paramSetSize);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT, "Check params failed")

    if (paramSet->paramsCnt != KDS_INPUT_PARAMS_NUMBER) {
        HKS_LOG_E("params number wrong");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    uint32_t validCount = 0;
    for (uint32_t i = 0; i < KDS_INPUT_PARAMS_NUMBER; i++) {
        uint32_t tag = g_kdsOrderedValidTags[i];
        for (uint32_t ii = 0; ii < KDS_INPUT_PARAMS_NUMBER; ii++) {
            struct HksParam tmp = paramSet->params[ii];
            if (CheckBlob(&tmp.blob) != HKS_SUCCESS) {
                HKS_LOG_E("invalid blob");
                return HKS_ERROR_INVALID_ARGUMENT;
            }
            if (tag == tmp.tag) {
                validCount++;
                break;
            }
        }
    }

    if (validCount != KDS_INPUT_PARAMS_NUMBER) {
        HKS_LOG_E("valid number wrong");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return ret;
}

// tdd时注意该check函数
static int32_t CheckKdsText(const struct HksBlob *cipherText, const struct HksBlob *plainText)
{
    if (cipherText->size != plainText->size) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (plainText->size > KDS_TEXT_MAX_LEN || plainText->size < KDS_TEXT_MIN_LEN) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (plainText->size % KDS_TEXT_LEN_FACTOR != 0) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

// oh上为写死的key，如果直接返回key，返回值可以为空
static int32_t GetPlatformPrivateKey(const struct HksBlob *salt, struct HksBlob *platformPrivateKey)
{
    return HksCryptoHalGenerateKey(&kdsEccSpec, platformPrivateKey);
}

static int32_t DoGenEcdhSharedKey(const struct HksBlob *pubKey,
    const struct HksBlob *salt, struct HksBlob *sharedKey)
{
    if (pubKey->size != KDS_TMP_PK_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (salt->size != KDS_SALT_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    struct HksBlob platformPrivateKey = { .size = 0, .data = NULL };
    int32_t ret = GetPlatformPrivateKey(salt, &platformPrivateKey);
    if (platformPrivateKey.data == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    ret = HksCryptoHalAgreeKey(&platformPrivateKey, pubKey, &kdsEcdhSpec, sharedKey);
    HksFree(platformPrivateKey.data);
    return ret;
}

static int32_t DoHmacSha256(const struct HksBlob *customInfo,
    const struct HksBlob *sharedKey, struct HksBlob *wrapedKey)
{
    if (customInfo->size != KDS_CUSTOM_INFO_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    struct HksBlob processInfo = { .size = KDS_PROCESS_INFO_MAX_SIZE,
        .data = (uint8_t *)HksMalloc(KDS_PROCESS_INFO_MAX_SIZE) };
    if (processInfo.data == NULL) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    // int32_t ret = HuksGetProcessName(&processInfo);
    // if (ret != HKS_SUCCESS) {
    //     HksFree(processInfo.data);
    //     return ret;
    // }
    int32_t ret;

    uint32_t messageSize = processInfo.size + customInfo->size;
    struct HksBlob message = { .size = messageSize, .data = (uint8_t *)HksMalloc(messageSize) };
    if (message.data == NULL) {
        HksFree(processInfo.data);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    uint32_t i = 0;
    for (; i < processInfo.size; i++) {
        message.data[i] = processInfo.data[i];
    }
    for (; i < messageSize; i++) {
        message.data[i] = customInfo->data[i - processInfo.size];
    }

    ret = HksCryptoHalHmac(sharedKey, hmacDigest, &message, wrapedKey);
    HksFree(processInfo.data);
    HksFree(message.data);
    return ret;
}

static int32_t DoKdsDecrypt(const struct HksParamSet *paramSecureSet,
    const struct HksBlob *wrapedKey, struct HksBlob *plainText)
{
    struct HksParam *cipherTextParam = NULL;
    (void)HksGetParam(paramSecureSet, HKS_TAG_CRYPTO_CTX, &cipherTextParam);
    struct HksParam *ivParam = NULL;
    (void)HksGetParam(paramSecureSet, HKS_TAG_IV, &ivParam);
    struct HksParam *aadParam = NULL;
    (void)HksGetParam(paramSecureSet, HKS_TAG_ASSOCIATED_DATA, &aadParam);
    struct HksParam *macParam = NULL;
    (void)HksGetParam(paramSecureSet, HKS_TAG_AE_TAG, &macParam);
    struct HksBlob aad = aadParam->blob;
    struct HksBlob iv = ivParam->blob;
    struct HksBlob mac = macParam->blob;
    struct HksBlob cipherText = cipherTextParam->blob;
    if (aad.size != KDS_AAD_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (iv.size != KDS_IV_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (mac.size != KDS_MAC_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    struct HksAeadParam aeadParam = {
        .nonce = iv,
        .aad = aad,
        .tagDec = mac,
        .payloadLen = 0,
    };
    struct HksUsageSpec kdsDecryptSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_GCM,
        .padding = HKS_PADDING_NONE,
        .digest = HKS_DIGEST_NONE,
        .purpose = HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&aeadParam,
    };
    return HksCryptoHalDecrypt(wrapedKey, &kdsDecryptSpec, &cipherText, plainText);
}

int32_t HuksCoreChipsetPlatformDecrypt(const struct HksParamSet *paramSet, struct HksBlob *plainText)
{
    // basic check for plainText and paramSet
    int32_t ret = CheckBlob(plainText);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Check plainText failed")
    ret = CheckKdsParams(paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Check kds params failed")

    // deep copy of paramSet
    struct HksParamSet *paramSecureSet = NULL;
    ret = HksGetParamSet(paramSet, paramSet->paramSetSize, &paramSecureSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "deep copy params failed")

    // specialized check for text
    struct HksParam *cipherTextParam = NULL;
    (void)HksGetParam(paramSecureSet, HKS_TAG_CRYPTO_CTX, &cipherTextParam);
    ret = CheckKdsText(&cipherTextParam->blob, plainText);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check text failed")

    // malloc for key
    struct HksBlob sharedKey = { .size = KDS_SHARED_KEY_SIZE, .data = (uint8_t *)HksMalloc(KDS_SHARED_KEY_SIZE) };
    if (sharedKey.data == NULL) {
        HksFreeParamSet(&paramSecureSet);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    struct HksBlob wrapedKey = { .size = KDS_WRAPED_KEY_SIZE, .data = (uint8_t *)HksMalloc(KDS_WRAPED_KEY_SIZE) };
    if (wrapedKey.data == NULL) {
        HksFreeParamSet(&paramSecureSet);
        HksFree(sharedKey.data);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    do {
        // do ecdh to get sharedKey
        struct HksParam *saltParam = NULL;
        (void)HksGetParam(paramSecureSet, HKS_TAG_SALT, &saltParam);
        struct HksParam *tmpPkParam = NULL;
        (void)HksGetParam(paramSecureSet, HKS_TAG_AGREE_PUBLIC_KEY, &tmpPkParam);
        ret = DoGenEcdhSharedKey(&tmpPkParam->blob, &saltParam->blob, &sharedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ecdh get sharedKey failed")

        // do hmac to get wrapedKey
        struct HksParam *customInfoParam = NULL;
        (void)HksGetParam(paramSecureSet, HKS_TAG_INFO, &customInfoParam);
        ret = DoHmacSha256(&customInfoParam->blob, &sharedKey, &wrapedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hmac get wrapedKey failed")

        // do aes decrypt
        ret = DoKdsDecrypt(paramSecureSet, &wrapedKey, plainText);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "aes decrypt failed")
    } while (0);

    HksFree(sharedKey.data);
    HksFree(wrapedKey.data);
    HksFreeParamSet(&paramSecureSet);
    return ret;
}