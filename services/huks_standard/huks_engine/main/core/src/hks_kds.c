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

#include "hks_client_service_adapter.h"
#include "hks_crypto_hal.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "securec.h"

// static const struct HksKeySpec KDS_ECC_SPEC = {
//     .algType = HKS_ALG_ECC,
//     .keyLen = HKS_ECC_KEY_SIZE_256,
//     .algParam = NULL,
// };

static const struct HksKeySpec KDS_ECDH_SPEC = {
    .algType = HKS_ALG_ECDH,
    .keyLen = HKS_ECC_KEY_SIZE_256,
    .algParam = NULL,
};

static const enum HksKeyDigest HMAC_DIGEST = HKS_DIGEST_SHA256;

static const uint32_t KDS_ORDERED_VALID_TAGS[] = {
    HKS_TAG_SALT,
    HKS_TAG_AGREE_PUBLIC_KEY,
    HKS_TAG_INFO,
    HKS_TAG_IV,
    HKS_TAG_ASSOCIATED_DATA,
    HKS_TAG_AE_TAG,
    HKS_TAG_CRYPTO_CTX,
};

// #define KDS_PLATFORM_PRI_KEY_SIZE 51
// static const uint8_t KDS_PLATFORM_PRI_KEY[KDS_PLATFORM_PRI_KEY_SIZE] = {
//     48, 49, 2, 1, 1, 4, 32, 159, 140, 96, 146, 92, 151, 67, 213, 113,
//     71, 145, 0, 245, 100, 157, 220, 165, 140, 37, 88, 170, 2, 80, 61,
//     8, 182, 5, 77, 176, 116, 56, 10, 160, 10, 6, 8, 42, 134, 72, 206,
//     61, 3, 1, 7
// };
#define KDS_PLATFORM_PRI_KEY_SIZE 116
// static const uint8_t KDS_PLATFORM_PRI_KEY[KDS_PLATFORM_PRI_KEY_SIZE] = {
// 2,0,0,0,0,1,0,0,32,0,0,0,32,0,0,0,32,0,0,0,40,34,254,220,207,35,20,25,22,166,
// 190,152,29,122,17,25,37,170,188,207,1,151,147,51,181,134,108,183,230,9,154,
// 147,185,70,213,187,107,142,3,83,192,166,45,153,61,90,16,207,141,138,236,
// 156,57,254,213,132,55,231,68,12,244,252,173,178,241,219,39,233,216,58,182,63,214,101,27,46,198,47,103,96,231,144,103,71,138,163,3,6,31,95,201,50,75,164,154,80
// };

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
        uint32_t tag = KDS_ORDERED_VALID_TAGS[i];
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

// oh上为写死的key，如果直接返回固定的key，返回值可以为空, TODO:salt是否要判断，返回TA私钥和CA私钥
// static int32_t GetPlatformPrivateKey(const struct HksBlob *salt, struct HksBlob *platformPrivateKey)
// {
//     platformPrivateKey->size = KDS_PLATFORM_PRI_KEY_SIZE;
//     platformPrivateKey->data = (uint8_t *)KDS_PLATFORM_PRI_KEY;
//     return HKS_SUCCESS;
// }

static int32_t DoGenEcdhSharedKey(const struct HksBlob *pubKey,
    struct HksBlob *salt, struct HksBlob *sharedKey, uint32_t saltType)
{
    if (pubKey->size != KDS_TMP_PK_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    // TODO: salt:15,16均可？
    if (salt->size < KDS_SALT_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (saltType == KDS_SALT_TYPE_TA) {
        (void)memset_s(salt + KDS_SALT_SIZE, KDS_SALT_ADDED_BYTE_SIZE, KDS_SALT_ADDED_BYTE_TA, KDS_SALT_ADDED_BYTE_SIZE);
    }
    if (saltType == KDS_SALT_TYPE_CA) {
        (void)memset_s(salt + KDS_SALT_SIZE, KDS_SALT_ADDED_BYTE_SIZE, KDS_SALT_ADDED_BYTE_CA, KDS_SALT_ADDED_BYTE_SIZE);
    }
    // 平台私钥注意内存管理，如果调用hal函数，则由其申请内存，如果是写死的平台私钥，为常量，则不用管理内存
    // struct HksBlob platformPrivateKey = { .size = 0, .data = NULL };
    // int32_t ret = GetPlatformPrivateKey(salt, &platformPrivateKey);
    // if (platformPrivateKey.data == NULL) {
    //     return HKS_ERROR_INVALID_ARGUMENT;
    // }
    uint8_t KDS_PLATFORM_PRI_KEY[KDS_PLATFORM_PRI_KEY_SIZE] = {
    2,0,0,0,0,1,0,0,32,0,0,0,32,0,0,0,32,0,0,0,40,34,254,220,207,35,20,25,22,166,
    190,152,29,122,17,25,37,170,188,207,1,151,147,51,181,134,108,183,230,9,154,
    147,185,70,213,187,107,142,3,83,192,166,45,153,61,90,16,207,141,138,236,
    156,57,254,213,132,55,231,68,12,244,252,173,178,241,219,39,233,216,58,182,63,214,101,27,46,198,47,103,96,231,144,103,71,138,163,3,6,31,95,201,50,75,164,154,80
    };
    struct HksBlob platformPrivateKey = { .size = KDS_PLATFORM_PRI_KEY_SIZE, .data = KDS_PLATFORM_PRI_KEY };
    HKS_LOG_E("DoGenEcdhSharedKey hal start");
    int32_t ret = HksCryptoHalAgreeKey(&platformPrivateKey, pubKey, &KDS_ECDH_SPEC, sharedKey);
    // HksFree(platformPrivateKey.data);
    HKS_LOG_E("DoGenEcdhSharedKey end");
    return ret;
}

static int32_t DoHmacSha256(const struct HksBlob *customInfo,
    const struct HksBlob *sharedKey, struct HksBlob *wrapedKey)
{
    if (customInfo->size > KDS_CUSTOM_INFO_SIZE) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = HksCryptoHalHmac(sharedKey, HMAC_DIGEST, customInfo, wrapedKey);
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

int32_t HuksCoreChipsetPlatformDecrypt(const struct HksParamSet *paramSet, struct HksBlob *plainText, uint32_t saltType)
{
    HKS_LOG_E("start test");
    // basic check for plainText and paramSet
    int32_t ret = CheckBlob(plainText);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Check plainText failed")
    ret = CheckKdsParams(paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Check kds params failed")

    // check saltType
    if (saltType != KDS_SALT_TYPE_TA && saltType != KDS_SALT_TYPE_CA) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    // deep copy of paramSet
    struct HksParamSet *paramSecureSet = NULL;
    ret = HksGetParamSet(paramSet, paramSet->paramSetSize, &paramSecureSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "deep copy params failed")

    // specialized check for text
    struct HksParam *cipherTextParam = NULL;
    (void)HksGetParam(paramSecureSet, HKS_TAG_CRYPTO_CTX, &cipherTextParam);
    ret = CheckKdsText(&cipherTextParam->blob, plainText);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&paramSecureSet);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

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
        HKS_LOG_E("start ecdh");
        ret = DoGenEcdhSharedKey(&tmpPkParam->blob, &saltParam->blob, &sharedKey, saltType);
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

    (void)memset_s(sharedKey.data, KDS_SHARED_KEY_SIZE, 0, KDS_SHARED_KEY_SIZE);
    (void)memset_s(wrapedKey.data, KDS_WRAPED_KEY_SIZE, 0, KDS_WRAPED_KEY_SIZE);
    HKS_LOG_E("kds free start");
    HksFree(sharedKey.data);
    HksFree(wrapedKey.data);
    HksFreeParamSet(&paramSecureSet);
    HKS_LOG_E("kds free end");
    return ret;
}