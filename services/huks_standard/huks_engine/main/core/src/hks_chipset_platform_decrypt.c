/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#include "hks_chipset_platform_decrypt.h"

#include "hks_chipset_platform_key.h"
#include "hks_client_service_adapter.h"
#include "hks_crypto_hal.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_template.h"
#include "hks_type.h"

#include "securec.h"
#include <stdbool.h>

#ifdef HKS_SUPPORT_CHIPSET_PLATFORM_DECRYPT

static const uint32_t ORDERED_VALID_TAGS[PLATFORM_KEY_INPUT_PARAMS_COUNT] = {
    HKS_TAG_SALT,
    HKS_TAG_PEER_PUBLIC_KEY,
    HKS_TAG_INFO,
    HKS_TAG_IV,
    HKS_TAG_ASSOCIATED_DATA,
    HKS_TAG_AE_TAG,
    HKS_TAG_CIPHER_TEXT,
};

static int32_t CheckParams(const struct HksParamSet *paramSet)
{
    if (paramSet == NULL) {
        HKS_LOG_E("invalid paramSet");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = HksCheckParamSet(paramSet, paramSet->paramSetSize);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT, "Check params failed")

    if (paramSet->paramsCnt != PLATFORM_KEY_INPUT_PARAMS_COUNT) {
        HKS_LOG_E("invalid params count");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    for (uint32_t i = 0; i < PLATFORM_KEY_INPUT_PARAMS_COUNT; ++i) {
        if (GetTagType((enum HksTag)(paramSet->params[i].tag)) != HKS_TAG_TYPE_BYTES) {
            HKS_LOG_E("params not bytes");
            return HKS_ERROR_INVALID_ARGUMENT;
        }
        ret = CheckBlob(&paramSet->params[i].blob);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT, "Check params failed")
    }

    // check whether all required tags are present or duplicated
    uint32_t uniqCount = 0;
    for (uint32_t i = 0; i < PLATFORM_KEY_INPUT_PARAMS_COUNT; ++i) {
        for (uint32_t j = 0; j < PLATFORM_KEY_INPUT_PARAMS_COUNT; ++j) {
            if (paramSet->params[j].tag == ORDERED_VALID_TAGS[i]) {
                uniqCount++;
                break;
            }
        }
    }

    if (uniqCount != PLATFORM_KEY_INPUT_PARAMS_COUNT) {
        HKS_LOG_E("param tags repeat");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return ret;
}

static int32_t CheckText(const struct HksBlob *cipherText, const struct HksBlob *plainText)
{
    if (cipherText->size != plainText->size) {
        HKS_LOG_E("cipher text len %" LOG_PUBLIC "d does not equal to plain text len %" LOG_PUBLIC "d",
            cipherText->size, plainText->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (plainText->size > PLATFORM_KEY_TEXT_MAX_LEN || plainText->size < PLATFORM_KEY_TEXT_MIN_LEN) {
        HKS_LOG_E("plain text length out of range %" LOG_PUBLIC "d", plainText->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

static int32_t DoGenEcdhSharedKey(const struct HksParamSet *paramSet, enum HksChipsetPlatformDecryptScene scene,
    struct HksBlob *sharedKey)
{
    struct HksBlob saltPadding = { .size = PLATFORM_KEY_SALT_SIZE,
        .data = (uint8_t *)HksMalloc(PLATFORM_KEY_SALT_SIZE) };
    HKS_IF_NULL_RETURN(saltPadding.data, HKS_ERROR_MALLOC_FAIL);
    int32_t ret;
    do {
        struct HksParam *saltParam = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_SALT, &saltParam);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get salt fail");

        struct HksParam *peerPkParam = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_PEER_PUBLIC_KEY, &peerPkParam);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get tmp pk fail");

        if (saltParam->blob.size != PLATFORM_KEY_SALT_SIZE ||
            peerPkParam->blob.size != PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE) {
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }
        (void)(memcpy_s(saltPadding.data, PLATFORM_KEY_SALT_SIZE, saltParam->blob.data, PLATFORM_KEY_SALT_SIZE));
        if (scene == HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA) {
            saltPadding.data[PLATFORM_KEY_SALT_SIZE - 1] = PLATFORM_KEY_SALT_PADDING_BYTE_TA_TO_TA;
        }
        ret = HksChipsetPlatformDeriveKeyAndEcdh(&peerPkParam->blob, &saltPadding, sharedKey);
    } while (false);
    HKS_MEMSET_FREE_BLOB(saltPadding);
    return ret;
}

static int32_t DoHmacSha256(const struct HksBlob *hmacMsg,
    const struct HksBlob *sharedKey, struct HksBlob *wrappedKey)
{
    if (hmacMsg->size != PLATFORM_KEY_HMAC_MESSAGE_SIZE) {
        HKS_LOG_E("invalid hmacMsg->size %" LOG_PUBLIC "d", hmacMsg->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HksCryptoHalHmac(sharedKey, HKS_DIGEST_SHA256, hmacMsg, wrappedKey);
}

static int32_t DoAesDecrypt(const struct HksParamSet *paramSecureSet,
    const struct HksBlob *wrappedKey, struct HksBlob *plainText)
{
    struct HksParam *cipherTextParam = NULL;
    int32_t ret = HksGetParam(paramSecureSet, HKS_TAG_CIPHER_TEXT, &cipherTextParam);
    HKS_IF_NOT_SUCC_RETURN(ret, ret);

    struct HksParam *ivParam = NULL;
    ret = HksGetParam(paramSecureSet, HKS_TAG_IV, &ivParam);
    HKS_IF_NOT_SUCC_RETURN(ret, ret);

    struct HksParam *aadParam = NULL;
    ret = HksGetParam(paramSecureSet, HKS_TAG_ASSOCIATED_DATA, &aadParam);
    HKS_IF_NOT_SUCC_RETURN(ret, ret);

    struct HksParam *tagParam = NULL;
    ret = HksGetParam(paramSecureSet, HKS_TAG_AE_TAG, &tagParam);
    HKS_IF_NOT_SUCC_RETURN(ret, ret);

    struct HksBlob aad = aadParam->blob;
    struct HksBlob iv = ivParam->blob;
    struct HksBlob tag = tagParam->blob;
    struct HksBlob cipherText = cipherTextParam->blob;
    if (aad.size != PLATFORM_KEY_AAD_SIZE) {
        HKS_LOG_E("invalid aad size %" LOG_PUBLIC "d", aad.size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (iv.size != PLATFORM_KEY_IV_SIZE) {
        HKS_LOG_E("invalid iv size %" LOG_PUBLIC "d", iv.size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (tag.size != PLATFORM_KEY_TAG_SIZE) {
        HKS_LOG_E("invalid tag size %" LOG_PUBLIC "d", tag.size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    struct HksAeadParam aeadParam = {
        .nonce = iv,
        .aad = aad,
        .tagDec = tag,
        .payloadLen = cipherText.size,
    };
    struct HksUsageSpec decryptSpec = {
        .algType = HKS_ALG_AES,
        .mode = HKS_MODE_GCM,
        .padding = HKS_PADDING_NONE,
        .purpose = HKS_KEY_PURPOSE_DECRYPT,
        .algParam = (void *)&aeadParam,
    };
    return HksCryptoHalDecrypt(wrappedKey, &decryptSpec, &cipherText, plainText);
}

static int32_t CheckInput(const struct HksParamSet *paramSet, struct HksBlob *plainText,
    enum HksChipsetPlatformDecryptScene scene)
{
    // basic check for plainText and paramSet
    int32_t ret = CheckBlob(plainText);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Check plainText failed")

    ret = CheckParams(paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Check params failed")

    // check scene
    if (scene != HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA) {
        HKS_LOG_E("invalid scene");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    // specialized check for text
    struct HksParam *cipherTextParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_CIPHER_TEXT, &cipherTextParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get param cipher text failed")
    ret = CheckText(&cipherTextParam->blob, plainText);
    if (ret != HKS_SUCCESS) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HuksCoreChipsetPlatformDecrypt(const struct HksParamSet *paramSet,
    enum HksChipsetPlatformDecryptScene scene, struct HksBlob *plainText)
{
    int32_t ret = CheckInput(paramSet, plainText, scene);
    HKS_IF_NOT_SUCC_RETURN(ret, ret);

    // malloc for key
    struct HksBlob sharedKey = { .size = PLATFORM_KEY_SHARED_KEY_SIZE,
        .data = (uint8_t *)HksMalloc(PLATFORM_KEY_SHARED_KEY_SIZE) };
    if (sharedKey.data == NULL) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    struct HksBlob wrappedKey = { .size = PLATFORM_KEY_WRAPPED_KEY_SIZE,
        .data = (uint8_t *)HksMalloc(PLATFORM_KEY_WRAPPED_KEY_SIZE) };
    if (wrappedKey.data == NULL) {
        HKS_MEMSET_FREE_BLOB(sharedKey);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    do {
        // do ecdh to get sharedKey
        HKS_LOG_I("start ecdh");
        ret = DoGenEcdhSharedKey(paramSet, scene, &sharedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "ecdh get sharedKey failed %" LOG_PUBLIC "d", ret)

        // do hmac to get wrappedKey
        struct HksParam *customInfoParam = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_INFO, &customInfoParam);
        HKS_IF_NOT_SUCC_BREAK(ret)

        HKS_LOG_I("start hmac");
        ret = DoHmacSha256(&customInfoParam->blob, &sharedKey, &wrappedKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hmac get wrappedKey failed %" LOG_PUBLIC "d", ret)

        // do aes decrypt
        HKS_LOG_I("start decrypt");
        ret = DoAesDecrypt(paramSet, &wrappedKey, plainText);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "aes decrypt failed %" LOG_PUBLIC "d", ret)
    } while (false);

    HKS_MEMSET_FREE_BLOB(sharedKey);
    HKS_MEMSET_FREE_BLOB(wrappedKey);
    return ret;
}

int32_t HuksCoreExportChipsetPlatformPublicKey(const struct HksBlob *salt,
    enum HksChipsetPlatformDecryptScene scene, struct HksBlob *publicKey)
{
    if (CheckBlob(salt) != HKS_SUCCESS || CheckBlob(publicKey) != HKS_SUCCESS) {
        HKS_LOG_E("invalid input salt or pk empty blob");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (salt->size != PLATFORM_KEY_SALT_SIZE || publicKey->size != PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE ||
        scene != HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA) {
        HKS_LOG_E("invalid input salt sz %" LOG_PUBLIC "d pk sz %" LOG_PUBLIC "d scene %" LOG_PUBLIC "d",
            salt->size, publicKey->size, scene);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    struct HksBlob saltPadding = { .size = PLATFORM_KEY_SALT_SIZE,
        .data = (uint8_t *)HksMalloc(PLATFORM_KEY_SALT_SIZE) };
    HKS_IF_NULL_LOGE_RETURN(saltPadding.data, HKS_ERROR_MALLOC_FAIL, "malloc salt padding fail");
    (void)memcpy_s(saltPadding.data, PLATFORM_KEY_SALT_SIZE, salt->data, PLATFORM_KEY_SALT_SIZE);
    saltPadding.data[PLATFORM_KEY_SALT_SIZE - 1] = PLATFORM_KEY_SALT_PADDING_BYTE_TA_TO_TA;
    int32_t ret = HksChipsetPlatformDerivePubKey(&saltPadding, publicKey);
    HKS_MEMSET_FREE_BLOB(saltPadding);
    return ret;
}

#endif // HKS_SUPPORT_CHIPSET_PLATFORM_DECRYPT
