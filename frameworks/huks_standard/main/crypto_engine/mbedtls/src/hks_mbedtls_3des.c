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

#ifdef HKS_SUPPORT_3DES_C

#include "hks_mbedtls_3des.h"

#include <mbedtls/des.h>
#include <mbedtls/ccm.h>
#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>

#include <securec.h>

#include "hks_log.h"
#include "hks_mbedtls_common.h"
#include "hks_mem.h"
#include "hks_template.h"

#define HKS_3DES_CBC_NOPADDING_IV_SIZE 8
#define HKS_3DES_CBC_DATA_BLOB_SIZE 8

struct HksMbedtls3DesCtx {
    uint32_t algType;
    uint32_t mode;
    uint32_t padding;
    uint8_t *append;
    uint8_t iv[HKS_3DES_CBC_NOPADDING_IV_SIZE];
} HksMbedtls3DesCtx;

static int32_t CheckKeySize(const struct HksBlob *key)
{
    if ((key->size != HKS_KEY_BYTES(HKS_3DES_KEY_SIZE_128)) && (key->size != HKS_KEY_BYTES(HKS_3DES_KEY_SIZE_192))) {
        return HKS_ERROR_INVALID_KEY_SIZE;
    }

    return HKS_SUCCESS;
}

#ifdef HKS_SUPPORT_3DES_GENERATE_KEY
int32_t HksMbedtls3DesGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    if ((spec->keyLen != HKS_3DES_KEY_SIZE_128) && (spec->keyLen != HKS_3DES_KEY_SIZE_192)) {
        return HKS_ERROR_INVALID_KEY_SIZE;
    }

    const uint32_t keyByteLen = spec->keyLen / HKS_BITS_PER_BYTE;

    uint8_t *outKey = (uint8_t *)HksMalloc(keyByteLen);
    HKS_IF_NULL_RETURN(outKey, HKS_ERROR_MALLOC_FAIL)

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctrDrbg;
    (void)memset_s(&entropy, sizeof(mbedtls_entropy_context), 0, sizeof(mbedtls_entropy_context));
    (void)memset_s(&ctrDrbg, sizeof(mbedtls_ctr_drbg_context), 0, sizeof(mbedtls_ctr_drbg_context));
    int32_t ret = HksCtrDrbgSeed(&ctrDrbg, &entropy);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(outKey);
        return ret;
    }

    do {
        ret = mbedtls_ctr_drbg_random(&ctrDrbg, outKey, keyByteLen);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls ctr drbg random failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            (void)memset_s(outKey, keyByteLen, 0, keyByteLen);
            HKS_FREE(outKey);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        key->data = outKey;
        key->size = keyByteLen;
    } while (0);

    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}
#endif /* HKS_SUPPORT_3DES_GENERATE_KEY */

#ifdef HKS_SUPPORT_3DES_CBC_NOPADDING
static int32_t Des3CbcNoPaddingCryptSetKey(const struct HksBlob *key, mbedtls_des3_context *ctx, const bool encrypt)
{
    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    if (encrypt) {
        if (key->size == HKS_KEY_BYTES(HKS_3DES_KEY_SIZE_128)) {
            ret = mbedtls_des3_set2key_enc(ctx, key->data);
        } else if (key->size == HKS_KEY_BYTES(HKS_3DES_KEY_SIZE_192)) {
            ret = mbedtls_des3_set3key_enc(ctx, key->data);
        }
    } else {
        if (key->size == HKS_KEY_BYTES(HKS_3DES_KEY_SIZE_128)) {
            ret = mbedtls_des3_set2key_dec(ctx, key->data);
        } else if (key->size == HKS_KEY_BYTES(HKS_3DES_KEY_SIZE_192)) {
            ret = mbedtls_des3_set3key_dec(ctx, key->data);
        }
    }

    return ret;
}

static int32_t Des3CbcNoPaddingCryptInit(
    void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec, const bool encrypt)
{
    mbedtls_des3_context *ctx = (mbedtls_des3_context *)HksMalloc(sizeof(mbedtls_des3_context));
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_MALLOC_FAIL, "initialize ctx fail")
    mbedtls_des3_init(ctx);

    int32_t ret = Des3CbcNoPaddingCryptSetKey(key, ctx, encrypt);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls 3des set key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_des3_free(ctx);
        HKS_FREE(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    struct HksCipherParam *iv = (struct HksCipherParam *)(usageSpec->algParam);
    if (iv->iv.size != HKS_3DES_CBC_NOPADDING_IV_SIZE) {
        HKS_LOG_E("initialize iv fail");
        mbedtls_des3_free(ctx);
        HKS_FREE(ctx);
        return HKS_ERROR_INVALID_IV;
    }

    struct HksMbedtls3DesCtx *outCtx = (struct HksMbedtls3DesCtx *)HksMalloc(sizeof(struct HksMbedtls3DesCtx));
    if (outCtx == NULL) {
        HKS_LOG_E("initialize outCtx fail");
        mbedtls_des3_free(ctx);
        HKS_FREE(ctx);
        return HKS_ERROR_MALLOC_FAIL;
    }

    outCtx->append = (void *)ctx;
    outCtx->mode = usageSpec->mode;
    outCtx->padding = usageSpec->padding;
    (void)memcpy_s(outCtx->iv, HKS_3DES_CBC_NOPADDING_IV_SIZE, iv->iv.data, HKS_3DES_CBC_NOPADDING_IV_SIZE);

    *cryptoCtx = (void *)outCtx;

    return ret;
}

static int32_t Des3CbcNoPaddingCryptUpdate(
    void *cryptoCtx, const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    struct HksMbedtls3DesCtx *des3Ctx = (struct HksMbedtls3DesCtx *)cryptoCtx;
    HKS_IF_NULL_RETURN(des3Ctx, HKS_ERROR_NULL_POINTER)

    mbedtls_des3_context *cbcNoPaddingCtx = (mbedtls_des3_context *)des3Ctx->append;

    HKS_IF_NULL_RETURN(cbcNoPaddingCtx, HKS_ERROR_NULL_POINTER)

    int32_t ret;
    do {
        if (message->size % HKS_3DES_CBC_DATA_BLOB_SIZE != 0) {
            HKS_LOG_E("Des3CbcNoPaddingCryptUpdate data size invalid!");
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }

        /* mbedtls_des3_crypt_cbc will refresh iv, so need a temp iv */
        uint8_t tmpIv[HKS_3DES_CBC_NOPADDING_IV_SIZE];
        if (memcpy_s(tmpIv, HKS_3DES_CBC_NOPADDING_IV_SIZE, des3Ctx->iv, HKS_3DES_CBC_NOPADDING_IV_SIZE) != EOK) {
            HKS_LOG_E("Memcpy temp iv failed!");
            ret = HKS_ERROR_INVALID_IV;
            break;
        }

        ret = mbedtls_des3_crypt_cbc(cbcNoPaddingCtx,
            (encrypt ? MBEDTLS_DES_ENCRYPT : MBEDTLS_DES_DECRYPT),
            message->size,
            tmpIv,
            message->data,
            cipherText->data);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtks 3des cbc nopadding crypt failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        cipherText->size = message->size;
        (void)memcpy_s(des3Ctx->iv, HKS_3DES_CBC_NOPADDING_IV_SIZE, tmpIv, HKS_3DES_CBC_NOPADDING_IV_SIZE);
    } while (0);

    return ret;
}

static int32_t Des3CbcNoPaddingCryptFinal(
    void **cryptoCtx, const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    struct HksMbedtls3DesCtx *des3Ctx = (struct HksMbedtls3DesCtx *)*cryptoCtx;
    mbedtls_des3_context *cbcNoPaddingCtx = (mbedtls_des3_context *)des3Ctx->append;

    if (cbcNoPaddingCtx == NULL) {
        HKS_FREE(*cryptoCtx);
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HKS_SUCCESS;
    do {
        if (message->size % HKS_3DES_CBC_DATA_BLOB_SIZE != 0) {
            HKS_LOG_E("Des3CbcNoPaddingCryptFinal data size invalid!");
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }

        if (message->size != 0) {
            /* mbedtls_des3_crypt_cbc will refresh iv, so need a temp iv */
            uint8_t tmpIv[HKS_3DES_CBC_NOPADDING_IV_SIZE];
            if (memcpy_s(tmpIv, HKS_3DES_CBC_NOPADDING_IV_SIZE, des3Ctx->iv, HKS_3DES_CBC_NOPADDING_IV_SIZE) != EOK) {
                HKS_LOG_E("Memcpy temp iv failed!");
                ret = HKS_ERROR_INVALID_IV;
                break;
            }
            ret = mbedtls_des3_crypt_cbc(cbcNoPaddingCtx,
                (encrypt ? MBEDTLS_DES_ENCRYPT : MBEDTLS_DES_DECRYPT),
                message->size,
                tmpIv,
                message->data,
                cipherText->data);
            if (ret != HKS_MBEDTLS_SUCCESS) {
                HKS_LOG_E("Mbedtls 3des gcm encryot failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
                (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
                ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
                break;
            }
        }
        cipherText->size = message->size;
    } while (0);

    mbedtls_des3_free(cbcNoPaddingCtx);
    HKS_FREE(des3Ctx->append);
    HKS_FREE(*cryptoCtx);

    return ret;
}
#endif /* HKS_SUPPORT_3DES_CBC_NOPADDING */

static int32_t Des3CbcCryptInit(
    void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec, const bool encrypt)
{
    switch (usageSpec->padding) {
#ifdef HKS_SUPPORT_3DES_CBC_NOPADDING
        case HKS_PADDING_NONE:
            return Des3CbcNoPaddingCryptInit(cryptoCtx, key, usageSpec, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", usageSpec->padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t Des3CbcCryptUpdate(void *cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText, const bool encrypt)
{
    switch (padding) {
#ifdef HKS_SUPPORT_3DES_CBC_NOPADDING
        case HKS_PADDING_NONE:
            return Des3CbcNoPaddingCryptUpdate(cryptoCtx, message, encrypt, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t Des3CbcCryptFinal(void **cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText, const bool encrypt)
{
    switch (padding) {
#ifdef HKS_SUPPORT_3DES_CBC_NOPADDING
        case HKS_PADDING_NONE:
            return Des3CbcNoPaddingCryptFinal(cryptoCtx, message, encrypt, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

#ifdef HKS_SUPPORT_3DES_ECB_NOPADDING
static int32_t Des3EcbNoPaddingCryptInitParam(const struct HksBlob *key, mbedtls_cipher_context_t *ecbCtx,
    const bool encrypt)
{
    const mbedtls_cipher_info_t *info = NULL;
    if (key->size == HKS_KEY_BYTES(HKS_3DES_KEY_SIZE_128)) {
        info = mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_DES, key->size * HKS_BITS_PER_BYTE, MBEDTLS_MODE_ECB);
    } else if (key->size == HKS_KEY_BYTES(HKS_3DES_KEY_SIZE_192)) {
        info = mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_3DES, key->size * HKS_BITS_PER_BYTE, MBEDTLS_MODE_ECB);
    }
    if (info == NULL) {
        HKS_LOG_E("get cipher info from values failed!");
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    int32_t ret = mbedtls_cipher_setup(ecbCtx, info);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls cipher setup failed ret = %" LOG_PUBLIC "d", ret);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = mbedtls_cipher_setkey(
        ecbCtx, key->data, key->size * HKS_BITS_PER_BYTE, encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls setkey failed ret = %" LOG_PUBLIC "d", ret);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = mbedtls_cipher_set_iv(ecbCtx, NULL, 0);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls set iv failed ret = %" LOG_PUBLIC "d", ret);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return HKS_SUCCESS;
}

static int32_t Des3EcbNoPaddingCryptInit(void **cryptoCtx, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *key, const bool encrypt)
{
    mbedtls_cipher_context_t *ecbCtx = (mbedtls_cipher_context_t *)HksMalloc(sizeof(mbedtls_cipher_context_t));
    HKS_IF_NULL_LOGE_RETURN(ecbCtx, HKS_ERROR_MALLOC_FAIL, "Ecb ecbCtx malloc fail")

    mbedtls_cipher_init(ecbCtx);

    int32_t ret = Des3EcbNoPaddingCryptInitParam(key, ecbCtx, encrypt);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Des3EcbNoPaddingCryptInitParam failed ret = %" LOG_PUBLIC "d", ret);
        mbedtls_cipher_free(ecbCtx);
        HKS_FREE(ecbCtx);
        return ret;
    }

    ret = mbedtls_cipher_reset(ecbCtx);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls reset failed ret = %" LOG_PUBLIC "d", ret);
        mbedtls_cipher_free(ecbCtx);
        HKS_FREE(ecbCtx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    struct HksMbedtls3DesCtx *outCtx = (struct HksMbedtls3DesCtx *)HksMalloc(sizeof(struct HksMbedtls3DesCtx));
    if (outCtx == NULL) {
        HKS_LOG_E("initialize outCtx fail");
        mbedtls_cipher_free(ecbCtx);
        HKS_FREE(ecbCtx);
        return HKS_ERROR_MALLOC_FAIL;
    }

    outCtx->algType = usageSpec->algType;
    outCtx->mode = usageSpec->mode;
    outCtx->padding = usageSpec->padding;
    outCtx->append = (void *)ecbCtx;
    *cryptoCtx = (void *)outCtx;

    return ret;
}

static int32_t Des3EcbNoPaddingData(mbedtls_cipher_context_t *ecbNoPadingctx, size_t blockSize,
    const struct HksBlob *message, struct HksBlob *cipherText, size_t *outLenTotal)
{
    int32_t ret;

    uint8_t *tmpMessage = (uint8_t *)HksMalloc(blockSize);
    HKS_IF_NULL_LOGE_RETURN(tmpMessage, HKS_ERROR_INSUFFICIENT_MEMORY, "EcbNoPaddingUpdate tmpMessage is null")

    if (message->size <= blockSize) {
        (void)memset_s(tmpMessage, blockSize, 0, blockSize);
        (void)memcpy_s(tmpMessage, message->size, message->data, message->size);
        ret = mbedtls_cipher_update(ecbNoPadingctx, tmpMessage, blockSize, cipherText->data, outLenTotal);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls ecb no padding update failed ret = 0x%" LOG_PUBLIC "X", ret);
            HKS_FREE(tmpMessage);
            return HKS_ERROR_CRYPTO_ENGINE_ERROR;
        }
    } else {
        uint32_t point = 0;
        while (point < message->size) {
            (void)memset_s(tmpMessage, blockSize, 0, blockSize);
            uint32_t tmpSize = (message->size - point) >= blockSize ? blockSize : (message->size - point);
            ret = memcpy_s(tmpMessage, blockSize, message->data + point, tmpSize);
            if (ret != HKS_MBEDTLS_SUCCESS) {
                HKS_LOG_E("copy data failed");
                HKS_FREE(tmpMessage);
                return HKS_ERROR_INSUFFICIENT_MEMORY;
            }
            size_t olen;
            ret = mbedtls_cipher_update(ecbNoPadingctx, tmpMessage, tmpSize, cipherText->data + point, &olen);
            if (ret != HKS_MBEDTLS_SUCCESS) {
                HKS_LOG_E("Mbedtls ecb no padding update failed ret = 0x%" LOG_PUBLIC "X", ret);
                HKS_FREE(tmpMessage);
                return HKS_ERROR_CRYPTO_ENGINE_ERROR;
            }
            *outLenTotal += olen;
            point += blockSize;
        }
    }
    HKS_FREE(tmpMessage);
    return HKS_SUCCESS;
}

static mbedtls_cipher_context_t *Get3DesEcbNoPaddingCtx(void *cryptoCtx, const struct HksBlob *message,
    struct HksBlob *cipherText, size_t *outLenTotal)
{
    struct HksMbedtls3DesCtx *des3Ctx = (struct HksMbedtls3DesCtx *)cryptoCtx;
    mbedtls_cipher_context_t *ecbNoPadingctx = (mbedtls_cipher_context_t *)des3Ctx->append;
    HKS_IF_NULL_LOGE_RETURN(ecbNoPadingctx, NULL, "EcbNoPaddingUpdate ecbNoPadingctx is null")

    int32_t ret = HKS_SUCCESS;
    do {
        if (message == NULL) {
            HKS_LOG_E("The message is null.");
            ret = HKS_FAILURE;
            break;
        }

        if (message->size != 0) {
            size_t blockSize = mbedtls_cipher_get_block_size(ecbNoPadingctx);
            HKS_LOG_E("Ecb No padding update!message.size[%" LOG_PUBLIC "d] blockSize[%" LOG_PUBLIC "d]",
                message->size, blockSize);
            if (blockSize == 0 || (message->size % blockSize != 0)) {
                HKS_LOG_E("The size of message is invalid.");
                ret = HKS_ERROR_INVALID_ARGUMENT;
                break;
            }

            ret = Des3EcbNoPaddingData(ecbNoPadingctx, blockSize, message, cipherText, outLenTotal);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "DesEcbNoPaddingData failed")
        }
    } while (0);

    HKS_IF_NOT_SUCC_RETURN(ret, NULL)

    return ecbNoPadingctx;
}

static int32_t Des3EcbNoPaddingCryptUpdate(void *cryptoCtx, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    size_t outLenTotal = 0;
    HKS_IF_NULL_RETURN(Get3DesEcbNoPaddingCtx(cryptoCtx, message, cipherText, &outLenTotal), HKS_ERROR_NULL_POINTER)

    cipherText->size = outLenTotal;
    return HKS_SUCCESS;
}

static int32_t Des3EcbNoPaddingCryptFinal(void **cryptoCtx, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    size_t outLenTotal = 0;
    mbedtls_cipher_context_t *ecbNoPadingctx = Get3DesEcbNoPaddingCtx(*cryptoCtx, message, cipherText, &outLenTotal);
    if (ecbNoPadingctx == NULL) {
        HKS_FREE(*cryptoCtx);
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksMbedtls3DesCtx *des3Ctx = (struct HksMbedtls3DesCtx *)*cryptoCtx;
    size_t finishOlen;
    size_t olen = outLenTotal;
    int32_t ret = mbedtls_cipher_finish(ecbNoPadingctx, cipherText->data + olen, &finishOlen);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls ecb nopadding crypt update failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
        ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    } else {
        cipherText->size = olen + finishOlen;
    }

    mbedtls_cipher_free(ecbNoPadingctx);
    HKS_FREE(des3Ctx->append);
    HKS_FREE(*cryptoCtx);

    return ret;
}
#endif

static int32_t Des3EcbCryptInit(void **cryptoCtx, const struct HksBlob *key,
    const struct HksUsageSpec *usageSpec, const bool encrypt)
{
    switch (usageSpec->padding) {
#ifdef HKS_SUPPORT_3DES_ECB_NOPADDING
        case HKS_PADDING_NONE:
            return Des3EcbNoPaddingCryptInit(cryptoCtx, usageSpec, key, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", usageSpec->padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t Des3EcbCryptUpdate(void *cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    switch (padding) {
#ifdef HKS_SUPPORT_3DES_ECB_NOPADDING
        case HKS_PADDING_NONE:
            return Des3EcbNoPaddingCryptUpdate(cryptoCtx, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t Des3EcbCryptFinal(void **cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    switch (padding) {
#ifdef HKS_SUPPORT_3DES_ECB_NOPADDING
        case HKS_PADDING_NONE:
            return Des3EcbNoPaddingCryptFinal(cryptoCtx, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

int32_t HksMbedtls3DesEncryptInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec)
{
    if (CheckKeySize(key) != HKS_SUCCESS || cryptoCtx == NULL || usageSpec == NULL) {
        HKS_LOG_E("Invalid des3 keySiz = 0x%" LOG_PUBLIC "X", key->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    switch (usageSpec->mode) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return Des3CbcCryptInit(cryptoCtx, key, usageSpec, true);
#endif
#if defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return Des3EcbCryptInit(cryptoCtx, key, usageSpec, true);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", usageSpec->mode);
            return HKS_ERROR_NOT_SUPPORTED;
    }
}

int32_t HksMbedtls3DesEncryptUpdate(void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    HKS_IF_NULL_LOGE_RETURN(cryptoCtx, HKS_ERROR_INVALID_ARGUMENT, "Mbedtls 3DES encrypt update param is null")

    struct HksMbedtls3DesCtx *des3EncryptCtx = (struct HksMbedtls3DesCtx *)cryptoCtx;

    switch (des3EncryptCtx->mode) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return Des3CbcCryptUpdate(cryptoCtx, des3EncryptCtx->padding, message, cipherText, true);
#endif
#if defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return Des3EcbCryptUpdate(cryptoCtx, des3EncryptCtx->padding, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", des3EncryptCtx->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtls3DesEncryptFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    struct HksMbedtls3DesCtx *des3EncryptCtx = (struct HksMbedtls3DesCtx *)*cryptoCtx;

    switch (des3EncryptCtx->mode) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return Des3CbcCryptFinal(cryptoCtx, des3EncryptCtx->padding, message, cipherText, true);
#endif
#if defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return Des3EcbCryptFinal(cryptoCtx, des3EncryptCtx->padding, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", des3EncryptCtx->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtls3DesDecryptInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(
        CheckKeySize(key), HKS_ERROR_INVALID_ARGUMENT, "Invalid des3 keySize = 0x%" LOG_PUBLIC "X", key->size)

    switch (usageSpec->mode) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return Des3CbcCryptInit(cryptoCtx, key, usageSpec, false);
#endif
#if defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return Des3EcbCryptInit(cryptoCtx, key, usageSpec, false);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", usageSpec->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtls3DesDecryptUpdate(void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    struct HksMbedtls3DesCtx *des3DecryptCtx = (struct HksMbedtls3DesCtx *)cryptoCtx;
    switch (des3DecryptCtx->mode) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return Des3CbcCryptUpdate(cryptoCtx, des3DecryptCtx->padding, message, cipherText, false);
#endif
#if defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return Des3EcbCryptUpdate(cryptoCtx, des3DecryptCtx->padding, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", des3DecryptCtx->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtls3DesDecryptFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    struct HksMbedtls3DesCtx *des3DecryptCtx = (struct HksMbedtls3DesCtx *)*cryptoCtx;

    switch (des3DecryptCtx->mode) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return Des3CbcCryptFinal(cryptoCtx, des3DecryptCtx->padding, message, cipherText, false);
#endif
#if defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return Des3EcbCryptFinal(cryptoCtx, des3DecryptCtx->padding, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", des3DecryptCtx->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtls3DesCryptoInit(
    void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec, const bool encrypt)
{
    if (encrypt) {
        return HksMbedtls3DesEncryptInit(cryptoCtx, key, usageSpec);
    } else {
        return HksMbedtls3DesDecryptInit(cryptoCtx, key, usageSpec);
    }
}

int32_t HksMbedtls3DesCryptoUpdate(
    void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText, const bool encrypt)
{
    if (encrypt) {
        return HksMbedtls3DesEncryptUpdate(cryptoCtx, message, cipherText);
    } else {
        return HksMbedtls3DesDecryptUpdate(cryptoCtx, message, cipherText);
    }
}

int32_t HksMbedtls3DesCryptoFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText,
    const bool encrypt)
{
    if (encrypt) {
        return HksMbedtls3DesEncryptFinal(cryptoCtx, message, cipherText);
    } else {
        return HksMbedtls3DesDecryptFinal(cryptoCtx, message, cipherText);
    }
}

#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING)
void HksMbedtls3DesHalModeCbcFreeCtx(void **cryptCtx)
{
    if (cryptCtx == NULL || *cryptCtx == NULL) {
        HKS_LOG_E("FreeCtx cryptCtx param is null");
        return;
    }

    struct HksMbedtls3DesCtx *mbedtls3DesCtx = (struct HksMbedtls3DesCtx *)*cryptCtx;
    if (mbedtls3DesCtx->padding == HKS_PADDING_NONE) {
        if (mbedtls3DesCtx->append != NULL) {
            mbedtls_des3_free((mbedtls_des3_context *)(mbedtls3DesCtx->append));
            HKS_FREE(mbedtls3DesCtx->append);
        }
    }
}
#endif

#if defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
void HksMbedtls3DesHalModeEcbFreeCtx(void **cryptCtx)
{
    if (cryptCtx == NULL || *cryptCtx == NULL) {
        HKS_LOG_E("FreeCtx cryptCtx param is null");
        return;
    }

    struct HksMbedtls3DesCtx *mbedtlsDesCtx = (struct HksMbedtls3DesCtx *)*cryptCtx;
    if (mbedtlsDesCtx->padding == HKS_PADDING_NONE) {
        if (mbedtlsDesCtx->append != NULL) {
            mbedtls_cipher_free((mbedtls_cipher_context_t *)mbedtlsDesCtx->append);
            HKS_FREE(mbedtlsDesCtx->append);
        }
    }
}
#endif

void HksMbedtls3DesHalFreeCtx(void **cryptCtx)
{
    if (cryptCtx == NULL || *cryptCtx == NULL) {
        HKS_LOG_E("FreeCtx param context null");
        return;
    }

    struct HksMbedtls3DesCtx *mbedtls3DesCtx = (struct HksMbedtls3DesCtx *)*cryptCtx;
    switch (mbedtls3DesCtx->mode) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            HksMbedtls3DesHalModeCbcFreeCtx(cryptCtx);
            break;
#endif
#if defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            HksMbedtls3DesHalModeEcbFreeCtx(cryptCtx);
            break;
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", mbedtls3DesCtx->mode);
            break;
    }
    HKS_FREE(*cryptCtx);
}
#endif /* HKS_SUPPORT_3DES_C */