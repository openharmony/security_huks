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

#ifdef HKS_SUPPORT_DES_C

#include "hks_mbedtls_des.h"

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

#define HKS_DES_CBC_NOPADDING_IV_SIZE 8
#define HKS_DES_CBC_DATA_BLOB_SIZE 8

struct HksMbedtlsDesCtx {
    uint32_t algType;
    uint32_t mode;
    uint32_t padding;
    uint8_t *append;
    uint8_t iv[HKS_DES_CBC_NOPADDING_IV_SIZE];
    uint8_t *nonce;
    uint32_t nonceSize;
    uint8_t *aad;
    uint32_t aadSize;
} HksMbedtlsDesCtx;

static int32_t CheckKeySize(const struct HksBlob *key)
{
    if (key->size != HKS_KEY_BYTES(HKS_DES_KEY_SIZE_64)) {
        return HKS_ERROR_INVALID_KEY_SIZE;
    }

    return HKS_SUCCESS;
}

#ifdef HKS_SUPPORT_DES_GENERATE_KEY
int32_t HksMbedtlsDesGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    if (spec->keyLen != HKS_DES_KEY_SIZE_64) {
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
#endif /* HKS_SUPPORT_DES_GENERATE_KEY */

#ifdef HKS_SUPPORT_DES_CBC_NOPADDING
static int32_t DesCbcNoPaddingCryptInit(
    void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec, const bool encrypt)
{
    mbedtls_des_context *ctx = (mbedtls_des_context *)HksMalloc(sizeof(mbedtls_des_context));
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_MALLOC_FAIL, "initialize ctx fail")
    mbedtls_des_init(ctx);

    int32_t ret;
    if (encrypt) {
        ret = mbedtls_des_setkey_enc(ctx, key->data);
    } else {
        ret = mbedtls_des_setkey_dec(ctx, key->data);
    }
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls des set key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_des_free(ctx);
        HKS_FREE(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    struct HksCipherParam *iv = (struct HksCipherParam *)(usageSpec->algParam);
    if (iv->iv.size != HKS_DES_CBC_NOPADDING_IV_SIZE) {
        HKS_LOG_E("initialize iv fail");
        mbedtls_des_free(ctx);
        HKS_FREE(ctx);
        return HKS_ERROR_INVALID_IV;
    }

    struct HksMbedtlsDesCtx *outCtx = (struct HksMbedtlsDesCtx *)HksMalloc(sizeof(struct HksMbedtlsDesCtx));
    if (outCtx == NULL) {
        HKS_LOG_E("initialize outCtx fail");
        mbedtls_des_free(ctx);
        HKS_FREE(ctx);
        return HKS_ERROR_MALLOC_FAIL;
    }

    outCtx->append = (void *)ctx;
    outCtx->mode = usageSpec->mode;
    outCtx->padding = usageSpec->padding;
    (void)memcpy_s(outCtx->iv, HKS_DES_CBC_NOPADDING_IV_SIZE, iv->iv.data, HKS_DES_CBC_NOPADDING_IV_SIZE);

    *cryptoCtx = (void *)outCtx;

    return ret;
}

static int32_t DesCbcNoPaddingCryptUpdate(
    void *cryptoCtx, const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    struct HksMbedtlsDesCtx *desCtx = (struct HksMbedtlsDesCtx *)cryptoCtx;
    HKS_IF_NULL_RETURN(desCtx, HKS_ERROR_NULL_POINTER)

    mbedtls_des_context *cbcNoPaddingCtx = (mbedtls_des_context *)desCtx->append;

    HKS_IF_NULL_RETURN(cbcNoPaddingCtx, HKS_ERROR_NULL_POINTER)

    int32_t ret;
    do {
        if (message->size % HKS_DES_CBC_DATA_BLOB_SIZE != 0) {
            HKS_LOG_E("DesCbcNoPaddingCryptUpdate data size invalid!");
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }

        /* mbedtls_des_crypt_cbc will refresh iv, so need a temp iv */
        uint8_t tmpIv[HKS_DES_CBC_NOPADDING_IV_SIZE];
        if (memcpy_s(tmpIv, HKS_DES_CBC_NOPADDING_IV_SIZE, desCtx->iv, HKS_DES_CBC_NOPADDING_IV_SIZE) != EOK) {
            HKS_LOG_E("Memcpy temp iv failed!");
            ret = HKS_ERROR_INVALID_IV;
            break;
        }

        ret = mbedtls_des_crypt_cbc(cbcNoPaddingCtx,
            (encrypt ? MBEDTLS_DES_ENCRYPT : MBEDTLS_DES_DECRYPT),
            message->size,
            tmpIv,
            message->data,
            cipherText->data);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtks des cbc nopadding crypt failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        cipherText->size = message->size;
        (void)memcpy_s(desCtx->iv, HKS_DES_CBC_NOPADDING_IV_SIZE, tmpIv, HKS_DES_CBC_NOPADDING_IV_SIZE);
    } while (0);

    return ret;
}

static int32_t DesCbcNoPaddingCryptFinal(
    void **cryptoCtx, const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    struct HksMbedtlsDesCtx *desCtx = (struct HksMbedtlsDesCtx *)*cryptoCtx;
    mbedtls_des_context *cbcNoPaddingCtx = (mbedtls_des_context *)desCtx->append;

    if (cbcNoPaddingCtx == NULL) {
        HKS_FREE(*cryptoCtx);
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HKS_SUCCESS;
    do {
        if (message->size % HKS_DES_CBC_DATA_BLOB_SIZE != 0) {
            HKS_LOG_E("DesCbcNoPaddingCryptFinal data size invalid!");
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }

        if (message->size != 0) {
            /* mbedtls_des_crypt_cbc will refresh iv, so need a temp iv */
            uint8_t tmpIv[HKS_DES_CBC_NOPADDING_IV_SIZE];
            if (memcpy_s(tmpIv, HKS_DES_CBC_NOPADDING_IV_SIZE, desCtx->iv, HKS_DES_CBC_NOPADDING_IV_SIZE) != EOK) {
                HKS_LOG_E("Memcpy temp iv failed!");
                ret = HKS_ERROR_INVALID_IV;
                break;
            }
            ret = mbedtls_des_crypt_cbc(cbcNoPaddingCtx,
                (encrypt ? MBEDTLS_DES_ENCRYPT : MBEDTLS_DES_DECRYPT),
                message->size,
                tmpIv,
                message->data,
                cipherText->data);
            if (ret != HKS_MBEDTLS_SUCCESS) {
                HKS_LOG_E("Mbedtls des gcm encryot failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
                (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
                ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
                break;
            }
        }
        cipherText->size = message->size;
    } while (0);

    mbedtls_des_free(cbcNoPaddingCtx);
    HKS_FREE(desCtx->append);
    HKS_FREE(*cryptoCtx);

    return ret;
}
#endif /* HKS_SUPPORT_DES_CBC_NOPADDING */

static int32_t DesCbcCryptInit(
    void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec, const bool encrypt)
{
    switch (usageSpec->padding) {
#ifdef HKS_SUPPORT_DES_CBC_NOPADDING
        case HKS_PADDING_NONE:
            return DesCbcNoPaddingCryptInit(cryptoCtx, key, usageSpec, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", usageSpec->padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t DesCbcCryptUpdate(void *cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText, const bool encrypt)
{
    switch (padding) {
#ifdef HKS_SUPPORT_DES_CBC_NOPADDING
        case HKS_PADDING_NONE:
            return DesCbcNoPaddingCryptUpdate(cryptoCtx, message, encrypt, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t DesCbcCryptFinal(void **cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText, const bool encrypt)
{
    switch (padding) {
#ifdef HKS_SUPPORT_DES_CBC_NOPADDING
        case HKS_PADDING_NONE:
            return DesCbcNoPaddingCryptFinal(cryptoCtx, message, encrypt, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

#ifdef HKS_SUPPORT_DES_ECB_NOPADDING
static int32_t DesEcbNoPaddingCryptInitParam(const struct HksBlob *key, mbedtls_cipher_context_t *ecbCtx,
    const bool encrypt)
{
    const mbedtls_cipher_info_t *info =
        mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_DES, key->size * HKS_BITS_PER_BYTE, MBEDTLS_MODE_ECB);
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

static int32_t DesEcbNoPaddingCryptInit(void **cryptoCtx, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *key, const bool encrypt)
{
    mbedtls_cipher_context_t *ecbCtx = (mbedtls_cipher_context_t *)HksMalloc(sizeof(mbedtls_cipher_context_t));
    HKS_IF_NULL_LOGE_RETURN(ecbCtx, HKS_ERROR_MALLOC_FAIL, "Ecb ecbCtx malloc fail")

    mbedtls_cipher_init(ecbCtx);

    int32_t ret = DesEcbNoPaddingCryptInitParam(key, ecbCtx, encrypt);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("DesEcbNoPaddingCryptInitParam failed ret = %" LOG_PUBLIC "d", ret);
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

    struct HksMbedtlsDesCtx *outCtx = (struct HksMbedtlsDesCtx *)HksMalloc(sizeof(struct HksMbedtlsDesCtx));
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

static int32_t DesEcbNoPaddingData(mbedtls_cipher_context_t *ecbNoPadingctx, size_t blockSize,
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

static mbedtls_cipher_context_t *GetDesEcbNoPaddingCtx(void *cryptoCtx, const struct HksBlob *message,
    struct HksBlob *cipherText, size_t *outLenTotal)
{
    struct HksMbedtlsDesCtx *desCtx = (struct HksMbedtlsDesCtx *)cryptoCtx;
    mbedtls_cipher_context_t *ecbNoPadingctx = (mbedtls_cipher_context_t *)desCtx->append;
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

            ret = DesEcbNoPaddingData(ecbNoPadingctx, blockSize, message, cipherText, outLenTotal);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "DesEcbNoPaddingData failed")
        }
    } while (0);

    HKS_IF_NOT_SUCC_RETURN(ret, NULL)

    return ecbNoPadingctx;
}

static int32_t DesEcbNoPaddingCryptUpdate(void *cryptoCtx, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    size_t outLenTotal = 0;
    HKS_IF_NULL_RETURN(GetDesEcbNoPaddingCtx(cryptoCtx, message, cipherText, &outLenTotal), HKS_ERROR_NULL_POINTER)

    cipherText->size = outLenTotal;
    return HKS_SUCCESS;
}

static int32_t DesEcbNoPaddingCryptFinal(void **cryptoCtx, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    size_t outLenTotal = 0;
    mbedtls_cipher_context_t *ecbNoPadingctx = GetDesEcbNoPaddingCtx(*cryptoCtx, message, cipherText, &outLenTotal);
    if (ecbNoPadingctx == NULL) {
        HKS_FREE(*cryptoCtx);
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksMbedtlsDesCtx *desCtx = (struct HksMbedtlsDesCtx *)*cryptoCtx;
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
    HKS_FREE(desCtx->append);
    HKS_FREE(*cryptoCtx);

    return ret;
}
#endif

#if defined(HKS_SUPPORT_DES_ECB_NOPADDING)
static int32_t DesEcbCryptInit(void **cryptoCtx, const struct HksBlob *key,
    const struct HksUsageSpec *usageSpec, const bool encrypt)
{
    switch (usageSpec->padding) {
#ifdef HKS_SUPPORT_DES_ECB_NOPADDING
        case HKS_PADDING_NONE:
            return DesEcbNoPaddingCryptInit(cryptoCtx, usageSpec, key, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", usageSpec->padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t DesEcbCryptUpdate(void *cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    switch (padding) {
#ifdef HKS_SUPPORT_DES_ECB_NOPADDING
        case HKS_PADDING_NONE:
            return DesEcbNoPaddingCryptUpdate(cryptoCtx, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t DesEcbCryptFinal(void **cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    switch (padding) {
#ifdef HKS_SUPPORT_DES_ECB_NOPADDING
        case HKS_PADDING_NONE:
            return DesEcbNoPaddingCryptFinal(cryptoCtx, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}
#endif

int32_t HksMbedtlsDesEncryptInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec)
{
    if (CheckKeySize(key) != HKS_SUCCESS || cryptoCtx == NULL || usageSpec == NULL) {
        HKS_LOG_E("Invalid des keySiz = 0x%" LOG_PUBLIC "X", key->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    switch (usageSpec->mode) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return DesCbcCryptInit(cryptoCtx, key, usageSpec, true);
#endif
#if defined(HKS_SUPPORT_DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return DesEcbCryptInit(cryptoCtx, key, usageSpec, true);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", usageSpec->mode);
            return HKS_ERROR_NOT_SUPPORTED;
    }
}

int32_t HksMbedtlsDesEncryptUpdate(void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    HKS_IF_NULL_LOGE_RETURN(cryptoCtx, HKS_ERROR_INVALID_ARGUMENT, "Mbedtls DES encrypt update param is null")

    struct HksMbedtlsDesCtx *desEncryptCtx = (struct HksMbedtlsDesCtx *)cryptoCtx;

    switch (desEncryptCtx->mode) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return DesCbcCryptUpdate(cryptoCtx, desEncryptCtx->padding, message, cipherText, true);
#endif
#if defined(HKS_SUPPORT_DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return DesEcbCryptUpdate(cryptoCtx, desEncryptCtx->padding, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", desEncryptCtx->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtlsDesEncryptFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    struct HksMbedtlsDesCtx *desEncryptCtx = (struct HksMbedtlsDesCtx *)*cryptoCtx;

    switch (desEncryptCtx->mode) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return DesCbcCryptFinal(cryptoCtx, desEncryptCtx->padding, message, cipherText, true);
#endif
#if defined(HKS_SUPPORT_DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return DesEcbCryptFinal(cryptoCtx, desEncryptCtx->padding, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", desEncryptCtx->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtlsDesDecryptInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(
        CheckKeySize(key), HKS_ERROR_INVALID_ARGUMENT, "Invalid des keySize = 0x%" LOG_PUBLIC "X", key->size)

    switch (usageSpec->mode) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return DesCbcCryptInit(cryptoCtx, key, usageSpec, false);
#endif
#if defined(HKS_SUPPORT_DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return DesEcbCryptInit(cryptoCtx, key, usageSpec, false);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", usageSpec->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtlsDesDecryptUpdate(void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    struct HksMbedtlsDesCtx *desDecryptCtx = (struct HksMbedtlsDesCtx *)cryptoCtx;
    switch (desDecryptCtx->mode) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return DesCbcCryptUpdate(cryptoCtx, desDecryptCtx->padding, message, cipherText, false);
#endif
#if defined(HKS_SUPPORT_DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return DesEcbCryptUpdate(cryptoCtx, desDecryptCtx->padding, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", desDecryptCtx->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtlsDesDecryptFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    struct HksMbedtlsDesCtx *desDecryptCtx = (struct HksMbedtlsDesCtx *)*cryptoCtx;

    switch (desDecryptCtx->mode) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return DesCbcCryptFinal(cryptoCtx, desDecryptCtx->padding, message, cipherText, false);
#endif
#if defined(HKS_SUPPORT_DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return DesEcbCryptFinal(cryptoCtx, desDecryptCtx->padding, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", desDecryptCtx->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtlsDesCryptoInit(
    void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec, const bool encrypt)
{
    if (encrypt) {
        return HksMbedtlsDesEncryptInit(cryptoCtx, key, usageSpec);
    } else {
        return HksMbedtlsDesDecryptInit(cryptoCtx, key, usageSpec);
    }
}

int32_t HksMbedtlsDesCryptoUpdate(
    void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText, const bool encrypt)
{
    if (encrypt) {
        return HksMbedtlsDesEncryptUpdate(cryptoCtx, message, cipherText);
    } else {
        return HksMbedtlsDesDecryptUpdate(cryptoCtx, message, cipherText);
    }
}

int32_t HksMbedtlsDesCryptoFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText,
    const bool encrypt)
{
    if (encrypt) {
        return HksMbedtlsDesEncryptFinal(cryptoCtx, message, cipherText);
    } else {
        return HksMbedtlsDesDecryptFinal(cryptoCtx, message, cipherText);
    }
}

#if defined(HKS_SUPPORT_DES_CBC_NOPADDING)
void HksMbedtlsDesHalModecbcFreeCtx(void **cryptCtx)
{
    if (cryptCtx == NULL || *cryptCtx == NULL) {
        HKS_LOG_E("FreeCtx cryptCtx param is null");
        return;
    }

    struct HksMbedtlsDesCtx *mbedtlsDesCtx = (struct HksMbedtlsDesCtx *)*cryptCtx;
    if (mbedtlsDesCtx->padding == HKS_PADDING_NONE) {
        if (mbedtlsDesCtx->append != NULL) {
            mbedtls_des_free((mbedtls_des_context *)(mbedtlsDesCtx->append));
            HKS_FREE(mbedtlsDesCtx->append);
        }
    }
}
#endif

void HksMbedtlsDesHalFreeCtx(void **cryptCtx)
{
    if (cryptCtx == NULL || *cryptCtx == NULL) {
        HKS_LOG_E("FreeCtx param context null");
        return;
    }

    struct HksMbedtlsDesCtx *mbedtlsDesCtx = (struct HksMbedtlsDesCtx *)*cryptCtx;
    switch (mbedtlsDesCtx->mode) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            HksMbedtlsDesHalModecbcFreeCtx(cryptCtx);
            break;
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", mbedtlsDesCtx->mode);
            break;
    }
    HKS_FREE(*cryptCtx);
}

#endif /* HKS_SUPPORT_DES_C */