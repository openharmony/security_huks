/*
 * Copyright (c) 2020-2022 Huawei Device Co., Ltd.
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

#ifdef HKS_SUPPORT_AES_C

#include "hks_mbedtls_aes.h"

#include <mbedtls/aes.h>
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

#define HKS_AES_CBC_NOPADDING_IV_SIZE 16
#define HKS_AES_CBC_DATA_BLOB_SIZE 16
#define HKS_AES_CCM_DATA_SIZE_MAX (1 * 1024 * 1024) // 1M

struct HksMbedtlsAesCtx {
    uint32_t algType;
    uint32_t mode;
    uint32_t padding;
    uint8_t *append;
    uint8_t iv[HKS_AES_CBC_NOPADDING_IV_SIZE];
    uint8_t *nonce;
    uint32_t nonceSize;
    uint8_t *aad;
    uint32_t aadSize;
} HksMbedtlsAesCtx;

#ifdef HKS_SUPPORT_AES_GENERATE_KEY
int32_t HksMbedtlsAesGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    if (spec->keyLen != HKS_AES_KEY_SIZE_128 && spec->keyLen != HKS_AES_KEY_SIZE_192 &&
        spec->keyLen != HKS_AES_KEY_SIZE_256) {
        return HKS_ERROR_INVALID_ARGUMENT;
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
#endif /* HKS_SUPPORT_AES_GENERATE_KEY */

#ifdef HKS_SUPPORT_AES_CBC_NOPADDING
static int32_t AesCbcNoPaddingCrypt(const struct HksBlob *key, const struct HksCipherParam *cipherParam,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int32_t ret;
    do {
        if (encrypt) {
            ret = mbedtls_aes_setkey_enc(&ctx, key->data, key->size * HKS_BITS_PER_BYTE);
        } else {
            ret = mbedtls_aes_setkey_dec(&ctx, key->data, key->size * HKS_BITS_PER_BYTE);
        }
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls aes set key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            break;
        }

        /* mbedtls_aes_crypt_cbc will refresh iv, so need a temp iv */
        uint8_t tmpIv[HKS_AES_CBC_NOPADDING_IV_SIZE];
        if (memcpy_s(tmpIv, HKS_AES_CBC_NOPADDING_IV_SIZE, cipherParam->iv.data, cipherParam->iv.size) != EOK) {
            HKS_LOG_E("Memcpy temp iv failed!");
            ret = HKS_ERROR_INVALID_IV;
            break;
        }

        ret = mbedtls_aes_crypt_cbc(&ctx,
            (encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT),
            message->size,
            tmpIv,
            message->data,
            cipherText->data);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtks aes cbc crypt failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        cipherText->size = message->size;
    } while (0);

    mbedtls_aes_free(&ctx);
    return ret;
}

static int32_t AesCbcNoPaddingCryptInit(void **cryptoCtx, const struct HksBlob *key,
    const struct HksUsageSpec *usageSpec, const bool encrypt)
{
    mbedtls_aes_context *ctx = (mbedtls_aes_context *)HksMalloc(sizeof(mbedtls_aes_context));
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_MALLOC_FAIL, "initialize ctx fail")
    mbedtls_aes_init(ctx);

    int32_t ret;
    if (encrypt) {
        ret = mbedtls_aes_setkey_enc(ctx, key->data, key->size * HKS_BITS_PER_BYTE);
    } else {
        ret = mbedtls_aes_setkey_dec(ctx, key->data, key->size * HKS_BITS_PER_BYTE);
    }
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls aes set key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_aes_free(ctx);
        HKS_FREE(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    struct HksCipherParam *iv = (struct HksCipherParam *)(usageSpec->algParam);
    if (iv->iv.size != HKS_AES_CBC_NOPADDING_IV_SIZE) {
        HKS_LOG_E("initialize iv fail");
        mbedtls_aes_free(ctx);
        HKS_FREE(ctx);
        return HKS_ERROR_INVALID_IV;
    }

    struct HksMbedtlsAesCtx *outCtx = (struct HksMbedtlsAesCtx *)HksMalloc(sizeof(HksMbedtlsAesCtx));
    if (outCtx == NULL) {
        HKS_LOG_E("initialize outCtx fail");
        mbedtls_aes_free(ctx);
        HKS_FREE(ctx);
        return HKS_ERROR_MALLOC_FAIL;
    }

    outCtx->append = (void *)ctx;
    outCtx->mode = usageSpec->mode;
    outCtx->padding = usageSpec->padding;
    (void)memcpy_s(outCtx->iv, HKS_AES_CBC_NOPADDING_IV_SIZE, iv->iv.data, HKS_AES_CBC_NOPADDING_IV_SIZE);

    *cryptoCtx = (void *)outCtx;

    return ret;
}

static int32_t AesCbcNoPaddingCryptUpdate(void *cryptoCtx,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    struct HksMbedtlsAesCtx *aesCtx = (struct HksMbedtlsAesCtx *)cryptoCtx;
    HKS_IF_NULL_RETURN(aesCtx, HKS_ERROR_NULL_POINTER)

    mbedtls_aes_context *cbcNoPaddingCtx = (mbedtls_aes_context *)aesCtx->append;

    HKS_IF_NULL_RETURN(cbcNoPaddingCtx, HKS_ERROR_NULL_POINTER)

    int32_t ret;
    do {
        if (message->size % HKS_AES_CBC_DATA_BLOB_SIZE != 0) {
            HKS_LOG_E("AesCbcNoPaddingCryptUpdate data size invalid!");
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }

        /* mbedtls_aes_crypt_cbc will refresh iv, so need a temp iv */
        uint8_t tmpIv[HKS_AES_CBC_NOPADDING_IV_SIZE];
        if (memcpy_s(tmpIv, HKS_AES_CBC_NOPADDING_IV_SIZE, aesCtx->iv, HKS_AES_CBC_NOPADDING_IV_SIZE) != EOK) {
            HKS_LOG_E("Memcpy temp iv failed!");
            ret = HKS_ERROR_INVALID_IV;
            break;
        }

        ret = mbedtls_aes_crypt_cbc(cbcNoPaddingCtx,
            (encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT),
            message->size,
            tmpIv,
            message->data,
            cipherText->data);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtks aes cbc nopadding crypt failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        cipherText->size = message->size;
        if (memcpy_s(aesCtx->iv, HKS_AES_CBC_NOPADDING_IV_SIZE, tmpIv, HKS_AES_CBC_NOPADDING_IV_SIZE) != EOK) {
            HKS_LOG_E("copy aesCtx failed!");
            ret = HKS_ERROR_INSUFFICIENT_MEMORY;
            break;
        }
    } while (0);

    return ret;
}

static int32_t AesCbcNoPaddingCryptFinal(void **cryptoCtx,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    struct HksMbedtlsAesCtx *aesCtx = (struct HksMbedtlsAesCtx *)*cryptoCtx;
    mbedtls_aes_context *cbcNoPaddingCtx = (mbedtls_aes_context *)aesCtx->append;

    if (cbcNoPaddingCtx == NULL) {
        HKS_FREE(*cryptoCtx);
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret = HKS_SUCCESS;
    do {
        if (message->size % HKS_AES_CBC_DATA_BLOB_SIZE != 0) {
            HKS_LOG_E("AesCbcNoPaddingCryptFinal data size invalid!");
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }

        if (message->size != 0) {
            /* mbedtls_aes_crypt_cbc will refresh iv, so need a temp iv */
            uint8_t tmpIv[HKS_AES_CBC_NOPADDING_IV_SIZE];
            if (memcpy_s(tmpIv, HKS_AES_CBC_NOPADDING_IV_SIZE, aesCtx->iv, HKS_AES_CBC_NOPADDING_IV_SIZE) != EOK) {
                HKS_LOG_E("Memcpy temp iv failed!");
                ret = HKS_ERROR_INVALID_IV;
                break;
            }
            ret = mbedtls_aes_crypt_cbc(cbcNoPaddingCtx,
                (encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT),
                message->size,
                tmpIv,
                message->data,
                cipherText->data);
            if (ret != HKS_MBEDTLS_SUCCESS) {
                HKS_LOG_E("Mbedtls aes gcm encryot failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
                (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
                ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
                break;
            }
        }
        cipherText->size = message->size;
    } while (0);

    mbedtls_aes_free(cbcNoPaddingCtx);
    HKS_FREE(aesCtx->append);
    HKS_FREE(*cryptoCtx);

    return ret;
}
#endif /* HKS_SUPPORT_AES_CBC_NOPADDING */

#ifdef HKS_SUPPORT_AES_CBC_PKCS7
static int32_t AesCbcPkcs7Crypt(const struct HksBlob *key, const struct HksCipherParam *cipherParam,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    const uint32_t keyBitLen = key->size * HKS_BITS_PER_BYTE;
    const mbedtls_cipher_info_t *info =
        mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, keyBitLen, MBEDTLS_MODE_CBC);

    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    int32_t ret;
    do {
        ret = mbedtls_cipher_setup(&ctx, info);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls cbc pkcs7 setup ctx failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        ret = mbedtls_cipher_setkey(&ctx, key->data, keyBitLen, (encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT));
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls cbc pkcs7 set key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        size_t keyLen = cipherText->size;
        ret = mbedtls_cipher_crypt(&ctx,
            cipherParam->iv.data,
            cipherParam->iv.size,
            message->data,
            message->size,
            cipherText->data,
            &keyLen);
        cipherText->size = (uint32_t)keyLen;
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls cbc pkcs7 crypt failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
        }
    } while (0);

    mbedtls_cipher_free(&ctx);
    return ret;
}

static int32_t AesCbcPkcs7CryptInitParam(const struct HksBlob *key, mbedtls_cipher_context_t *cbcPkcs7ctx,
    const bool encrypt)
{
    const uint32_t keyBitLen = key->size * HKS_BITS_PER_BYTE;
    const mbedtls_cipher_info_t *info =
        mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, keyBitLen, MBEDTLS_MODE_CBC);
    if (info == NULL) {
        HKS_LOG_E("get cipher info from values failed!");
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    int32_t ret = mbedtls_cipher_setup(cbcPkcs7ctx, info);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls cbc pkcs7 setup ctx failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = mbedtls_cipher_setkey(cbcPkcs7ctx, key->data, keyBitLen, (encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT));
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls cbc pkcs7 set key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return HKS_SUCCESS;
}

static int32_t AesCbcPkcs7CryptInit(void **cryptoCtx, const struct HksBlob *key,
    const struct HksUsageSpec *usageSpec, const bool encrypt)
{
    mbedtls_cipher_context_t *cbcPkcs7ctx = (mbedtls_cipher_context_t *)HksMalloc(sizeof(mbedtls_cipher_context_t));
    HKS_IF_NULL_LOGE_RETURN(cbcPkcs7ctx, HKS_ERROR_MALLOC_FAIL, "malloc cbcPkcs7ctx fail")
    mbedtls_cipher_init(cbcPkcs7ctx);

    int32_t ret = AesCbcPkcs7CryptInitParam(key, cbcPkcs7ctx, encrypt);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("AesCbcPkcs7CryptInitParam fail %" LOG_PUBLIC "d", ret);
        mbedtls_cipher_free(cbcPkcs7ctx);
        HKS_FREE(cbcPkcs7ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    const struct HksCipherParam *cipherParam = (struct HksCipherParam *)(usageSpec->algParam);
    ret = mbedtls_cipher_set_padding_mode(cbcPkcs7ctx, MBEDTLS_PADDING_PKCS7);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls cbc pkcs7 set padding mode failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_cipher_free(cbcPkcs7ctx);
        HKS_FREE(cbcPkcs7ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = mbedtls_cipher_set_iv(cbcPkcs7ctx, cipherParam->iv.data, cipherParam->iv.size);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls cbc pkcs7 set iv failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_cipher_free(cbcPkcs7ctx);
        HKS_FREE(cbcPkcs7ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    ret = mbedtls_cipher_reset(cbcPkcs7ctx);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls cbc pkcs7 reset failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_cipher_free(cbcPkcs7ctx);
        HKS_FREE(cbcPkcs7ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    struct HksMbedtlsAesCtx *outCtx = (struct HksMbedtlsAesCtx *)HksMalloc(sizeof(HksMbedtlsAesCtx));
    if (outCtx == NULL) {
        HKS_LOG_E("malloc outCtx fail");
        mbedtls_cipher_free(cbcPkcs7ctx);
        HKS_FREE(cbcPkcs7ctx);
        return HKS_ERROR_MALLOC_FAIL;
    }

    outCtx->mode = usageSpec->mode;
    outCtx->padding = usageSpec->padding;
    outCtx->append = (void *)cbcPkcs7ctx;

    *cryptoCtx = (void *)outCtx;

    return ret;
}

static int32_t AesCbcPkcs7CryptUpdate(void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    struct HksMbedtlsAesCtx *aesCtx = (struct HksMbedtlsAesCtx *)cryptoCtx;
    mbedtls_cipher_context_t *cbcPkcs7ctx = (mbedtls_cipher_context_t *)aesCtx->append;

    HKS_IF_NULL_RETURN(cbcPkcs7ctx, HKS_ERROR_NULL_POINTER)
    size_t keyLen = cipherText->size;
    int32_t ret = mbedtls_cipher_update(cbcPkcs7ctx, message->data, message->size, cipherText->data,
        &keyLen);
    cipherText->size = (uint32_t)keyLen;
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls cbc pkcs7 crypt update failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
        ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return ret;
}

static int32_t AesCbcPkcs7CryptFinal(void **cryptoCtx, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    struct HksMbedtlsAesCtx *aesCtx = (struct HksMbedtlsAesCtx *)*cryptoCtx;
    mbedtls_cipher_context_t *cbcPkcs7ctx = (mbedtls_cipher_context_t *)aesCtx->append;

    if (cbcPkcs7ctx == NULL) {
        HKS_FREE(*cryptoCtx);
        return HKS_ERROR_NULL_POINTER;
    }

    size_t finish_olen;
    int32_t ret;
    do {
        cipherText->size = 0;
        if (message->size != 0) {
            size_t keyLen = cipherText->size;
            ret = mbedtls_cipher_update(cbcPkcs7ctx, message->data, message->size, cipherText->data,
                &keyLen);
            cipherText->size = (uint32_t)keyLen;
            if (ret != HKS_MBEDTLS_SUCCESS) {
                HKS_LOG_E("Mbedtls cbc pkcs7 crypt update failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
                (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
                ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
                break;
            }
        }

        size_t olen = (size_t)cipherText->size;
        ret = mbedtls_cipher_finish(cbcPkcs7ctx, cipherText->data + olen, &finish_olen);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls cbc pkcs7 crypt finish failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        cipherText->size = olen + finish_olen;
    } while (0);

    mbedtls_cipher_free(cbcPkcs7ctx);
    HKS_FREE(aesCtx->append);
    HKS_FREE(*cryptoCtx);

    return ret;
}
#endif /* HKS_SUPPORT_AES_CBC_PKCS7 */

#if defined(HKS_SUPPORT_AES_CBC_NOPADDING) || defined(HKS_SUPPORT_AES_CBC_PKCS7)
static int32_t AesCbcCrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    const struct HksCipherParam *cipherParam = (struct HksCipherParam *)(usageSpec->algParam);

    switch (usageSpec->padding) {
#ifdef HKS_SUPPORT_AES_CBC_NOPADDING
        case HKS_PADDING_NONE:
            return AesCbcNoPaddingCrypt(key, cipherParam, message, encrypt, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_CBC_PKCS7
        case HKS_PADDING_PKCS7:
            return AesCbcPkcs7Crypt(key, cipherParam, message, encrypt, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", usageSpec->padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t AesCbcCryptInit(void **cryptoCtx, const struct HksBlob *key,
    const struct HksUsageSpec *usageSpec, const bool encrypt)
{
    switch (usageSpec->padding) {
#ifdef HKS_SUPPORT_AES_CBC_NOPADDING
        case HKS_PADDING_NONE:
            return AesCbcNoPaddingCryptInit(cryptoCtx, key, usageSpec, encrypt);
#endif
#ifdef HKS_SUPPORT_AES_CBC_PKCS7
        case HKS_PADDING_PKCS7:
            return AesCbcPkcs7CryptInit(cryptoCtx, key, usageSpec, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", usageSpec->padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t AesCbcCryptUpdate(void *cryptoCtx, const uint8_t padding,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    switch (padding) {
#ifdef HKS_SUPPORT_AES_CBC_NOPADDING
        case HKS_PADDING_NONE:
            return AesCbcNoPaddingCryptUpdate(cryptoCtx, message, encrypt, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_CBC_PKCS7
        case HKS_PADDING_PKCS7:
            return AesCbcPkcs7CryptUpdate(cryptoCtx, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t AesCbcCryptFinal(void **cryptoCtx, const uint8_t padding,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    switch (padding) {
#ifdef HKS_SUPPORT_AES_CBC_NOPADDING
        case HKS_PADDING_NONE:
            return AesCbcNoPaddingCryptFinal(cryptoCtx, message, encrypt, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_CBC_PKCS7
        case HKS_PADDING_PKCS7:
            return AesCbcPkcs7CryptFinal(cryptoCtx, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}
#endif /* HKS_SUPPORT_AES_CBC_NOPADDING or HKS_SUPPORT_AES_CBC_PKCS7 */

#ifdef HKS_SUPPORT_AES_GCM
static int32_t AesEncryptGcm(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText, struct HksBlob *tagAead)
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int32_t ret;
    do {
        ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key->data, key->size * HKS_BITS_PER_BYTE);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls aes gcm set key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        const struct HksAeadParam *aeadParam = (struct HksAeadParam *)(usageSpec->algParam);
        ret = mbedtls_gcm_crypt_and_tag(&ctx,
            MBEDTLS_GCM_ENCRYPT,
            message->size,
            aeadParam->nonce.data,
            aeadParam->nonce.size,
            aeadParam->aad.data,
            aeadParam->aad.size,
            message->data,
            cipherText->data,
            tagAead->size,
            tagAead->data);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls aes gcm encryot failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
            (void)memset_s(tagAead->data, tagAead->size, 0, tagAead->size);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        cipherText->size = message->size;
    } while (0);

    mbedtls_gcm_free(&ctx);
    return ret;
}

static int32_t AesEncryptGcmInit(void **cryptoCtx, const struct HksUsageSpec *usageSpec, const struct HksBlob *key)
{
    mbedtls_gcm_context *gcmCtx = (mbedtls_gcm_context *)HksMalloc(sizeof(mbedtls_gcm_context));
    HKS_IF_NULL_LOGE_RETURN(gcmCtx, HKS_ERROR_MALLOC_FAIL, "Gcm gcmCtx malloc fail")

    mbedtls_gcm_init(gcmCtx);

    int32_t ret = mbedtls_gcm_setkey(gcmCtx, MBEDTLS_CIPHER_ID_AES, key->data, key->size * HKS_BITS_PER_BYTE);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls aes gcm set key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_gcm_free(gcmCtx);
        HKS_FREE(gcmCtx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    const struct HksAeadParam *aeadParam = (struct HksAeadParam *)(usageSpec->algParam);
#ifdef USE_HISI_MBED
    ret = mbedtls_gcm_starts(gcmCtx, MBEDTLS_GCM_ENCRYPT, aeadParam->nonce.data,
        aeadParam->nonce.size, aeadParam->aad.data, aeadParam->aad.size);
#else
    ret = mbedtls_gcm_starts(gcmCtx, MBEDTLS_GCM_ENCRYPT, aeadParam->nonce.data,
        aeadParam->nonce.size);
#endif
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls aes gcm start failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_gcm_free(gcmCtx);
        HKS_FREE(gcmCtx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    struct HksMbedtlsAesCtx *outCtx = (struct HksMbedtlsAesCtx *)HksMalloc(sizeof(struct HksMbedtlsAesCtx));
    if (outCtx == NULL) {
        HKS_LOG_E("initialize outCtx fail");
        mbedtls_gcm_free(gcmCtx);
        HKS_FREE(gcmCtx);
        return HKS_ERROR_MALLOC_FAIL;
    }

    outCtx->mode = usageSpec->mode;
    outCtx->append = (void *)gcmCtx;
    *cryptoCtx = (void *)outCtx;

    return ret;
}

static int32_t MbedtlsGcmUpdate(mbedtls_gcm_context *gcmCtx, const struct HksBlob *message,
    struct HksBlob *cipherText, bool isEncrypt)
{
    int32_t ret;
#ifdef USE_HISI_MBED
    ret = mbedtls_gcm_update(gcmCtx, message->size, message->data, cipherText->data);
#else
    size_t size = 0;
    ret = mbedtls_gcm_update(gcmCtx, message->data, message->size, cipherText->data, cipherText->size, &size);
#endif
    if (ret != HKS_MBEDTLS_SUCCESS) {
        if (isEncrypt) {
            HKS_LOG_E("Mbedtls aes gcm encrypt update failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        } else {
            HKS_LOG_E("Mbedtls aes gcm decrypt update failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        }
        (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
        ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return ret;
}

static int32_t MbedtlsGcmFinish(mbedtls_gcm_context *gcmCtx, uint8_t *tagAeadData, uint32_t tagAeadSize, bool isEncrypt)
{
    int32_t ret;
#ifdef USE_HISI_MBED
    ret = mbedtls_gcm_finish(gcmCtx, tagAeadData, tagAeadSize);
#else
    size_t size = 0;
    ret = mbedtls_gcm_finish(gcmCtx, tagAeadData, tagAeadSize, &size, tagAeadData, tagAeadSize);
#endif
    if (ret != HKS_MBEDTLS_SUCCESS) {
        if (isEncrypt) {
            HKS_LOG_E("Mbedtls aes gcm encrypt update failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        } else {
            HKS_LOG_E("Mbedtls aes gcm decrypt update failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        }
        (void)memset_s(tagAeadData, tagAeadSize, 0, tagAeadSize);
        ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return ret;
}

static int32_t AesEncryptGcmUpdate(void *cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    (void)padding;

    struct HksMbedtlsAesCtx *aesCtx = (struct HksMbedtlsAesCtx *)cryptoCtx;
    mbedtls_gcm_context *gcmCtx = (mbedtls_gcm_context *)aesCtx->append;
    HKS_IF_NULL_LOGE_RETURN(gcmCtx, HKS_ERROR_NULL_POINTER, "GcmUpdate gcmCtx is null")

    int32_t ret = MbedtlsGcmUpdate(gcmCtx, message, cipherText, true);
    if (ret == HKS_MBEDTLS_SUCCESS) {
        cipherText->size = message->size;
    }
    return ret;
}

static int32_t AesEncryptGcmFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText,
    struct HksBlob *tagAead)
{
    struct HksMbedtlsAesCtx *aesCtx = (struct HksMbedtlsAesCtx *)*cryptoCtx;
    mbedtls_gcm_context *gcmCtx = (mbedtls_gcm_context *)aesCtx->append;
    if (gcmCtx == NULL) {
        HKS_LOG_E("GcmFinal gcmCtx is null");
        HKS_FREE(*cryptoCtx);
        return HKS_ERROR_NULL_POINTER;
    }

    int32_t ret;
    do {
        if (message->size != 0) {
            ret = MbedtlsGcmUpdate(gcmCtx, message, cipherText, true);
            if (ret != HKS_MBEDTLS_SUCCESS) {
                break;
            }
        }
        cipherText->size = message->size;
        ret = MbedtlsGcmFinish(gcmCtx, tagAead->data, tagAead->size, true);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            break;
        }
    } while (0);

    mbedtls_gcm_free(gcmCtx);
    HKS_FREE(aesCtx->append);
    HKS_FREE(*cryptoCtx);
    return ret;
}

static int32_t AesDecryptGcm(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText)
{
    mbedtls_gcm_context ctx;
    (void)memset_s(&ctx, sizeof(mbedtls_gcm_context), 0, sizeof(mbedtls_gcm_context));
    mbedtls_gcm_init(&ctx);

    int32_t ret;
    do {
        ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key->data, key->size * HKS_BITS_PER_BYTE);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls aes gcm set key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        const struct HksAeadParam *aeadParam = (struct HksAeadParam *)(usageSpec->algParam);
        ret = mbedtls_gcm_auth_decrypt(&ctx,
            message->size,
            aeadParam->nonce.data,
            aeadParam->nonce.size,
            aeadParam->aad.data,
            aeadParam->aad.size,
            aeadParam->tagDec.data,
            aeadParam->tagDec.size,
            message->data,
            cipherText->data);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls aes gcm decrypt failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        cipherText->size = message->size;
    } while (0);

    mbedtls_gcm_free(&ctx);
    return ret;
}

static int32_t AesDecryptGcmInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec)
{
    mbedtls_gcm_context *gcmCtx = (mbedtls_gcm_context*)HksMalloc(sizeof(mbedtls_gcm_context));
    HKS_IF_NULL_LOGE_RETURN(gcmCtx, HKS_ERROR_MALLOC_FAIL, "Decrtyt Gcm gcmCtx malloc fail")

    mbedtls_gcm_init(gcmCtx);

    int32_t ret = mbedtls_gcm_setkey(gcmCtx, MBEDTLS_CIPHER_ID_AES, key->data, key->size * HKS_BITS_PER_BYTE);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls aes gcm set key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_gcm_free(gcmCtx);
        HKS_FREE(gcmCtx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    const struct HksAeadParam *aeadParam = (struct HksAeadParam *)(usageSpec->algParam);
#ifdef USE_HISI_MBED
    ret = mbedtls_gcm_starts(gcmCtx, MBEDTLS_GCM_DECRYPT, aeadParam->nonce.data,
        aeadParam->nonce.size, aeadParam->aad.data, aeadParam->aad.size);
#else
    ret = mbedtls_gcm_starts(gcmCtx, MBEDTLS_GCM_DECRYPT, aeadParam->nonce.data,
        aeadParam->nonce.size);
#endif
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls aes gcm start failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_gcm_free(gcmCtx);
        HKS_FREE(gcmCtx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    struct HksMbedtlsAesCtx *outCtx = (struct HksMbedtlsAesCtx *)HksMalloc(sizeof(struct HksMbedtlsAesCtx));
    if (outCtx == NULL) {
        mbedtls_gcm_free(gcmCtx);
        HKS_FREE(gcmCtx);
        return HKS_ERROR_MALLOC_FAIL;
    }

    outCtx->mode = usageSpec->mode;
    outCtx->append = (void *)gcmCtx;
    *cryptoCtx = (void *)outCtx;

    return ret;
}

static int32_t AesDecryptGcmUpdate(void *cryptoCtx,
    const struct HksBlob *message, struct HksBlob *cipherText)
{
    struct HksMbedtlsAesCtx *aesCtx = (struct HksMbedtlsAesCtx *)cryptoCtx;
    mbedtls_gcm_context *gcmCtx = (mbedtls_gcm_context *)aesCtx->append;
    HKS_IF_NULL_LOGE_RETURN(gcmCtx, HKS_FAILURE, "GcmUpdate gcmCtx is null")

    int32_t ret = MbedtlsGcmUpdate(gcmCtx, message, cipherText, false);
    if (ret == HKS_MBEDTLS_SUCCESS) {
        cipherText->size = message->size;
    }

    return ret;
}

static int32_t AesDecryptGcmFinal(void **cryptoCtx, const struct HksBlob *message,
                                  struct HksBlob *cipherText, struct HksBlob *tagAead)
{
    struct HksMbedtlsAesCtx *aesCtx = (struct HksMbedtlsAesCtx *)*cryptoCtx;
    mbedtls_gcm_context *gcmCtx = (mbedtls_gcm_context *)aesCtx->append;
    if (gcmCtx == NULL) {
        HKS_LOG_E("GcmFinal gcmCtx is null");
        HKS_FREE(*cryptoCtx);
        return HKS_FAILURE;
    }

    int32_t ret;
    do {
        if (message->size != 0) {
            ret = MbedtlsGcmUpdate(gcmCtx, message, cipherText, false);
            if (ret != HKS_MBEDTLS_SUCCESS) {
                break;
            }
        }
        cipherText->size = message->size;

        uint8_t check_tag[16];
        ret = MbedtlsGcmFinish(gcmCtx, check_tag, tagAead->size, false);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            break;
        }

        uint8_t diff;
        size_t i;
        /* Check tag in "constant-time" */
        for (diff = 0, i = 0; i < tagAead->size; i++) {
            diff |= tagAead->data[i] ^ check_tag[i];
        }

        if (diff != 0) {
            mbedtls_platform_zeroize(cipherText->data, message->size);
            HKS_LOG_E("gcm auth failed!");
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
    } while (0);

    mbedtls_gcm_free(gcmCtx);
    HKS_FREE(aesCtx->append);
    HKS_FREE(*cryptoCtx);

    return ret;
}
#endif /* HKS_SUPPORT_AES_GCM */

#ifdef HKS_SUPPORT_AES_CCM
static int32_t AesEncryptCcm(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText, struct HksBlob *tagAead)
{
    mbedtls_ccm_context ctx;
    (void)memset_s(&ctx, sizeof(mbedtls_ccm_context), 0, sizeof(mbedtls_ccm_context));
    mbedtls_ccm_init(&ctx);

    int32_t ret;
    do {
        ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key->data, key->size * HKS_BITS_PER_BYTE);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls aes ccm set key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        const struct HksAeadParam *aeadParam = (struct HksAeadParam *)(usageSpec->algParam);
        ret = mbedtls_ccm_encrypt_and_tag(&ctx,
            message->size,
            aeadParam->nonce.data,
            aeadParam->nonce.size,
            aeadParam->aad.data,
            aeadParam->aad.size,
            message->data,
            cipherText->data,
            tagAead->data,
            tagAead->size);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls aes ccm encrypt failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
            (void)memset_s(tagAead->data, tagAead->size, 0, tagAead->size);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        cipherText->size = message->size;
    } while (0);

    mbedtls_ccm_free(&ctx);
    return ret;
}

static int32_t AesDecryptCcm(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText)
{
    mbedtls_ccm_context ctx;
    (void)memset_s(&ctx, sizeof(mbedtls_ccm_context), 0, sizeof(mbedtls_ccm_context));
    mbedtls_ccm_init(&ctx);

    int32_t ret;
    do {
        ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key->data, key->size * HKS_BITS_PER_BYTE);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls aes ccm set key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        const struct HksAeadParam *aeadParam = (struct HksAeadParam *)(usageSpec->algParam);
        ret = mbedtls_ccm_auth_decrypt(&ctx,
            message->size,
            aeadParam->nonce.data,
            aeadParam->nonce.size,
            aeadParam->aad.data,
            aeadParam->aad.size,
            message->data,
            cipherText->data,
            aeadParam->tagDec.data,
            aeadParam->tagDec.size);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls aes ccm decrypt failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        cipherText->size = message->size;
    } while (0);

    mbedtls_ccm_free(&ctx);
    return ret;
}
#endif /* HKS_SUPPORT_AES_CCM */

#ifdef HKS_SUPPORT_AES_CTR_NOPADDING
static int32_t AesCtrCrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    const struct HksCipherParam *cipherParam = (struct HksCipherParam *)(usageSpec->algParam);
    mbedtls_cipher_context_t ctx;
    (void)memset_s(&ctx, sizeof(mbedtls_cipher_context_t), 0, sizeof(mbedtls_cipher_context_t));
    mbedtls_cipher_init(&ctx);

    int32_t ret;
    do {
        const mbedtls_cipher_info_t *info =
            mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, key->size * HKS_BITS_PER_BYTE, MBEDTLS_MODE_CTR);
        if (info == NULL) {
            HKS_LOG_E("get cipher info from values failed!");
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        ret = mbedtls_cipher_setup(&ctx, info);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls failed ret = %" LOG_PUBLIC "d", ret);
            break;
        }

        ret = mbedtls_cipher_setkey(
            &ctx, key->data, key->size * HKS_BITS_PER_BYTE, encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls failed ret = %" LOG_PUBLIC "d", ret);
            break;
        }

        size_t outLen;
        ret = mbedtls_cipher_crypt(
            &ctx, cipherParam->iv.data, cipherParam->iv.size, message->data, message->size, cipherText->data, &outLen);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls failed ret = 0x%" LOG_PUBLIC "X", ret);
            break;
        }
        cipherText->size = outLen;

        mbedtls_cipher_free(&ctx);
        return HKS_SUCCESS;
    } while (0);

    mbedtls_cipher_free(&ctx);
    return HKS_ERROR_CRYPTO_ENGINE_ERROR;
}

static int32_t AesCtrCryptInitParam(const struct HksBlob *key, mbedtls_cipher_context_t *ctrCtx,
    const bool encrypt)
{
    int32_t ret;
    const mbedtls_cipher_info_t *info =
        mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, key->size * HKS_BITS_PER_BYTE, MBEDTLS_MODE_CTR);
    if (info == NULL) {
        HKS_LOG_E("get cipher info from values failed!");
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    ret = mbedtls_cipher_setup(ctrCtx, info);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls failed ret = %" LOG_PUBLIC "d", ret);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = mbedtls_cipher_setkey(
        ctrCtx, key->data, key->size * HKS_BITS_PER_BYTE, encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls failed ret = %" LOG_PUBLIC "d", ret);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return HKS_SUCCESS;
}

static int32_t AesCtrCryptInit(void **cryptoCtx, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *key, const bool encrypt)
{
    mbedtls_cipher_context_t *ctrCtx = (mbedtls_cipher_context_t *)HksMalloc(sizeof(mbedtls_cipher_context_t));
    HKS_IF_NULL_LOGE_RETURN(ctrCtx, HKS_ERROR_MALLOC_FAIL, "Ctr ctrCtx malloc fail")

    mbedtls_cipher_init(ctrCtx);

    int32_t ret;
    ret = AesCtrCryptInitParam(key, ctrCtx, encrypt);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("AesCtrCryptInitParam failed ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_cipher_free(ctrCtx);
        HKS_FREE(ctrCtx);
        return ret;
    }

    const struct HksCipherParam *cipherParam = (struct HksCipherParam *)(usageSpec->algParam);
    if (cipherParam == NULL) {
        HKS_LOG_E("Gcm cipherParam is null");
        mbedtls_cipher_free(ctrCtx);
        HKS_FREE(ctrCtx);
        return HKS_FAILURE;
    }

    ret = mbedtls_cipher_set_iv(ctrCtx, cipherParam->iv.data, cipherParam->iv.size);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Mbedtls cbc pkcs7 set iv failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_cipher_free(ctrCtx);
        HKS_FREE(ctrCtx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    ret = mbedtls_cipher_reset(ctrCtx);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Mbedtls cbc pkcs7 reset failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        mbedtls_cipher_free(ctrCtx);
        HKS_FREE(ctrCtx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    struct HksMbedtlsAesCtx *outCtx = (struct HksMbedtlsAesCtx *)HksMalloc(sizeof(HksMbedtlsAesCtx));
    if (outCtx == NULL) {
        mbedtls_cipher_free(ctrCtx);
        HKS_FREE(ctrCtx);
        return HKS_ERROR_MALLOC_FAIL;
    }

    outCtx->mode = usageSpec->mode;
    outCtx->padding = usageSpec->padding;
    outCtx->append = (void *)ctrCtx;

    *cryptoCtx = (void *)outCtx;
    return ret;
}

static int32_t AesCtrCryptUpdate(void *cryptoCtx,
    const struct HksBlob *message, struct HksBlob *cipherText)
{
    struct HksMbedtlsAesCtx *aesCtx = (struct HksMbedtlsAesCtx *)cryptoCtx;
    mbedtls_cipher_context_t *ctrCtx = (mbedtls_cipher_context_t *)aesCtx->append;
    HKS_IF_NULL_LOGE_RETURN(ctrCtx, HKS_FAILURE, "CtrUpdate ctrCtx is null")

    size_t olen;
    int32_t ret = mbedtls_cipher_update(ctrCtx, message->data, message->size, cipherText->data, &olen);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls cipher update failed ret = 0x%" LOG_PUBLIC "X", ret);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    cipherText->size = olen;
    return ret;
}

static int32_t AesCtrCryptFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    struct HksMbedtlsAesCtx *aesCtx = (struct HksMbedtlsAesCtx *)*cryptoCtx;
    mbedtls_cipher_context_t *ctrCtx = (mbedtls_cipher_context_t *)aesCtx->append;
    if (ctrCtx == NULL) {
        HKS_LOG_E("CtrFinal ctrCtx is null");
        HKS_FREE(*cryptoCtx);
        return HKS_FAILURE;
    }

    int32_t ret;
    do {
        size_t olen = (size_t)cipherText->size;
        if (message->size != 0) {
            ret = mbedtls_cipher_update(ctrCtx, message->data, message->size, cipherText->data, &olen);
            if (ret != HKS_MBEDTLS_SUCCESS) {
                HKS_LOG_E("Mbedtls cipher update failed ret = 0x%" LOG_PUBLIC "X", ret);
                ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
                break;
            }
        }

        size_t finish_olen;
        ret = mbedtls_cipher_finish(ctrCtx, cipherText->data + olen, &finish_olen);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls cipher update failed ret = 0x%" LOG_PUBLIC "X", ret);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        } else {
            cipherText->size = (uint32_t)(olen + finish_olen);
        }
    } while (0);

    mbedtls_cipher_free(ctrCtx);
    HKS_FREE(aesCtx->append);
    HKS_FREE(*cryptoCtx);
    return ret;
}
#endif

#ifdef HKS_SUPPORT_AES_ECB_NOPADDING
static int32_t AesEcbNoPaddingCrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    (void)usageSpec;
    mbedtls_cipher_context_t ctx;
    (void)memset_s(&ctx, sizeof(mbedtls_cipher_context_t), 0, sizeof(mbedtls_cipher_context_t));
    mbedtls_cipher_init(&ctx);

    int32_t ret;
    do {
        const mbedtls_cipher_info_t *info =
            mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, key->size * HKS_BITS_PER_BYTE, MBEDTLS_MODE_ECB);
        if (info == NULL) {
            HKS_LOG_E("get cipher info from values failed!");
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        ret = mbedtls_cipher_setup(&ctx, info);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls failed ret = %" LOG_PUBLIC "d", ret);
            break;
        }

        ret = mbedtls_cipher_setkey(
            &ctx, key->data, key->size * HKS_BITS_PER_BYTE, encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls failed ret = %" LOG_PUBLIC "d", ret);
            break;
        }

        size_t outLen;
        ret = mbedtls_cipher_crypt(&ctx, NULL, 0, message->data, message->size, cipherText->data, &outLen);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls failed ret = 0x%" LOG_PUBLIC "X", ret);
            break;
        }
        cipherText->size = outLen;

        mbedtls_cipher_free(&ctx);
        return HKS_SUCCESS;
    } while (0);

    mbedtls_cipher_free(&ctx);
    return HKS_ERROR_CRYPTO_ENGINE_ERROR;
}

static int32_t AesEcbNoPaddingCryptInitParam(const struct HksBlob *key, mbedtls_cipher_context_t *ecbCtx,
    const bool encrypt)
{
    const mbedtls_cipher_info_t *info =
        mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, key->size * HKS_BITS_PER_BYTE, MBEDTLS_MODE_ECB);
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

static int32_t AesEcbNoPaddingCryptInit(void **cryptoCtx, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *key, const bool encrypt)
{
    mbedtls_cipher_context_t *ecbCtx = (mbedtls_cipher_context_t *)HksMalloc(sizeof(mbedtls_cipher_context_t));
    HKS_IF_NULL_LOGE_RETURN(ecbCtx, HKS_ERROR_MALLOC_FAIL, "Ecb ecbCtx malloc fail")

    mbedtls_cipher_init(ecbCtx);

    int32_t ret = AesEcbNoPaddingCryptInitParam(key, ecbCtx, encrypt);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("AesEcbNoPaddingCryptInitParam failed ret = %" LOG_PUBLIC "d", ret);
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

    struct HksMbedtlsAesCtx *outCtx = (struct HksMbedtlsAesCtx *)HksMalloc(sizeof(HksMbedtlsAesCtx));
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

static int32_t AesEcbNoPaddingData(mbedtls_cipher_context_t *ecbNoPadingctx, size_t blockSize,
    const struct HksBlob *message, struct HksBlob *cipherText, size_t *olenTotal)
{
    int32_t ret;

    uint8_t *tmpMessage = (uint8_t *)HksMalloc(blockSize);
    HKS_IF_NULL_LOGE_RETURN(tmpMessage, HKS_ERROR_INSUFFICIENT_MEMORY, "EcbNoPaddingUpdate tmpMessage is null")

    if (message->size <= blockSize) {
        (void)memset_s(tmpMessage, blockSize, 0, blockSize);
        (void)memcpy_s(tmpMessage, message->size, message->data, message->size);
        ret = mbedtls_cipher_update(ecbNoPadingctx, tmpMessage, blockSize, cipherText->data, olenTotal);
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
            if (memcpy_s(tmpMessage, blockSize, message->data + point, tmpSize)) {
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
            *olenTotal += olen;
            point += blockSize;
        }
    }
    HKS_FREE(tmpMessage);
    return HKS_SUCCESS;
}

static mbedtls_cipher_context_t *GetAesEcbNoPaddingCtx(void *cryptoCtx, const struct HksBlob *message,
    struct HksBlob *cipherText, size_t *olenTotal)
{
    struct HksMbedtlsAesCtx *aesCtx = (struct HksMbedtlsAesCtx *)cryptoCtx;
    mbedtls_cipher_context_t *ecbNoPadingctx = (mbedtls_cipher_context_t *)aesCtx->append;
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

            ret = AesEcbNoPaddingData(ecbNoPadingctx, blockSize, message, cipherText, olenTotal);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "AesEcbNoPaddingData failed")
        }
    } while (0);

    HKS_IF_NOT_SUCC_RETURN(ret, NULL)

    return ecbNoPadingctx;
}

static int32_t AesEcbNoPaddingCryptUpdate(void *cryptoCtx, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    size_t olenTotal = 0;
    HKS_IF_NULL_RETURN(GetAesEcbNoPaddingCtx(cryptoCtx, message, cipherText, &olenTotal), HKS_ERROR_NULL_POINTER)

    cipherText->size = olenTotal;
    return HKS_SUCCESS;
}

static int32_t AesEcbNoPaddingCryptFinal(void **cryptoCtx, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    size_t olenTotal = 0;
    mbedtls_cipher_context_t *ecbNoPadingctx = GetAesEcbNoPaddingCtx(*cryptoCtx, message, cipherText, &olenTotal);
    if (ecbNoPadingctx == NULL) {
        HKS_FREE(*cryptoCtx);
        return HKS_ERROR_NULL_POINTER;
    }

    struct HksMbedtlsAesCtx *aesCtx = (struct HksMbedtlsAesCtx *)*cryptoCtx;
    size_t finish_olen;
    size_t olen = olenTotal;
    int32_t ret = mbedtls_cipher_finish(ecbNoPadingctx, cipherText->data + olen, &finish_olen);
    if (ret != HKS_MBEDTLS_SUCCESS) {
        HKS_LOG_E("Mbedtls ecb nopadding crypt update failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
        ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    } else {
        cipherText->size = olen + finish_olen;
    }

    mbedtls_cipher_free(ecbNoPadingctx);
    HKS_FREE(aesCtx->append);
    HKS_FREE(*cryptoCtx);

    return ret;
}
#endif

#if defined(HKS_SUPPORT_AES_ECB_NOPADDING) || defined(HKS_SUPPORT_AES_ECB_PKCS7PADDING)
static int32_t AesEcbCrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    switch (usageSpec->padding) {
#ifdef HKS_SUPPORT_AES_ECB_NOPADDING
        case HKS_PADDING_NONE:
            return AesEcbNoPaddingCrypt(key, usageSpec, message, encrypt, cipherText);
#endif
        case HKS_PADDING_PKCS7:
            return HKS_ERROR_NOT_SUPPORTED;
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", usageSpec->padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t AesEcbCryptInit(void **cryptoCtx, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *key, const bool encrypt)
{
    switch (usageSpec->padding) {
#ifdef HKS_SUPPORT_AES_ECB_NOPADDING
        case HKS_PADDING_NONE:
            return AesEcbNoPaddingCryptInit(cryptoCtx, usageSpec, key, encrypt);
#endif
        case HKS_PADDING_PKCS7:
            return HKS_ERROR_NOT_SUPPORTED;
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", usageSpec->padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t AesEcbCryptUpdate(void *cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    switch (padding) {
#ifdef HKS_SUPPORT_AES_ECB_NOPADDING
        case HKS_PADDING_NONE:
            return AesEcbNoPaddingCryptUpdate(cryptoCtx, message, cipherText);
#endif
        case HKS_PADDING_PKCS7:
            return HKS_ERROR_NOT_SUPPORTED;
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t AesEcbCryptFinal(void **cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText)
{
    switch (padding) {
#ifdef HKS_SUPPORT_AES_ECB_NOPADDING
        case HKS_PADDING_NONE:
            return AesEcbNoPaddingCryptFinal(cryptoCtx, message, cipherText);
#endif
        case HKS_PADDING_PKCS7:
            return HKS_ERROR_NOT_SUPPORTED;
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}
#endif

static int32_t CheckKeySize(const struct HksBlob *key)
{
    if ((key->size != HKS_KEY_BYTES(HKS_AES_KEY_SIZE_128)) && (key->size != HKS_KEY_BYTES(HKS_AES_KEY_SIZE_192)) &&
        (key->size != HKS_KEY_BYTES(HKS_AES_KEY_SIZE_256))) {
        return HKS_ERROR_INVALID_KEY_SIZE;
    }

    return HKS_SUCCESS;
}

int32_t HksMbedtlsAesEncrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText, struct HksBlob *tagAead)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckKeySize(key), HKS_ERROR_INVALID_KEY_SIZE,
        "Invalid aes keySiz = 0x%" LOG_PUBLIC "X", key->size)

    switch (usageSpec->mode) {
#if defined(HKS_SUPPORT_AES_CBC_NOPADDING) || defined(HKS_SUPPORT_AES_CBC_PKCS7)
        case HKS_MODE_CBC:
            return AesCbcCrypt(key, usageSpec, message, true, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_GCM
        case HKS_MODE_GCM:
            return AesEncryptGcm(key, usageSpec, message, cipherText, tagAead);
#endif
#ifdef HKS_SUPPORT_AES_CCM
        case HKS_MODE_CCM:
            return AesEncryptCcm(key, usageSpec, message, cipherText, tagAead);
#endif
#ifdef HKS_SUPPORT_AES_CTR_NOPADDING
        case HKS_MODE_CTR:
            return AesCtrCrypt(key, usageSpec, message, true, cipherText);
#endif
#if defined(HKS_SUPPORT_AES_ECB_NOPADDING) || defined(HKS_SUPPORT_AES_ECB_PKCS7PADDING)
        case HKS_MODE_ECB:
            return AesEcbCrypt(key, usageSpec, message, true, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", usageSpec->mode);
            return HKS_ERROR_NOT_SUPPORTED;
    }
}

int32_t HksMbedtlsAesEncryptInit(void** cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec)
{
    if (CheckKeySize(key) != HKS_SUCCESS || cryptoCtx == NULL || usageSpec == NULL) {
        HKS_LOG_E("Invalid aes keySiz = 0x%" LOG_PUBLIC "X", key->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    switch (usageSpec->mode) {
#if defined(HKS_SUPPORT_AES_CBC_NOPADDING) || defined(HKS_SUPPORT_AES_CBC_PKCS7)
        case HKS_MODE_CBC:
            return AesCbcCryptInit(cryptoCtx, key, usageSpec, true);
#endif
#ifdef HKS_SUPPORT_AES_GCM
        case HKS_MODE_GCM:
            return AesEncryptGcmInit(cryptoCtx, usageSpec, key);
#endif
#ifdef HKS_SUPPORT_AES_CCM
        case HKS_MODE_CCM:
            return HKS_ERROR_INVALID_ARGUMENT;
#endif
#ifdef HKS_SUPPORT_AES_CTR_NOPADDING
        case HKS_MODE_CTR:
            return AesCtrCryptInit(cryptoCtx, usageSpec, key, true);
#endif
#if defined(HKS_SUPPORT_AES_ECB_NOPADDING) || defined(HKS_SUPPORT_AES_ECB_PKCS7PADDING)
        case HKS_MODE_ECB:
            return AesEcbCryptInit(cryptoCtx, usageSpec, key, true);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", usageSpec->mode);
            return HKS_ERROR_NOT_SUPPORTED;
    }
}

int32_t HksMbedtlsAesEncryptUpdate(void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    HKS_IF_NULL_LOGE_RETURN(cryptoCtx, HKS_ERROR_INVALID_ARGUMENT, "Mbedtls AES encrypt update param is null")

    struct HksMbedtlsAesCtx *aesEncryptCtx = (struct HksMbedtlsAesCtx *)cryptoCtx;

    switch (aesEncryptCtx->mode) {
#if defined(HKS_SUPPORT_AES_CBC_NOPADDING) || defined(HKS_SUPPORT_AES_CBC_PKCS7)
        case HKS_MODE_CBC:
            return AesCbcCryptUpdate(cryptoCtx, aesEncryptCtx->padding, message, true, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_GCM
        case HKS_MODE_GCM:
            return AesEncryptGcmUpdate(cryptoCtx, aesEncryptCtx->padding, message, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_CCM
        case HKS_MODE_CCM:
            return HKS_ERROR_INVALID_ARGUMENT;
#endif
#ifdef HKS_SUPPORT_AES_CTR_NOPADDING
        case HKS_MODE_CTR:
            return AesCtrCryptUpdate(cryptoCtx, message, cipherText);
#endif
#if defined(HKS_SUPPORT_AES_ECB_NOPADDING) || defined(HKS_SUPPORT_AES_ECB_PKCS7PADDING)
        case HKS_MODE_ECB:
            return AesEcbCryptUpdate(cryptoCtx, aesEncryptCtx->padding, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", aesEncryptCtx->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtlsAesEncryptFinal(void** cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText,
    struct HksBlob *tagAead)
{
    struct HksMbedtlsAesCtx *aesEncryptCtx = (struct HksMbedtlsAesCtx *)*cryptoCtx;

    switch (aesEncryptCtx->mode) {
#if defined(HKS_SUPPORT_AES_CBC_NOPADDING) || defined(HKS_SUPPORT_AES_CBC_PKCS7)
        case HKS_MODE_CBC:
            return AesCbcCryptFinal(cryptoCtx, aesEncryptCtx->padding, message, true, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_GCM
        case HKS_MODE_GCM:
            return AesEncryptGcmFinal(cryptoCtx, message, cipherText, tagAead);
#endif
#ifdef HKS_SUPPORT_AES_CCM
        case HKS_MODE_CCM:
            return HKS_ERROR_INVALID_ARGUMENT;
#endif
#ifdef HKS_SUPPORT_AES_CTR_NOPADDING
        case HKS_MODE_CTR:
            return AesCtrCryptFinal(cryptoCtx, message, cipherText);
#endif
#if defined(HKS_SUPPORT_AES_ECB_NOPADDING) || defined(HKS_SUPPORT_AES_ECB_PKCS7PADDING)
        case HKS_MODE_ECB:
            return AesEcbCryptFinal(cryptoCtx, aesEncryptCtx->padding, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", aesEncryptCtx->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtlsAesDecrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckKeySize(key), HKS_ERROR_INVALID_KEY_SIZE,
        "Invalid aes keySize = 0x%" LOG_PUBLIC "X", key->size)

    switch (usageSpec->mode) {
#if defined(HKS_SUPPORT_AES_CBC_NOPADDING) || defined(HKS_SUPPORT_AES_CBC_PKCS7)
        case HKS_MODE_CBC:
            return AesCbcCrypt(key, usageSpec, message, false, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_GCM
        case HKS_MODE_GCM:
            return AesDecryptGcm(key, usageSpec, message, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_CCM
        case HKS_MODE_CCM:
            return AesDecryptCcm(key, usageSpec, message, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_CTR_NOPADDING
        case HKS_MODE_CTR:
            return AesCtrCrypt(key, usageSpec, message, false, cipherText);
#endif
#if defined(HKS_SUPPORT_AES_ECB_NOPADDING) || defined(HKS_SUPPORT_AES_ECB_PKCS7PADDING)
        case HKS_MODE_ECB:
            return AesEcbCrypt(key, usageSpec, message, false, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", usageSpec->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtlsAesDecryptInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckKeySize(key), HKS_ERROR_INVALID_ARGUMENT,
        "Invalid aes keySize = 0x%" LOG_PUBLIC "X", key->size)

    switch (usageSpec->mode) {
#if defined(HKS_SUPPORT_AES_CBC_NOPADDING) || defined(HKS_SUPPORT_AES_CBC_PKCS7)
        case HKS_MODE_CBC:
            return AesCbcCryptInit(cryptoCtx, key, usageSpec, false);
#endif
#ifdef HKS_SUPPORT_AES_GCM
        case HKS_MODE_GCM:
            return AesDecryptGcmInit(cryptoCtx, key, usageSpec);
#endif
#ifdef HKS_SUPPORT_AES_CCM
        case HKS_MODE_CCM:
            return HKS_ERROR_INVALID_ARGUMENT;
#endif
#ifdef HKS_SUPPORT_AES_CTR_NOPADDING
        case HKS_MODE_CTR:
            return AesCtrCryptInit(cryptoCtx, usageSpec, key, false);
#endif
#if defined(HKS_SUPPORT_AES_ECB_NOPADDING) || defined(HKS_SUPPORT_AES_ECB_PKCS7PADDING)
        case HKS_MODE_ECB:
            return AesEcbCryptInit(cryptoCtx, usageSpec, key, false);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", usageSpec->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtlsAesDecryptUpdate(void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    struct HksMbedtlsAesCtx *aesDecryptCtx = (struct HksMbedtlsAesCtx *)cryptoCtx;
    switch (aesDecryptCtx->mode) {
#if defined(HKS_SUPPORT_AES_CBC_NOPADDING) || defined(HKS_SUPPORT_AES_CBC_PKCS7)
        case HKS_MODE_CBC:
            return AesCbcCryptUpdate(cryptoCtx, aesDecryptCtx->padding, message, false, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_GCM
        case HKS_MODE_GCM:
            return AesDecryptGcmUpdate(cryptoCtx, message, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_CCM
        case HKS_MODE_CCM:
            return HKS_ERROR_INVALID_ARGUMENT;
#endif
#ifdef HKS_SUPPORT_AES_CTR_NOPADDING
        case HKS_MODE_CTR:
            return AesCtrCryptUpdate(cryptoCtx, message,  cipherText);
#endif
#if defined(HKS_SUPPORT_AES_ECB_NOPADDING) || defined(HKS_SUPPORT_AES_ECB_PKCS7PADDING)
        case HKS_MODE_ECB:
            return AesEcbCryptUpdate(cryptoCtx, aesDecryptCtx->padding, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", aesDecryptCtx->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtlsAesDecryptFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText,
    struct HksBlob *tagAead)
{
    struct HksMbedtlsAesCtx *aesDecryptCtx = (struct HksMbedtlsAesCtx *)*cryptoCtx;

    switch (aesDecryptCtx->mode) {
#if defined(HKS_SUPPORT_AES_CBC_NOPADDING) || defined(HKS_SUPPORT_AES_CBC_PKCS7)
        case HKS_MODE_CBC:
            return AesCbcCryptFinal(cryptoCtx, aesDecryptCtx->padding, message, false, cipherText);
#endif
#ifdef HKS_SUPPORT_AES_GCM
        case HKS_MODE_GCM:
            return AesDecryptGcmFinal(cryptoCtx, message, cipherText, tagAead);
#endif
#ifdef HKS_SUPPORT_AES_CCM
        case HKS_MODE_CCM:
            return HKS_ERROR_INVALID_ARGUMENT;
#endif
#ifdef HKS_SUPPORT_AES_CTR_NOPADDING
        case HKS_MODE_CTR:
            return AesCtrCryptFinal(cryptoCtx, message, cipherText);
#endif
#if defined(HKS_SUPPORT_AES_ECB_NOPADDING) || defined(HKS_SUPPORT_AES_ECB_PKCS7PADDING)
        case HKS_MODE_ECB:
            return AesEcbCryptFinal(cryptoCtx, aesDecryptCtx->padding, message, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", aesDecryptCtx->mode);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

int32_t HksMbedtlsAesCryptoInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const bool encrypt)
{
    if (encrypt) {
        return HksMbedtlsAesEncryptInit(cryptoCtx, key, usageSpec);
    } else {
        return HksMbedtlsAesDecryptInit(cryptoCtx, key, usageSpec);
    }
}

int32_t HksMbedtlsAesCryptoUpdate(void *cryptoCtx, const struct HksBlob *message,
    struct HksBlob *cipherText, const bool encrypt)
{
    if (encrypt) {
        return HksMbedtlsAesEncryptUpdate(cryptoCtx, message, cipherText);
    } else {
        return HksMbedtlsAesDecryptUpdate(cryptoCtx, message, cipherText);
    }
}

int32_t HksMbedtlsAesCryptoFinal(void **cryptoCtx, const struct HksBlob *message,
    struct HksBlob *cipherText, struct HksBlob *tagAead, const bool encrypt)
{
    if (encrypt) {
        return HksMbedtlsAesEncryptFinal(cryptoCtx, message, cipherText, tagAead);
    } else {
        return HksMbedtlsAesDecryptFinal(cryptoCtx, message, cipherText, tagAead);
    }
}

#if defined(HKS_SUPPORT_AES_CBC_NOPADDING) || defined(HKS_SUPPORT_AES_CBC_PKCS7)
void HksMbedtlsAesHalModecbcFreeCtx(void **cryptCtx)
{
    if (cryptCtx == NULL || *cryptCtx == NULL) {
        HKS_LOG_E("FreeCtx cryptCtx param is null");
        return;
    }

    struct HksMbedtlsAesCtx *mbedtlsAesCtx = (struct HksMbedtlsAesCtx *)*cryptCtx;
    if (mbedtlsAesCtx->padding == HKS_PADDING_NONE) {
        if (mbedtlsAesCtx->append != NULL) {
            mbedtls_aes_free((mbedtls_aes_context *)(mbedtlsAesCtx->append));
            HKS_FREE(mbedtlsAesCtx->append);
        }
    } else if (mbedtlsAesCtx->padding == HKS_PADDING_PKCS7) {
        if (mbedtlsAesCtx->append != NULL) {
            mbedtls_cipher_free((mbedtls_cipher_context_t *)mbedtlsAesCtx->append);
            HKS_FREE(mbedtlsAesCtx->append);
        }
    }
}
#endif
#ifdef HKS_SUPPORT_AES_GCM
void HksMbedtlsAesHalModegcmFreeCtx(void **cryptCtx)
{
    if (cryptCtx == NULL || *cryptCtx == NULL) {
        HKS_LOG_E("FreeCtx cryptCtx param is null");
        return;
    }

    struct HksMbedtlsAesCtx *mbedtlsAesCtx = (struct HksMbedtlsAesCtx *)*cryptCtx;
    if (mbedtlsAesCtx->append != NULL) {
        mbedtls_gcm_free((mbedtls_gcm_context *)mbedtlsAesCtx->append);
        HKS_FREE(mbedtlsAesCtx->append);
    }
}
#endif

#ifdef HKS_SUPPORT_AES_CTR_NOPADDING
void HksMbedtlsAesHalModectrFreeCtx(void **cryptCtx)
{
    if (cryptCtx == NULL || *cryptCtx == NULL) {
        HKS_LOG_E("FreeCtx cryptCtx param is null");
        return;
    }

    struct HksMbedtlsAesCtx *mbedtlsAesCtx = (struct HksMbedtlsAesCtx *)*cryptCtx;
    if (mbedtlsAesCtx->append != NULL) {
        mbedtls_cipher_free((mbedtls_cipher_context_t *)mbedtlsAesCtx->append);
        HKS_FREE(mbedtlsAesCtx->append);
    }
}
#endif

#if defined(HKS_SUPPORT_AES_ECB_NOPADDING) || defined(HKS_SUPPORT_AES_ECB_PKCS7PADDING)
void HksMbedtlsAesHalModeecbFreeCtx(void **cryptCtx)
{
    if (cryptCtx == NULL || *cryptCtx == NULL) {
        HKS_LOG_E("FreeCtx cryptCtx param is null");
        return;
    }

    struct HksMbedtlsAesCtx *mbedtlsAesCtx = (struct HksMbedtlsAesCtx *)*cryptCtx;
    if (mbedtlsAesCtx->padding == HKS_PADDING_NONE) {
        if (mbedtlsAesCtx->append != NULL) {
            mbedtls_cipher_free((mbedtls_cipher_context_t *)mbedtlsAesCtx->append);
            HKS_FREE(mbedtlsAesCtx->append);
        }
    }
}
#endif

void HksMbedtlsAesHalFreeCtx(void **cryptCtx)
{
    if (cryptCtx == NULL || *cryptCtx == NULL) {
        HKS_LOG_E("FreeCtx param context null");
        return;
    }

    struct HksMbedtlsAesCtx *mbedtlsAesCtx = (struct HksMbedtlsAesCtx *)*cryptCtx;
    switch (mbedtlsAesCtx->mode) {
#if defined(HKS_SUPPORT_AES_CBC_NOPADDING) || defined(HKS_SUPPORT_AES_CBC_PKCS7)
        case HKS_MODE_CBC:
            HksMbedtlsAesHalModecbcFreeCtx(cryptCtx);
            break;
#endif
#ifdef HKS_SUPPORT_AES_GCM
        case HKS_MODE_GCM:
            HksMbedtlsAesHalModegcmFreeCtx(cryptCtx);
            break;
#endif
#ifdef HKS_SUPPORT_AES_CCM
        case HKS_MODE_CCM:
            break;
#endif
#ifdef HKS_SUPPORT_AES_CTR_NOPADDING
        case HKS_MODE_CTR:
            HksMbedtlsAesHalModectrFreeCtx(cryptCtx);
            break;
#endif
#if defined(HKS_SUPPORT_AES_ECB_NOPADDING) || defined(HKS_SUPPORT_AES_ECB_PKCS7PADDING)
        case HKS_MODE_ECB:
            HksMbedtlsAesHalModeecbFreeCtx(cryptCtx);
            break;
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", mbedtlsAesCtx->mode);
            break;
    }

    HKS_FREE(*cryptCtx);
}
#endif /* HKS_SUPPORT_AES_C */
