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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#ifdef HKS_SUPPORT_DES_C

#include <openssl/des.h>
#include <openssl/evp.h>

#include "hks_cfi.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_openssl_des.h"
#include "hks_openssl_engine.h"
#include "hks_template.h"
#include "securec.h"

static int32_t CheckDesKeySize(const struct HksBlob *key)
{
    HKS_IF_TRUE_RETURN(key->size != HKS_KEY_BYTES(HKS_DES_KEY_SIZE_64), HKS_ERROR_INVALID_KEY_SIZE)
    return HKS_SUCCESS;
}

#ifdef HKS_SUPPORT_DES_GENERATE_KEY
int32_t HksOpensslDesGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    HKS_IF_TRUE_RETURN(spec->keyLen != HKS_DES_KEY_SIZE_64, HKS_ERROR_INVALID_KEY_SIZE)

    const uint32_t keyByteLen = spec->keyLen / HKS_BITS_PER_BYTE;
    uint8_t *outKey = (uint8_t *)HksMalloc(keyByteLen);
    HKS_IF_NULL_RETURN(outKey, HKS_ERROR_MALLOC_FAIL)

    DES_cblock desKey;
    if (DES_random_key(&desKey) != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("DES_random_key failed");
        HKS_FREE(outKey);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    (void)memcpy_s(outKey, keyByteLen, desKey, keyByteLen);
    key->data = outKey;
    key->size = keyByteLen;

    return HKS_SUCCESS;
}
#endif /* HKS_SUPPORT_DES_GENERATE_KEY */

ENABLE_CFI(const EVP_CIPHER *OpensslGetDesCipherType(uint32_t keySize, uint32_t mode))
{
    if (keySize == HKS_KEY_BYTES(HKS_DES_KEY_SIZE_64)) {
        switch (mode) {
            case HKS_MODE_CBC:
                return EVP_des_cbc();
            case HKS_MODE_ECB:
                return EVP_des_ecb();
            default:
                return NULL;
        }
    } else if (keySize == HKS_KEY_BYTES(HKS_3DES_KEY_SIZE_128)) {
        switch (mode) {
            case HKS_MODE_CBC:
                return EVP_des_ede_cbc();
            case HKS_MODE_ECB:
                return EVP_des_ede_ecb();
            default:
                return NULL;
        }
    } else if (keySize == HKS_KEY_BYTES(HKS_3DES_KEY_SIZE_192)) {
        switch (mode) {
            case HKS_MODE_CBC:
                return EVP_des_ede3_cbc();
            case HKS_MODE_ECB:
                return EVP_des_ede3_ecb();
            default:
                return NULL;
        }
    }
    return NULL;
}

static int32_t OpensslDesCipherInitParams(const struct HksBlob *key, EVP_CIPHER_CTX *ctx, bool isEncrypt,
    struct HksCipherParam *cipherParam)
{
    int32_t ret = isEncrypt
        ? EVP_EncryptInit_ex(ctx, NULL, NULL, key->data, (cipherParam == NULL) ? NULL : cipherParam->iv.data)
        : EVP_DecryptInit_ex(ctx, NULL, NULL, key->data, (cipherParam == NULL) ? NULL : cipherParam->iv.data);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = EVP_CIPHER_CTX_set_padding(ctx, OPENSSL_CTX_PADDING_NONE);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return HKS_SUCCESS;
}

static int32_t OpensslDesCipherInit(const struct HksBlob *key, const struct HksUsageSpec *usageSpec, bool isEncrypt,
    struct HksOpensslDesCtx *outCtx)
{
    int32_t ret;
    struct HksCipherParam *cipherParam = (struct HksCipherParam *)usageSpec->algParam;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    const EVP_CIPHER *cipher = OpensslGetDesCipherType(key->size, usageSpec->mode);
    if (cipher == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        return HKS_ERROR_INVALID_MODE;
    }

    ret = isEncrypt
        ? EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)
        : EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_CIPHER_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = OpensslDesCipherInitParams(key, ctx, isEncrypt, cipherParam);
    if (ret != HKS_SUCCESS) {
        EVP_CIPHER_CTX_free(ctx);
        HKS_LOG_E("OpensslBlockCipherCryptInitParams fail, ret = %" LOG_PUBLIC "d", ret);
        return ret;
    }
    outCtx->append = (void *)ctx;

    return HKS_SUCCESS;
}

int32_t DesNoPaddingCryptInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const bool encrypt)
{
    struct HksCipherParam *iv = (struct HksCipherParam *)(usageSpec->algParam);
    HKS_IF_TRUE_LOGE_RETURN(usageSpec->mode == HKS_MODE_CBC && iv->iv.size != HKS_DES_IV_SIZE, HKS_ERROR_INVALID_IV,
        "initialize iv fail")

    struct HksOpensslDesCtx *outCtx = (struct HksOpensslDesCtx *)HksMalloc(sizeof(struct HksOpensslDesCtx));
    HKS_IF_NULL_LOGE_RETURN(outCtx, HKS_ERROR_MALLOC_FAIL, "initialize outCtx fail")

    int32_t ret = OpensslDesCipherInit(key, usageSpec, encrypt, outCtx);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("openssl initialize des cipher fail");
        HKS_FREE(outCtx);
        return ret;
    }

    outCtx->mode = usageSpec->mode;
    outCtx->padding = usageSpec->padding;

    *cryptoCtx = (void *)outCtx;
    return HKS_SUCCESS;
}

int32_t DesNoPaddingCryptUpdate(void *cryptoCtx, const struct HksBlob *message, const bool encrypt,
    struct HksBlob *cipherText)
{
    struct HksOpensslDesCtx *desCtx = (struct HksOpensslDesCtx *)cryptoCtx;
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)desCtx->append;
    HKS_IF_NULL_RETURN(ctx, HKS_ERROR_NULL_POINTER)

    HKS_IF_TRUE_LOGE_RETURN(message->size % HKS_DES_BLOCK_SIZE != 0, HKS_ERROR_INVALID_ARGUMENT,
        "DesCbcNoPaddingCryptUpdate data size invalid!")

    int32_t outLen = 0;
    int evpRet = encrypt
        ? EVP_EncryptUpdate(ctx, cipherText->data, &outLen, message->data, message->size)
        : EVP_DecryptUpdate(ctx, cipherText->data, &outLen, message->data, message->size);
    if (evpRet != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    cipherText->size = (uint32_t)outLen;

    return HKS_SUCCESS;
}

int32_t DesNoPaddingCryptFinal(void **cryptoCtx, const struct HksBlob *message, const bool encrypt,
    struct HksBlob *cipherText)
{
    struct HksOpensslDesCtx *desCtx = (struct HksOpensslDesCtx *)*cryptoCtx;
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)desCtx->append;
    HKS_IF_NULL_RETURN(ctx, HKS_ERROR_NULL_POINTER)

    HKS_IF_TRUE_LOGE_RETURN(message->size % HKS_DES_BLOCK_SIZE != 0, HKS_ERROR_INVALID_ARGUMENT,
        "DesCbcNoPaddingCryptFinal data size invalid!")

    int32_t ret = HKS_SUCCESS;
    do {
        int32_t outLen = 0;
        int evpRet;
        if (message->size != 0) {
            evpRet = encrypt
                ? EVP_EncryptUpdate(ctx, cipherText->data, &outLen, message->data, message->size)
                : EVP_DecryptUpdate(ctx, cipherText->data, &outLen, message->data, message->size);
            if (evpRet != HKS_OPENSSL_SUCCESS) {
                HksLogOpensslError();
                ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
                break;
            }
        }
        cipherText->size = (uint32_t)outLen;
        evpRet = encrypt
            ? EVP_EncryptFinal_ex(ctx, (cipherText->data + outLen), &outLen)
            : EVP_DecryptFinal_ex(ctx, (cipherText->data + outLen), &outLen);
        if (evpRet != HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        cipherText->size += (uint32_t)outLen;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    desCtx->append = NULL;

    HksOpensslDesHalFreeCtx(cryptoCtx);
    return ret;
}

static int32_t DesCryptInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const bool encrypt)
{
    switch (usageSpec->padding) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING) || defined(HKS_SUPPORT_DES_ECB_NOPADDING)
        case HKS_PADDING_NONE:
            return DesNoPaddingCryptInit(cryptoCtx, key, usageSpec, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", usageSpec->padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t DesCryptUpdate(void *cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText, const bool encrypt)
{
    switch (padding) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING) || defined(HKS_SUPPORT_DES_ECB_NOPADDING)
        case HKS_PADDING_NONE:
            return DesNoPaddingCryptUpdate(cryptoCtx, message, encrypt, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t DesCryptFinal(void **cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText, const bool encrypt)
{
    switch (padding) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING) || defined(HKS_SUPPORT_DES_ECB_NOPADDING)
        case HKS_PADDING_NONE:
            return DesNoPaddingCryptFinal(cryptoCtx, message, encrypt, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

int32_t HksOpensslDesCryptoInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const bool encrypt)
{
    HKS_IF_TRUE_LOGE_RETURN(CheckDesKeySize(key) != HKS_SUCCESS || cryptoCtx == NULL || usageSpec == NULL,
        HKS_ERROR_INVALID_ARGUMENT, "Invalid des keySize = 0x%" LOG_PUBLIC "X", key->size)

    switch (usageSpec->mode) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return DesCryptInit(cryptoCtx, key, usageSpec, encrypt);
#endif
#if defined(HKS_SUPPORT_DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return DesCryptInit(cryptoCtx, key, usageSpec, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", usageSpec->mode);
            return HKS_ERROR_INVALID_MODE;
    }
}

int32_t HksOpensslDesCryptoUpdate(void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText,
    const bool encrypt)
{
    HKS_IF_NULL_LOGE_RETURN(cryptoCtx, HKS_ERROR_INVALID_ARGUMENT, "Openssl DES encrypt update param is null")
    struct HksOpensslDesCtx *desEncryptCtx = (struct HksOpensslDesCtx *)cryptoCtx;

    switch (desEncryptCtx->mode) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return DesCryptUpdate(cryptoCtx, desEncryptCtx->padding, message, cipherText, encrypt);
#endif
#if defined(HKS_SUPPORT_DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return DesCryptUpdate(cryptoCtx, desEncryptCtx->padding, message, cipherText, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", desEncryptCtx->mode);
            return HKS_ERROR_INVALID_MODE;
    }
}

int32_t HksOpensslDesCryptoFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText,
    struct HksBlob *tagAead, const bool encrypt)
{
    (void)tagAead;
    struct HksOpensslDesCtx *desEncryptCtx = (struct HksOpensslDesCtx *)*cryptoCtx;
    switch (desEncryptCtx->mode) {
#if defined(HKS_SUPPORT_DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return DesCryptFinal(cryptoCtx, desEncryptCtx->padding, message, cipherText, encrypt);
#endif
#if defined(HKS_SUPPORT_DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return DesCryptFinal(cryptoCtx, desEncryptCtx->padding, message, cipherText, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", desEncryptCtx->mode);
            return HKS_ERROR_INVALID_MODE;
    }
}

void HksOpensslDesHalFreeCtx(void **cryptCtx)
{
    HKS_IF_TRUE_LOGE_RETURN_VOID(cryptCtx == NULL || *cryptCtx == NULL, "FreeCtx param context null")
    HKS_FREE(*cryptCtx);
}
#endif /* HKS_SUPPORT_DES_C */
