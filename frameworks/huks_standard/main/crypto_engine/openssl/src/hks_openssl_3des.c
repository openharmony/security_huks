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

#ifdef HKS_SUPPORT_3DES_C

#include <openssl/des.h>
#include <openssl/evp.h>

#include "hks_cfi.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_openssl_3des.h"
#include "hks_openssl_des.h"
#include "hks_openssl_engine.h"
#include "hks_template.h"
#include "securec.h"

static int32_t Check3DesKeySize(const struct HksBlob *key)
{
    HKS_IF_TRUE_RETURN(key->size != HKS_KEY_BYTES(HKS_3DES_KEY_SIZE_128) &&
        key->size != HKS_KEY_BYTES(HKS_3DES_KEY_SIZE_192), HKS_ERROR_INVALID_KEY_SIZE)
    return HKS_SUCCESS;
}

#ifdef HKS_SUPPORT_3DES_GENERATE_KEY
int32_t HksOpenssl3DesGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    HKS_IF_TRUE_RETURN(spec->keyLen != HKS_3DES_KEY_SIZE_128 && spec->keyLen != HKS_3DES_KEY_SIZE_192,
        HKS_ERROR_INVALID_KEY_SIZE)

    const uint32_t keyByteLen = spec->keyLen / HKS_BITS_PER_BYTE;
    uint8_t *outKey = (uint8_t *)HksMalloc(keyByteLen);
    HKS_IF_NULL_RETURN(outKey, HKS_ERROR_MALLOC_FAIL)

    DES_cblock desKey;
    for (uint32_t i = 0; i < spec->keyLen / HKS_DES_KEY_SIZE_64; i++) {
        if (DES_random_key(&desKey) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("DES_random_key 3des key failed");
            HKS_FREE(outKey);
            return HKS_ERROR_CRYPTO_ENGINE_ERROR;
        }
        if (memcpy_s(outKey + i * HKS_DES_BLOCK_SIZE, keyByteLen - i * HKS_DES_BLOCK_SIZE, desKey,
            HKS_DES_BLOCK_SIZE) != EOK) {
            HKS_LOG_E("memcpy 3des key failed!");
            HKS_FREE(outKey);
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
    }

    key->data = outKey;
    key->size = keyByteLen;

    return HKS_SUCCESS;
}
#endif /* HKS_SUPPORT_3DES_GENERATE_KEY */

static int32_t Des3CryptInit(void **cryptoCtx, const struct HksBlob *key,
    const struct HksUsageSpec *usageSpec, const bool encrypt)
{
    switch (usageSpec->padding) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING) || defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_PADDING_NONE:
            return DesNoPaddingCryptInit(cryptoCtx, key, usageSpec, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", usageSpec->padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t Des3CryptUpdate(void *cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText, const bool encrypt)
{
    switch (padding) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING) || defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_PADDING_NONE:
            return DesNoPaddingCryptUpdate(cryptoCtx, message, encrypt, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

static int32_t Des3CryptFinal(void **cryptoCtx, const uint8_t padding, const struct HksBlob *message,
    struct HksBlob *cipherText, const bool encrypt)
{
    switch (padding) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING) || defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_PADDING_NONE:
            return DesNoPaddingCryptFinal(cryptoCtx, message, encrypt, cipherText);
#endif
        default:
            HKS_LOG_E("Unsupport padding! mode = 0x%" LOG_PUBLIC "X", padding);
            return HKS_ERROR_INVALID_PADDING;
    }
}

int32_t HksOpenssl3DesCryptoInit(void **cryptoCtx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const bool encrypt)
{
    HKS_IF_TRUE_LOGE_RETURN(Check3DesKeySize(key) != HKS_SUCCESS || cryptoCtx == NULL || usageSpec == NULL,
        HKS_ERROR_INVALID_ARGUMENT, "Invalid 3des keySize = 0x%" LOG_PUBLIC "X", key->size)

    switch (usageSpec->mode) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return Des3CryptInit(cryptoCtx, key, usageSpec, encrypt);
#endif
#if defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return Des3CryptInit(cryptoCtx, key, usageSpec, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", usageSpec->mode);
            return HKS_ERROR_INVALID_MODE;
    }
}

int32_t HksOpenssl3DesCryptoUpdate(void *cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText,
    const bool encrypt)
{
    HKS_IF_NULL_LOGE_RETURN(cryptoCtx, HKS_ERROR_INVALID_ARGUMENT, "Openssl 3DES encrypt update param is null")
    struct HksOpensslDesCtx *desEncryptCtx = (struct HksOpensslDesCtx *)cryptoCtx;

    switch (desEncryptCtx->mode) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return Des3CryptUpdate(cryptoCtx, desEncryptCtx->padding, message, cipherText, encrypt);
#endif
#if defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return Des3CryptUpdate(cryptoCtx, desEncryptCtx->padding, message, cipherText, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", desEncryptCtx->mode);
            return HKS_ERROR_INVALID_MODE;
    }
}

int32_t HksOpenssl3DesCryptoFinal(void **cryptoCtx, const struct HksBlob *message, struct HksBlob *cipherText,
    struct HksBlob *tagAead, const bool encrypt)
{
    (void)tagAead;
    struct HksOpensslDesCtx *desEncryptCtx = (struct HksOpensslDesCtx *)*cryptoCtx;
    switch (desEncryptCtx->mode) {
#if defined(HKS_SUPPORT_3DES_CBC_NOPADDING)
        case HKS_MODE_CBC:
            return Des3CryptFinal(cryptoCtx, desEncryptCtx->padding, message, cipherText, encrypt);
#endif
#if defined(HKS_SUPPORT_3DES_ECB_NOPADDING)
        case HKS_MODE_ECB:
            return Des3CryptFinal(cryptoCtx, desEncryptCtx->padding, message, cipherText, encrypt);
#endif
        default:
            HKS_LOG_E("Unsupport key alg! mode = 0x%" LOG_PUBLIC "X", desEncryptCtx->mode);
            return HKS_ERROR_INVALID_MODE;
    }
}

void HksOpenssl3DesHalFreeCtx(void **cryptCtx)
{
    HKS_IF_TRUE_LOGE_RETURN_VOID(cryptCtx == NULL || *cryptCtx == NULL, "FreeCtx param context null")
    HKS_FREE(*cryptCtx);
}
#endif /* HKS_SUPPORT_3DES_C */
