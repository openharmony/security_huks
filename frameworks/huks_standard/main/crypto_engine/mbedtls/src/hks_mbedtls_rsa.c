/*
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
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

#ifdef _CUT_AUTHENTICATE_
#undef HKS_SUPPORT_RSA_C
#endif

#ifdef HKS_SUPPORT_RSA_C

#include "hks_mbedtls_rsa.h"

#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/rsa.h>

#include "hks_log.h"
#include "hks_mbedtls_common.h"
#include "hks_mem.h"

#define HKS_RSA_PUBLIC_EXPONENT 65537
#define HKS_RSA_KEYPAIR_CNT 3

#define DATA_SIZE_MAX (1 * 1024 * 1024) // 1M

struct HksMbedtlslRsaCtx {
    struct HksBlob rsaMessageTotal;
    mbedtls_ctr_drbg_context *mCtrDrbg;
    mbedtls_entropy_context *mEntropy;
    struct HksBlob mKey;
    uint8_t *append;
} HksMbedtlslRsaCtx;

static int32_t RsaCheckKeySize(const uint32_t keySize)
{
    switch (keySize) {
        case HKS_RSA_KEY_SIZE_512:
        case HKS_RSA_KEY_SIZE_768:
        case HKS_RSA_KEY_SIZE_1024:
        case HKS_RSA_KEY_SIZE_2048:
        case HKS_RSA_KEY_SIZE_3072:
        case HKS_RSA_KEY_SIZE_4096:
            break;
        default:
            HKS_LOG_E("Invalid rsa key size! keySize = 0x%X", keySize);
            return HKS_ERROR_INVALID_KEY_SIZE;
    }

    return HKS_SUCCESS;
}

static int32_t RsaKeyMaterialNedSizeCheck(const struct KeyMaterialRsa *keyMaterial)
{
    const uint32_t maxKeyByteLen = HKS_RSA_KEY_SIZE_4096 / HKS_BITS_PER_BYTE;
    if ((keyMaterial->nSize > maxKeyByteLen) || (keyMaterial->eSize > maxKeyByteLen) ||
        (keyMaterial->dSize > maxKeyByteLen)) {
        HKS_LOG_E("Invalid rsa keyMaterial! nSize = 0x%X, eSize = 0x%X, dSize = 0x%X",
            keyMaterial->nSize,
            keyMaterial->eSize,
            keyMaterial->dSize);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

static int32_t RsaKeyCheck(const struct HksBlob *key)
{
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(key->data);

    int32_t ret = RsaCheckKeySize(keyMaterial->keySize);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = RsaKeyMaterialNedSizeCheck(keyMaterial);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    if (key->size < (sizeof(struct KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize + keyMaterial->dSize)) {
        HKS_LOG_E("Rsa key size too small! key size = 0x%X", key->size);
        return HKS_ERROR_INVALID_KEY_INFO;
    }

    return HKS_SUCCESS;
}

#ifdef HKS_SUPPORT_RSA_GENERATE_KEY
static int32_t RsaSaveKeyMaterial(const mbedtls_rsa_context *ctx, const uint32_t keySize, struct HksBlob *key)
{
    const uint32_t keyByteLen = keySize / HKS_BITS_PER_BYTE;
    const uint32_t rawMaterialLen = sizeof(struct KeyMaterialRsa) + keyByteLen * HKS_RSA_KEYPAIR_CNT;
    uint8_t *rawMaterial = (uint8_t *)HksMalloc(rawMaterialLen);
    if (rawMaterial == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(rawMaterial, rawMaterialLen, 0, rawMaterialLen);

    /* RSA key data internal struct: struct KeyMaterialRsa + nData + eData + dData */
    struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)rawMaterial;
    keyMaterial->keyAlg = HKS_ALG_RSA;
    keyMaterial->keySize = keySize;
    keyMaterial->nSize = keyByteLen;
    keyMaterial->eSize = keyByteLen;
    keyMaterial->dSize = keyByteLen;

    int32_t ret;
    do {
        uint32_t offset = sizeof(*keyMaterial);
        ret = mbedtls_mpi_write_binary(&(ctx->N), rawMaterial + offset, keyMaterial->nSize);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Rsa save keyMaterial mpi write N failed! mbedtls ret = 0x%X", ret);
            break;
        }

        offset = offset + keyMaterial->nSize;
        ret = mbedtls_mpi_write_binary(&(ctx->E), rawMaterial + offset, keyMaterial->eSize);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Rsa save keyMaterial mpi write E failed! mbedtls ret = 0x%X", ret);
            break;
        }

        offset = offset + keyMaterial->eSize;
        ret = mbedtls_mpi_write_binary(&(ctx->D), rawMaterial + offset, keyMaterial->dSize);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Rsa save keyMaterial mpi write D failed! mbedtls ret = 0x%X", ret);
            break;
        }

        key->data = rawMaterial;
        key->size = rawMaterialLen;
    } while (0);

    if (ret != HKS_MBEDTLS_SUCCESS) {
        (void)memset_s(rawMaterial, rawMaterialLen, 0, rawMaterialLen);
        HKS_FREE_PTR(rawMaterial);
        ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    return ret;
}

int32_t HksMbedtlsRsaGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    mbedtls_rsa_context ctx;
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    ctx.padding = 0;
    ctx.hash_id = 0;

    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_entropy_context entropy;
    int32_t ret = HksCtrDrbgSeed(&ctrDrbg, &entropy);
    if (ret != HKS_SUCCESS) {
        mbedtls_rsa_free(&ctx);
        return ret;
    }

    do {
        ret = mbedtls_rsa_gen_key(&ctx, mbedtls_ctr_drbg_random, &ctrDrbg, spec->keyLen, HKS_RSA_PUBLIC_EXPONENT);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls rsa generate key failed! mbedtls ret = 0x%X", ret);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        ret = RsaSaveKeyMaterial(&ctx, spec->keyLen, key);
    } while (0);

    mbedtls_rsa_free(&ctx);
    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}
#endif /* HKS_SUPPORT_RSA_GENERATE_KEY */

#if defined(HKS_SUPPORT_RSA_CRYPT) || defined(HKS_SUPPORT_RSA_SIGN_VERIFY)
static int32_t RsaKeyMaterialToCtx(const struct HksBlob *key, const bool needPrivateExponent, mbedtls_rsa_context *ctx)
{
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(key->data);

    mbedtls_mpi n;
    mbedtls_mpi e;
    mbedtls_mpi d;

    mbedtls_mpi_init(&n);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&d);

    int32_t ret;
    do {
        uint32_t offset = sizeof(*keyMaterial);
        ret = mbedtls_mpi_read_binary(&n, key->data + offset, keyMaterial->nSize);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls rsa keyMaterial to ctx read N failed! mbedtls ret = 0x%X", ret);
            break;
        }

        offset = offset + keyMaterial->nSize;
        ret = mbedtls_mpi_read_binary(&e, key->data + offset, keyMaterial->eSize);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls rsa keyMaterial to ctx read E failed! mbedtls ret = 0x%X", ret);
            break;
        }

        if (needPrivateExponent) {
            offset = offset + keyMaterial->eSize;
            ret = mbedtls_mpi_read_binary(&d, key->data + offset, keyMaterial->dSize);
            if (ret != HKS_MBEDTLS_SUCCESS) {
                HKS_LOG_E("Mbedtls rsa keyMaterial to ctx read D failed! mbedtls ret = 0x%X", ret);
                break;
            }
        }

        ret = mbedtls_rsa_import(ctx, &n, NULL, NULL, (needPrivateExponent ? &d : NULL), &e);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls rsa keyMaterial to ctx import failed! mbedtls ret = 0x%X", ret);
            break;
        }

        ret = mbedtls_rsa_complete(ctx);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls rsa keyMaterial to ctx complete failed! mbedtls ret = 0x%X", ret);
        }
    } while (0);

    mbedtls_mpi_free(&n);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&d);

    if (ret != HKS_MBEDTLS_SUCCESS) {
        ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return ret;
}
#endif /* HKS_SUPPORT_RSA_CRYPT or HKS_SUPPORT_RSA_SIGN_VERIFY */

#ifdef HKS_SUPPORT_RSA_CRYPT
static int32_t HksToMbedtlsPadding(uint32_t hksPadding, int32_t *padding)
{
    switch (hksPadding) {
        case HKS_PADDING_PKCS1_V1_5:
            *padding = MBEDTLS_RSA_PKCS_V15;
            break;
        case HKS_PADDING_OAEP:
            *padding = MBEDTLS_RSA_PKCS_V21;
            break;
        default:
            return HKS_ERROR_NOT_SUPPORTED;
    }
    return HKS_SUCCESS;
}

static int32_t HksMbedtlsRsaCrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    int32_t ret = RsaKeyCheck(key);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    int32_t padding;
    ret = HksToMbedtlsPadding(usageSpec->padding, &padding);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    uint32_t mbedtlsAlg;
    if (padding == MBEDTLS_RSA_PKCS_V21) {
        ret = HksToMbedtlsDigestAlg(usageSpec->digest, &mbedtlsAlg);
        if (ret != HKS_SUCCESS) {
            return ret;
        }
    }

    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_entropy_context entropy;
    ret = HksCtrDrbgSeed(&ctrDrbg, &entropy);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    mbedtls_rsa_context ctx;
    mbedtls_rsa_init(&ctx, padding, mbedtlsAlg); /* only support oaep padding */

    do {
        ret = RsaKeyMaterialToCtx(key, !encrypt, &ctx); /* encrypt don't need private exponent (d) */
        if (ret != HKS_SUCCESS) {
            break;
        }

        size_t outlen;
        if (encrypt) {
            ret = mbedtls_rsa_pkcs1_encrypt(&ctx, mbedtls_ctr_drbg_random,
                &ctrDrbg, MBEDTLS_RSA_PUBLIC, (size_t)message->size, message->data, cipherText->data);
            outlen = mbedtls_rsa_get_len(&ctx);
        } else {
            ret = mbedtls_rsa_pkcs1_decrypt(&ctx, mbedtls_ctr_drbg_random, &ctrDrbg, MBEDTLS_RSA_PRIVATE,
                &outlen, message->data, cipherText->data, (size_t)cipherText->size);
        }
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("Mbedtls rsa crypt failed! mbedtls ret = 0x%X", ret);
            (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        cipherText->size = (uint32_t)outlen;
    } while (0);

    mbedtls_rsa_free(&ctx);
    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

int32_t HksMbedtlsRsaEncrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText, struct HksBlob *tagAead)
{
    (void)tagAead;
    return HksMbedtlsRsaCrypt(key, usageSpec, message, true, cipherText);
}

int32_t HksMbedtlsRsaDecrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText)
{
    return HksMbedtlsRsaCrypt(key, usageSpec, message, false, cipherText);
}

int32_t HksMbedtlsRsaEncryptDecrypt(void *ctx, const struct HksBlob *message)
{
    if (ctx == NULL || message == NULL) {
        HKS_LOG_E("invalid argument");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    struct HksMbedtlslRsaCtx *rsaCtx = (struct HksMbedtlslRsaCtx *)ctx;
    struct HksBlob totalMessage = (struct HksBlob)rsaCtx->rsaMessageTotal;

    if (message->size == 0 || (message->size) > DATA_SIZE_MAX || (totalMessage.size) > DATA_SIZE_MAX) {
        HKS_LOG_E("invalid size");
        return HKS_FAILURE;
    }

    uint32_t len = totalMessage.size + message->size;
    if (len > DATA_SIZE_MAX) {
        HKS_LOG_E("invalid size");
        return HKS_FAILURE;
    }

    uint8_t *newTotalMessageData = (uint8_t *)HksMalloc(len);
    if (newTotalMessageData == NULL) {
        HKS_LOG_E("initialize newTotalMessageData failed");
        return HKS_ERROR_MALLOC_FAIL;
    }

    int ret;
    if (totalMessage.size > 0) {
        ret = memcpy_s(newTotalMessageData, totalMessage.size, totalMessage.data, totalMessage.size);
        if (ret) {
            HKS_LOG_E("memcpy_s fail, error code = %d", ret);
            HksFree(newTotalMessageData);
            return HKS_ERROR_MALLOC_FAIL;
        }
    }
    ret = memcpy_s((newTotalMessageData + totalMessage.size), message->size, message->data, message->size);
    if (ret != EOK) {
        HKS_LOG_E("memcpy_s fail, error code = %d", ret);
        HksFree(newTotalMessageData);
        return HKS_ERROR_MALLOC_FAIL;
    }

    if (totalMessage.data != NULL) {
        HksFree(totalMessage.data);
    }

    totalMessage.data = newTotalMessageData;
    totalMessage.size = len;
    rsaCtx->rsaMessageTotal = totalMessage;

    return HKS_SUCCESS;
}

static int32_t HksMbedtlsRsaInitCtx(mbedtls_ctr_drbg_context **ctrDrbg, mbedtls_entropy_context **entropy,
    mbedtls_rsa_context *context, const struct HksUsageSpec *usageSpec)
{
    *ctrDrbg = (mbedtls_ctr_drbg_context *)HksMalloc(sizeof(mbedtls_ctr_drbg_context));
    if (*ctrDrbg == NULL) {
        HKS_LOG_E("malloc fail");
        return HKS_ERROR_MALLOC_FAIL;
    }
    *entropy = (mbedtls_entropy_context *)HksMalloc(sizeof(mbedtls_entropy_context));
    if (*entropy == NULL) {
        HKS_LOG_E("malloc fail");
        HksFree(*ctrDrbg);
        return HKS_ERROR_MALLOC_FAIL;
    }
    int32_t ret = HksCtrDrbgSeed(*ctrDrbg, *entropy);
    if (ret != HKS_SUCCESS) {
        HksFree(*ctrDrbg);
        HksFree(*entropy);
    }
    int32_t padding = 0;
    ret = HksToMbedtlsPadding(usageSpec->padding, &padding);
    if (ret != HKS_SUCCESS) {
        HksFree(*ctrDrbg);
        HksFree(*entropy);
        return ret;
    }

    uint32_t mbedtlsAlg = 0;
    if (padding == MBEDTLS_RSA_PKCS_V21) {
        ret = HksToMbedtlsDigestAlg(usageSpec->digest, &mbedtlsAlg);
        if (ret != HKS_SUCCESS) {
            HksFree(*ctrDrbg);
            HksFree(*entropy);
            return ret;
        }
    }
    mbedtls_rsa_init(context, padding, mbedtlsAlg); /* only support oaep padding */
    return HKS_SUCCESS;
}

int32_t HksMbedtlsRsaCryptInit(void **ctx, const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const bool encrypt)
{
    int32_t ret = RsaKeyCheck(key);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    mbedtls_rsa_context *context = (mbedtls_rsa_context *)HksMalloc(sizeof(mbedtls_rsa_context));
    if (context == NULL) {
        HKS_LOG_E("malloc fail");
        return HKS_ERROR_MALLOC_FAIL;
    }

    mbedtls_ctr_drbg_context *ctrDrbg = NULL;
    mbedtls_entropy_context *entropy = NULL;
    ret = HksMbedtlsRsaInitCtx(&ctrDrbg, &entropy, context, usageSpec);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InitCtx fail, ret = %d", ret);
        HksFree(context);
        return ret;
    }

    struct HksMbedtlslRsaCtx *outCtx = (struct HksMbedtlslRsaCtx *)HksMalloc(sizeof(HksMbedtlslRsaCtx));
    if (outCtx == NULL) {
        HKS_LOG_E("initialize outCtx fail");
        HksFree(ctrDrbg);
        HksFree(entropy);
        HksFree(context);
        return HKS_ERROR_MALLOC_FAIL;
    }

    outCtx->mKey.size = key->size;
    outCtx->mKey.data = (uint8_t *)HksMalloc(key->size);
    if (outCtx->mKey.data == NULL) {
        HKS_LOG_E("malloc fail");
        HksFree(ctrDrbg);
        HksFree(entropy);
        HksFree(context);
        HksFree(outCtx);
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(outCtx->mKey.data, key->size, key->data, key->size);
    outCtx->rsaMessageTotal.data = NULL;
    outCtx->rsaMessageTotal.size = 0;
    outCtx->mCtrDrbg = ctrDrbg;
    outCtx->mEntropy = entropy;
    outCtx->append = (void *)context;
    *ctx = (void *)outCtx;

    return HKS_SUCCESS;
}

static void HksMbedtlsRsaCryptFree(mbedtls_rsa_context *context, struct HksMbedtlslRsaCtx *rsaCtx)
{
    if (rsaCtx != NULL) {
        if (rsaCtx->append != NULL) {
            mbedtls_rsa_free(context);
            rsaCtx->append = NULL;
        }

        if (rsaCtx->mCtrDrbg != NULL) {
            mbedtls_ctr_drbg_free(rsaCtx->mCtrDrbg);
            HksFree(rsaCtx->mCtrDrbg);
            rsaCtx->mCtrDrbg = NULL;
        }

        if (rsaCtx->mEntropy != NULL) {
            mbedtls_entropy_free(rsaCtx->mEntropy);
            HksFree(rsaCtx->mEntropy);
            rsaCtx->mEntropy = NULL;
        }

        if (rsaCtx->rsaMessageTotal.data != NULL) {
            HksFree(rsaCtx->rsaMessageTotal.data);
            rsaCtx->rsaMessageTotal.data = NULL;
        }

        if (rsaCtx->mKey.data != NULL) {
            HksFree(rsaCtx->mKey.data);
            rsaCtx->mKey.data = NULL;
        }
        HKS_FREE_PTR(rsaCtx);
    }
}

int32_t HksMbedtlsRsaCryptUpdate(void *ctx, const struct HksBlob *message, struct HksBlob *out, const bool encrypt)
{
    out->size = 0;
    int32_t ret = HksMbedtlsRsaEncryptDecrypt(ctx, message);

    struct HksMbedtlslRsaCtx *rsaCtx = (struct HksMbedtlslRsaCtx *)ctx;
    mbedtls_rsa_context *context = (mbedtls_rsa_context *)(rsaCtx->append);

    if (ret != HKS_SUCCESS) {
        HksMbedtlsRsaCryptFree(context, rsaCtx);
    }
    return ret;
}

static int32_t HksMbedtlsRsaCryptFinalCheckParam(void **ctx, const struct HksBlob *message, struct HksBlob *cipherText)
{
    if (ctx == NULL) {
        HKS_LOG_E("invalid argument ctx");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    struct HksMbedtlslRsaCtx *rsaCtx = (struct HksMbedtlslRsaCtx *)*ctx;
    if (rsaCtx == NULL) {
        HKS_LOG_E("rsaCtx or rsaMessageTotal invalid");
        return HKS_FAILURE;
    }

    mbedtls_rsa_context *context = (mbedtls_rsa_context *)rsaCtx->append;
    if (context == NULL) {
        HKS_LOG_E("context is null");
        HksFree(rsaCtx);
        *ctx = NULL;
        return HKS_FAILURE;
    }

    if (message == NULL || cipherText == NULL) {
        HKS_LOG_E("invalid argument message or cipherText");
        HksMbedtlsRsaCryptFree(context, rsaCtx);
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    return HKS_SUCCESS;
}

int32_t HksMbedtlsRsaCryptFinal(void **ctx, const struct HksBlob *message, struct HksBlob *cipherText,
    struct HksBlob *tagAead, const bool encrypt)
{
    (void)tagAead;
    int32_t ret = HksMbedtlsRsaCryptFinalCheckParam(ctx, message, cipherText);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    struct HksMbedtlslRsaCtx *rsaCtx = (struct HksMbedtlslRsaCtx *)*ctx;
    mbedtls_rsa_context *context = (mbedtls_rsa_context *)rsaCtx->append;

    size_t outlen;
    if (message->size != 0) {
        ret = HksMbedtlsRsaEncryptDecrypt((void *)*ctx, message);
        if (ret != HKS_SUCCESS) {
            HksMbedtlsRsaCryptFree(context, rsaCtx);
            return ret;
        }
    }
    ret = RsaKeyMaterialToCtx(&rsaCtx->mKey, !encrypt, context); /* encrypt don't need private exponent (d) */
    if (ret != HKS_SUCCESS) {
        HksMbedtlsRsaCryptFree(context, rsaCtx);
        HKS_LOG_E("rsaKey material to ctx fail");
        return ret;
    }
    if (encrypt) {
        ret = mbedtls_rsa_pkcs1_encrypt(context, mbedtls_ctr_drbg_random, rsaCtx->mCtrDrbg, MBEDTLS_RSA_PUBLIC,
            (size_t)rsaCtx->rsaMessageTotal.size, rsaCtx->rsaMessageTotal.data, cipherText->data);
        outlen = mbedtls_rsa_get_len(context);
    } else {
        ret = mbedtls_rsa_pkcs1_decrypt(context, mbedtls_ctr_drbg_random, rsaCtx->mCtrDrbg, MBEDTLS_RSA_PRIVATE,
            &outlen, rsaCtx->rsaMessageTotal.data, cipherText->data, (size_t)cipherText->size);
    }
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Mbedtls rsa crypt failed! mbedtls ret = 0x%X", ret);
        (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
        HksMbedtlsRsaCryptFree(context, rsaCtx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    cipherText->size = (uint32_t)outlen;

    HksMbedtlsRsaHalFreeCtx(ctx);
    return ret;
}
#endif /* HKS_SUPPORT_RSA_CRYPT */

#ifdef HKS_SUPPORT_RSA_SIGN_VERIFY
static int32_t HksToMbedtlsSignPadding(uint32_t hksPadding, int32_t *padding)
{
    switch (hksPadding) {
        case HKS_PADDING_PKCS1_V1_5:
            *padding = MBEDTLS_RSA_PKCS_V15;
            break;
        case HKS_PADDING_PSS:
            *padding = MBEDTLS_RSA_PKCS_V21;
            break;
        default:
            return HKS_ERROR_NOT_SUPPORTED;
    }
    return HKS_SUCCESS;
}

static int32_t HksMbedtlsRsaSignVerify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const bool sign, struct HksBlob *signature)
{
    uint32_t mbedtlsAlg;
    uint32_t digest = (usageSpec->digest == HKS_DIGEST_NONE) ? HKS_DIGEST_SHA256 : usageSpec->digest;
    int32_t ret = HksToMbedtlsDigestAlg(digest, &mbedtlsAlg);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    int32_t padding;
    ret = HksToMbedtlsSignPadding(usageSpec->padding, &padding);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_entropy_context entropy;
    ret = HksCtrDrbgSeed(&ctrDrbg, &entropy);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    mbedtls_rsa_context ctx;
    mbedtls_rsa_init(&ctx, padding, mbedtlsAlg);

    do {
        ret = RsaKeyMaterialToCtx(key, sign, &ctx); /* sign need private exponent (d) */
        if (ret != HKS_SUCCESS) {
            break;
        }

        if (sign) {
            ret = mbedtls_rsa_pkcs1_sign(&ctx, mbedtls_ctr_drbg_random, &ctrDrbg, MBEDTLS_RSA_PRIVATE,
                mbedtlsAlg, message->size, message->data, signature->data);
        } else {
            ret = mbedtls_rsa_pkcs1_verify(&ctx, mbedtls_ctr_drbg_random, &ctrDrbg, MBEDTLS_RSA_PUBLIC,
                mbedtlsAlg, message->size, message->data, signature->data);
        }
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls rsa sign/verify failed! mbedtls ret = 0x%X", ret);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            (void)memset_s(signature->data, signature->size, 0, signature->size);
        }
    } while (0);

    if (sign) {
        signature->size = mbedtls_rsa_get_len(&ctx);
    }

    mbedtls_rsa_free(&ctx);
    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

int32_t HksMbedtlsRsaSign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    int32_t ret = RsaKeyCheck(key);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    return HksMbedtlsRsaSignVerify(key, usageSpec, message, true, signature); /* true: is sign */
}

int32_t HksMbedtlsRsaVerify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    int32_t ret = RsaKeyCheck(key);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    return HksMbedtlsRsaSignVerify(key, usageSpec, message, false, (struct HksBlob *)signature); /* false: is verify */
}
#endif /* HKS_SUPPORT_RSA_SIGN_VERIFY */

#ifdef HKS_SUPPORT_RSA_GET_PUBLIC_KEY
static int32_t GetRsaPubKeyCheckParams(const struct HksBlob *keyIn, const struct HksBlob *keyOut)
{
    int32_t ret = RsaKeyCheck(keyIn);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    /* check keyOut size */
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(keyIn->data);
    if (keyOut->size < (sizeof(struct HksPubKeyInfo) + keyMaterial->nSize + keyMaterial->eSize)) {
        HKS_LOG_E("Rsa public keyOut size too small! keyOut size = 0x%X", keyOut->size);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    return HKS_SUCCESS;
}

int32_t HksMbedtlsGetRsaPubKey(const struct HksBlob *keyIn, struct HksBlob *keyOut)
{
    int32_t ret = GetRsaPubKeyCheckParams(keyIn, keyOut);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    /* n + e, so need size is: sizeof(struct HksPubKeyInfo) + nSize + eSize */
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(keyIn->data);
    const uint32_t outLen = sizeof(struct HksPubKeyInfo) + keyMaterial->nSize + keyMaterial->eSize;
    if (memcpy_s(keyOut->data, keyOut->size, (void *)keyMaterial, outLen) != EOK) {
        HKS_LOG_E("Memcpy rsa pub key failed!");
        (void)memset_s(keyOut->data, keyOut->size, 0, keyOut->size);
        return HKS_ERROR_BAD_STATE;
    }
    ((struct KeyMaterialRsa *)(keyOut->data))->dSize = 0;
    keyOut->size = outLen;

    return HKS_SUCCESS;
}
#endif /* HKS_SUPPORT_RSA_GET_PUBLIC_KEY */

void HksMbedtlsRsaHalFreeCtx(void **cryptCtx)
{
    if (cryptCtx == NULL || *cryptCtx == NULL) {
        HKS_LOG_E("Openssl hmac free ctx is null");
        return;
    }

    struct HksMbedtlslRsaCtx *mbedtlsRsaCtx = (struct HksMbedtlslRsaCtx *)*cryptCtx;

    if (mbedtlsRsaCtx->append != NULL) {
        mbedtls_rsa_free((mbedtls_rsa_context *)mbedtlsRsaCtx->append);
        if (mbedtlsRsaCtx->append != NULL) {
            HksFree(mbedtlsRsaCtx->append);
            mbedtlsRsaCtx->append = NULL;
        }
    }

    if (mbedtlsRsaCtx->mCtrDrbg != NULL) {
        mbedtls_ctr_drbg_free(mbedtlsRsaCtx->mCtrDrbg);
        if (mbedtlsRsaCtx->mCtrDrbg != NULL) {
            HksFree(mbedtlsRsaCtx->mCtrDrbg);
            mbedtlsRsaCtx->mCtrDrbg = NULL;
        }
    }

    if (mbedtlsRsaCtx->mEntropy != NULL) {
        mbedtls_entropy_free(mbedtlsRsaCtx->mEntropy);
        if (mbedtlsRsaCtx->mEntropy != NULL) {
            HksFree(mbedtlsRsaCtx->mEntropy);
            mbedtlsRsaCtx->mEntropy = NULL;
        }
    }

    if (mbedtlsRsaCtx->rsaMessageTotal.data != NULL) {
        HksFree(mbedtlsRsaCtx->rsaMessageTotal.data);
        mbedtlsRsaCtx->rsaMessageTotal.data = NULL;
    }

    if (mbedtlsRsaCtx->mKey.data != NULL) {
        HksFree(mbedtlsRsaCtx->mKey.data);
        mbedtlsRsaCtx->mKey.data = NULL;
    }

    if (*cryptCtx != NULL) {
        HksFree(*cryptCtx);
        *cryptCtx = NULL;
    }
}
#endif /* HKS_SUPPORT_RSA_C */
