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
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

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
#include <securec.h>

#include "hks_log.h"
#include "hks_mbedtls_common.h"
#include "hks_common_check.h"
#include "hks_mem.h"
#include "hks_template.h"

#define HKS_RSA_PUBLIC_EXPONENT 65537
#define HKS_RSA_KEYPAIR_CNT 3
#define MBEDTLS_RSA_PUBLIC	0
#define MBEDTLS_RSA_PRIVATE	1
#define HKS_RSA_KEYSIZE_CNT 8
#define MBEDTLS_RSA_PSS_DIGEST_NUM 2

typedef struct HksMbedtlsSignVerifyParam {
    uint32_t mbedtlsAlg;
    int32_t padding;
    uint32_t pssSaltLen;
} HksMbedtlsSignVerifyParam;

static int32_t RsaCheckKeySize(const uint32_t keySize)
{
#ifdef HKS_SUPPORT_RSA_C_FLEX_KEYSIZE
    if ((keySize >= HKS_RSA_KEY_SIZE_1024) && (keySize <= HKS_RSA_KEY_SIZE_2048)) {
        if ((keySize % HKS_RSA_KEYSIZE_CNT) == 0) {
            return HKS_SUCCESS;
        }
    }
#endif
    switch (keySize) {
        case HKS_RSA_KEY_SIZE_512:
        case HKS_RSA_KEY_SIZE_768:
        case HKS_RSA_KEY_SIZE_1024:
        case HKS_RSA_KEY_SIZE_2048:
        case HKS_RSA_KEY_SIZE_3072:
        case HKS_RSA_KEY_SIZE_4096:
            break;
        default:
            HKS_LOG_E("Invalid rsa key size! keySize = 0x%" LOG_PUBLIC "X", keySize);
            return HKS_ERROR_INVALID_KEY_SIZE;
    }

    return HKS_SUCCESS;
}

int32_t RsaKeyMaterialNedSizeCheck(const struct KeyMaterialRsa *keyMaterial)
{
    const uint32_t maxKeyByteLen = HKS_RSA_KEY_SIZE_4096 / HKS_BITS_PER_BYTE;
    if ((keyMaterial->nSize > maxKeyByteLen) || (keyMaterial->eSize > maxKeyByteLen) ||
        (keyMaterial->dSize > maxKeyByteLen)) {
        HKS_LOG_E("Invalid rsa keyMaterial! nSize = 0x%" LOG_PUBLIC "X, eSize = 0x%" LOG_PUBLIC "X, "
            "dSize = 0x%" LOG_PUBLIC "X",
            keyMaterial->nSize,
            keyMaterial->eSize,
            keyMaterial->dSize);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

int32_t RsaKeyCheck(const struct HksBlob *key)
{
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(key->data);

    int32_t ret = RsaCheckKeySize(keyMaterial->keySize);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = RsaKeyMaterialNedSizeCheck(keyMaterial);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    if (key->size < (sizeof(struct KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize + keyMaterial->dSize)) {
        HKS_LOG_E("Rsa key size too small! key size = 0x%" LOG_PUBLIC "X", key->size);
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
    HKS_IF_NULL_RETURN(rawMaterial, HKS_ERROR_MALLOC_FAIL)
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
        ret = mbedtls_mpi_write_binary(&(ctx->MBEDTLS_PRIVATE(N)), rawMaterial + offset, keyMaterial->nSize);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Rsa save keyMaterial mpi write N failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            break;
        }

        offset = offset + keyMaterial->nSize;
        ret = mbedtls_mpi_write_binary(&(ctx->MBEDTLS_PRIVATE(E)), rawMaterial + offset, keyMaterial->eSize);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Rsa save keyMaterial mpi write E failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            break;
        }

        offset = offset + keyMaterial->eSize;
        ret = mbedtls_mpi_write_binary(&(ctx->MBEDTLS_PRIVATE(D)), rawMaterial + offset, keyMaterial->dSize);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Rsa save keyMaterial mpi write D failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            break;
        }

        key->data = rawMaterial;
        key->size = rawMaterialLen;
    } while (0);

    if (ret != HKS_MBEDTLS_SUCCESS) {
        (void)memset_s(rawMaterial, rawMaterialLen, 0, rawMaterialLen);
        HKS_FREE(rawMaterial);
        ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    return ret;
}

int32_t HksMbedtlsRsaGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    mbedtls_rsa_context ctx;
    (void)memset_s(&ctx, sizeof(mbedtls_rsa_context), 0, sizeof(mbedtls_rsa_context));
    mbedtls_rsa_init(&ctx);
    ctx.MBEDTLS_PRIVATE(padding) = 0;
    ctx.MBEDTLS_PRIVATE(hash_id) = 0;

    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_entropy_context entropy;
    (void)memset_s(&entropy, sizeof(mbedtls_entropy_context), 0, sizeof(mbedtls_entropy_context));
    (void)memset_s(&ctrDrbg, sizeof(mbedtls_ctr_drbg_context), 0, sizeof(mbedtls_ctr_drbg_context));
    int32_t ret = HksCtrDrbgSeed(&ctrDrbg, &entropy);
    if (ret != HKS_SUCCESS) {
        mbedtls_rsa_free(&ctx);
        return ret;
    }

    do {
        ret = mbedtls_rsa_gen_key(&ctx, mbedtls_ctr_drbg_random, &ctrDrbg, spec->keyLen, HKS_RSA_PUBLIC_EXPONENT);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls rsa generate key failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
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
int32_t RsaKeyMaterialToCtx(const struct HksBlob *key, const bool needPrivateExponent, mbedtls_rsa_context *ctx)
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
            HKS_LOG_E("Mbedtls rsa keyMaterial to ctx read N failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            break;
        }

        offset = offset + keyMaterial->nSize;
        ret = mbedtls_mpi_read_binary(&e, key->data + offset, keyMaterial->eSize);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls rsa keyMaterial to ctx read E failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            break;
        }

        if (needPrivateExponent) {
            offset = offset + keyMaterial->eSize;
            ret = mbedtls_mpi_read_binary(&d, key->data + offset, keyMaterial->dSize);
            if (ret != HKS_MBEDTLS_SUCCESS) {
                HKS_LOG_E("Mbedtls rsa keyMaterial to ctx read D failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
                break;
            }
        }

        ret = mbedtls_rsa_import(ctx, &n, NULL, NULL, (needPrivateExponent ? &d : NULL), &e);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls rsa keyMaterial to ctx import failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
            break;
        }

        ret = mbedtls_rsa_complete(ctx);
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls rsa keyMaterial to ctx complete failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
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
#ifdef HKS_SUPPORT_RSA_ECB_NOPADDING
        case HKS_PADDING_NONE:
            return HKS_SUCCESS;
#endif
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

static int32_t HksMbedtlsRsaCryptMbedtls(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText, size_t *outlen,
    mbedtls_rsa_context *ctx)
{
    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_entropy_context entropy;
    (void)memset_s(&entropy, sizeof(mbedtls_entropy_context), 0, sizeof(mbedtls_entropy_context));
    (void)memset_s(&ctrDrbg, sizeof(mbedtls_ctr_drbg_context), 0, sizeof(mbedtls_ctr_drbg_context));
    int32_t ret = HksCtrDrbgSeed(&ctrDrbg, &entropy);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    do {
        ret = RsaKeyMaterialToCtx(key, !encrypt, ctx); /* encrypt don't need private exponent (d) */
        HKS_IF_NOT_SUCC_BREAK(ret)
#ifdef HKS_SUPPORT_RSA_ECB_NOPADDING
        if (usageSpec->padding == HKS_PADDING_NONE) {
            if (ctx->private_len != message->size) {
                HKS_LOG_E("Mbedtls rsa crypt nopadding failed! message size = 0x%" LOG_PUBLIC "X", message->size);
                ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
                break;
            }
            if (encrypt) {
                ret = mbedtls_rsa_public(ctx, message->data, cipherText->data);
                *outlen = mbedtls_rsa_get_len(ctx);
            } else {
                ret = mbedtls_rsa_private(ctx, mbedtls_ctr_drbg_random, &ctrDrbg,
                    message->data, cipherText->data);
                *outlen = mbedtls_rsa_get_len(ctx);
            }
            break;
        }
#endif
        if (encrypt) {
            ret = mbedtls_rsa_pkcs1_encrypt(ctx, mbedtls_ctr_drbg_random,
                &ctrDrbg, (size_t)message->size, message->data, cipherText->data);
            *outlen = mbedtls_rsa_get_len(ctx);
        } else {
            ret = mbedtls_rsa_pkcs1_decrypt(ctx, mbedtls_ctr_drbg_random, &ctrDrbg,
                outlen, message->data, cipherText->data, (size_t)cipherText->size);
        }
    } while (0);

    mbedtls_rsa_free(ctx);
    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

static int32_t HksMbedtlsRsaCrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    int32_t ret = RsaKeyCheck(key);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    int32_t padding = MBEDTLS_RSA_PKCS_V15;
    ret = HksToMbedtlsPadding(usageSpec->padding, &padding);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    mbedtls_rsa_context ctx;
    (void)memset_s(&ctx, sizeof(mbedtls_rsa_context), 0, sizeof(mbedtls_rsa_context));
    mbedtls_rsa_init(&ctx);

    if (padding == MBEDTLS_RSA_PKCS_V21) {
        uint32_t mbedtlsAlg;
        ret = HksToMbedtlsDigestAlg(usageSpec->digest, &mbedtlsAlg);
        mbedtls_rsa_set_padding(&ctx, padding, (mbedtls_md_type_t)mbedtlsAlg);
        HKS_IF_NOT_SUCC_RETURN(ret, ret)
    }

    size_t outlen;
    ret = HksMbedtlsRsaCryptMbedtls(key, usageSpec, message, encrypt, cipherText, &outlen, &ctx);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Mbedtls rsa crypt failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
        (void)memset_s(cipherText->data, cipherText->size, 0, cipherText->size);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    cipherText->size = (uint32_t)outlen;

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

static int32_t HksToMbedtlsRsaSetPssSaltLen(const struct HksBlob *key, const uint32_t digest,
    const uint32_t hksPssSaltLen, HksMbedtlsSignVerifyParam *param)
{
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(key->data);
    uint32_t digestLen = 0;
    int32_t ret = HksGetDigestLen(digest, &digestLen);
    HKS_IF_NOT_SUCC_RETURN(ret, ret);
    uint32_t saltLen = 0;

    switch (hksPssSaltLen) {
        case HKS_RSA_PSS_SALTLEN_DIGEST:
            saltLen = digestLen;
            break;
        case HKS_RSA_PSS_SALTLEN_MAX:
            if ((keyMaterial->keySize / HKS_BITS_PER_BYTE) < (digestLen + MBEDTLS_RSA_PSS_DIGEST_NUM)) {
                HKS_LOG_E("saltLen is invalid, keysize: %" LOG_PUBLIC "u, digestLen: %" LOG_PUBLIC "u",
                    keyMaterial->keySize, digestLen);
                return HKS_ERROR_INVALID_KEY_SIZE;
            }
            saltLen = (keyMaterial->keySize / HKS_BITS_PER_BYTE) - digestLen - MBEDTLS_RSA_PSS_DIGEST_NUM;
            break;
        default:
            return HKS_ERROR_NOT_SUPPORTED;
    }
    param->pssSaltLen = saltLen;

    return HKS_SUCCESS;
}

static int32_t HksMbedtlsRsaSignHandle(mbedtls_rsa_context *ctx, mbedtls_ctr_drbg_context *ctrDrbg,
    HksMbedtlsSignVerifyParam *signParam, const struct HksBlob *message, struct HksBlob *signature)
{
    int32_t ret = HKS_SUCCESS;
    if (signParam->padding == MBEDTLS_RSA_PKCS_V21) {
        // 支持传入saltlen
        ret = mbedtls_rsa_rsassa_pss_sign_ext(ctx, mbedtls_ctr_drbg_random, ctrDrbg,
            (mbedtls_md_type_t)signParam->mbedtlsAlg, message->size, message->data, signParam->pssSaltLen,
            signature->data);
    } else {
        ret = mbedtls_rsa_pkcs1_sign(ctx, mbedtls_ctr_drbg_random, ctrDrbg,
            (mbedtls_md_type_t)signParam->mbedtlsAlg, message->size, message->data, signature->data);
    }

    return ret;
}

static int32_t HksMbedtlsRsaVerifyHandle(mbedtls_rsa_context *ctx, mbedtls_ctr_drbg_context *ctrDrbg,
    HksMbedtlsSignVerifyParam *verifyParam, const struct HksBlob *message, struct HksBlob *signature)
{
    (void)ctrDrbg;
    int32_t ret = HKS_SUCCESS;
    if (verifyParam->padding == MBEDTLS_RSA_PKCS_V21) {
        // 支持传入saltlen
        ret = mbedtls_rsa_rsassa_pss_verify_ext(ctx, (mbedtls_md_type_t)verifyParam->mbedtlsAlg,
            message->size, message->data, (mbedtls_md_type_t)verifyParam->mbedtlsAlg, verifyParam->pssSaltLen,
            signature->data);
    } else {
        ret = mbedtls_rsa_pkcs1_verify(ctx,
            (mbedtls_md_type_t)verifyParam->mbedtlsAlg, message->size, message->data, signature->data);
    }

    return ret;
}

static int32_t HksMbedtlsRsaSignVerify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const bool sign, struct HksBlob *signature)
{
    uint32_t mbedtlsAlg;
    int32_t ret = HksToMbedtlsDigestAlg(usageSpec->digest, &mbedtlsAlg);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    int32_t padding;
    ret = HksToMbedtlsSignPadding(usageSpec->padding, &padding);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_entropy_context entropy;
    (void)memset_s(&entropy, sizeof(mbedtls_entropy_context), 0, sizeof(mbedtls_entropy_context));
    (void)memset_s(&ctrDrbg, sizeof(mbedtls_ctr_drbg_context), 0, sizeof(mbedtls_ctr_drbg_context));
    ret = HksCtrDrbgSeed(&ctrDrbg, &entropy);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    mbedtls_rsa_context ctx;
    (void)memset_s(&ctx, sizeof(mbedtls_rsa_context), 0, sizeof(mbedtls_rsa_context));
    mbedtls_rsa_init(&ctx);
    mbedtls_rsa_set_padding(&ctx, padding, (mbedtls_md_type_t)mbedtlsAlg);
    HksMbedtlsSignVerifyParam mbedtlsSignVerifyParam = { 0 };
    if (padding == MBEDTLS_RSA_PKCS_V21) {
        ret = HksToMbedtlsRsaSetPssSaltLen(key, usageSpec->digest, usageSpec->pssSaltLenType, &mbedtlsSignVerifyParam);
        HKS_IF_NOT_SUCC_RETURN(ret, ret)
    }
    mbedtlsSignVerifyParam.mbedtlsAlg = mbedtlsAlg;
    mbedtlsSignVerifyParam.padding = padding;

    do {
        ret = RsaKeyMaterialToCtx(key, sign, &ctx); /* sign need private exponent (d) */
        HKS_IF_NOT_SUCC_BREAK(ret)
        if (sign) {
            ret = HksMbedtlsRsaSignHandle(&ctx, &ctrDrbg, &mbedtlsSignVerifyParam, message, signature);
        } else {
            ret = HksMbedtlsRsaVerifyHandle(&ctx, &ctrDrbg, &mbedtlsSignVerifyParam, message, signature);
        }
        if (ret != HKS_MBEDTLS_SUCCESS) {
            HKS_LOG_E("Mbedtls rsa sign/verify failed! mbedtls ret = 0x%" LOG_PUBLIC "X", ret);
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

static int32_t RsaCheckNoPadding(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message)
{
    if (usageSpec->digest != HKS_DIGEST_NONE) {
        HKS_LOG_E("check rsa digest fail");
        return HKS_ERROR_INVALID_DIGEST;
    }

    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(key->data);
#ifdef HKS_SUPPORT_RSA_C_FLEX_KEYSIZE
    if (keyMaterial->keySize < HKS_RSA_KEY_SIZE_1024 || keyMaterial->keySize > HKS_RSA_KEY_SIZE_2048 ||
        keyMaterial->keySize % HKS_RSA_KEYSIZE_CNT != 0) {
        HKS_LOG_E("check rsa key size fail");
        return HKS_ERROR_INVALID_KEY_SIZE;
    }
#endif

    if (message->size * HKS_BITS_PER_BYTE != keyMaterial->keySize) {
        HKS_LOG_E("check rsa message size fail");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

static int32_t HksMbedtlsRsaSignForNoPadding(mbedtls_rsa_context *ctx, mbedtls_ctr_drbg_context *ctrDrbg,
    const struct HksBlob *message, struct HksBlob *signature)
{
    int32_t ret = mbedtls_rsa_private(ctx, mbedtls_ctr_drbg_random, ctrDrbg, message->data, signature->data);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("mbedtls rsa no padding sign failed, mbedtls ret = %" LOG_PUBLIC "d", ret);
        (void)memset_s(signature->data, signature->size, 0, signature->size);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    signature->size = (uint32_t)mbedtls_rsa_get_len(ctx);
    return HKS_SUCCESS;
}

static int32_t HksMbedtlsRsaVerifyForNoPadding(mbedtls_rsa_context *ctx, const struct HksBlob *message,
    struct HksBlob *signature)
{
    uint8_t *decryptedHash = (uint8_t *)HksMalloc(message->size);
    if (decryptedHash == NULL) {
        HKS_LOG_E("HksMalloc failed");
        return HKS_ERROR_MALLOC_FAIL;
    }

    int32_t ret = mbedtls_rsa_public(ctx, signature->data, decryptedHash);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get message hash from signature fail, mbedtls ret = %" LOG_PUBLIC "d", ret);
        HKS_FREE(decryptedHash);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    if (memcmp(decryptedHash, message->data, message->size) != 0) {
        HKS_LOG_E("mbedtls rsa no padding verify failed");
        HKS_FREE(decryptedHash);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    HKS_FREE(decryptedHash);
    return HKS_SUCCESS;
}

static int32_t HksMbedtlsRsaSignVerifyForNoPadding(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const bool sign, struct HksBlob *signature)
{
    int32_t ret = RsaCheckNoPadding(key, usageSpec, message);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check rsa no padding fail")

    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_entropy_context entropy;
    (void)memset_s(&ctrDrbg, sizeof(mbedtls_ctr_drbg_context), 0, sizeof(mbedtls_ctr_drbg_context));
    (void)memset_s(&entropy, sizeof(mbedtls_entropy_context), 0, sizeof(mbedtls_entropy_context));
    ret = HksCtrDrbgSeed(&ctrDrbg, &entropy);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    mbedtls_rsa_context ctx;
    (void)memset_s(&ctx, sizeof(mbedtls_rsa_context), 0, sizeof(mbedtls_rsa_context));
    mbedtls_rsa_init(&ctx);

    do {
        ret = RsaKeyMaterialToCtx(key, sign, &ctx); /* sign need private exponent (d) */
        HKS_IF_NOT_SUCC_BREAK(ret)

        if (sign) {
            ret = HksMbedtlsRsaSignForNoPadding(&ctx, &ctrDrbg, message, signature);
        } else {
            ret = HksMbedtlsRsaVerifyForNoPadding(&ctx, message, signature);
        }
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("mbedtls rsa sign/verify failed");
        }
    } while (0);

    mbedtls_rsa_free(&ctx);
    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

int32_t HksMbedtlsRsaSign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    int32_t ret = RsaKeyCheck(key);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    if (usageSpec->padding != HKS_PADDING_NONE) {
        ret = HksMbedtlsRsaSignVerify(key, usageSpec, message, true, signature);
    } else {
        ret = HksMbedtlsRsaSignVerifyForNoPadding(key, usageSpec, message, true, signature);
    }

    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksMbedtlsRsaSign, ret = %" LOG_PUBLIC "d", ret);
    }
    return ret;
}

int32_t HksMbedtlsRsaVerify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    int32_t ret = RsaKeyCheck(key);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
    if (usageSpec->padding != HKS_PADDING_NONE) {
        ret = HksMbedtlsRsaSignVerify(key, usageSpec, message, false, (struct HksBlob *)signature);
    } else {
        ret = HksMbedtlsRsaSignVerifyForNoPadding(key, usageSpec, message, false, (struct HksBlob *)signature);
    }

    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksMbedtlsRsaVerify, ret = %" LOG_PUBLIC "d", ret);
    }
    return ret;
}
#endif /* HKS_SUPPORT_RSA_SIGN_VERIFY */

#ifdef HKS_SUPPORT_RSA_GET_PUBLIC_KEY
static int32_t GetRsaPubKeyCheckParams(const struct HksBlob *keyIn, const struct HksBlob *keyOut)
{
    int32_t ret = RsaKeyCheck(keyIn);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* check keyOut size */
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(keyIn->data);
    if (keyOut->size < (sizeof(struct HksPubKeyInfo) + keyMaterial->nSize + keyMaterial->eSize)) {
        HKS_LOG_E("Rsa public keyOut size too small! keyOut size = 0x%" LOG_PUBLIC "X", keyOut->size);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    return HKS_SUCCESS;
}

int32_t HksMbedtlsGetRsaPubKey(const struct HksBlob *keyIn, struct HksBlob *keyOut)
{
    int32_t ret = GetRsaPubKeyCheckParams(keyIn, keyOut);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* n + e, so need size is: sizeof(struct HksPubKeyInfo) + nSize + eSize */
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(keyIn->data);
    const uint32_t outLen = sizeof(struct HksPubKeyInfo) + keyMaterial->nSize + keyMaterial->eSize;
    if (memcpy_s(keyOut->data, keyOut->size, (void *)keyMaterial, outLen) != EOK) {
        HKS_LOG_E("Memcpy rsa pub key failed!");
        (void)memset_s(keyOut->data, keyOut->size, 0, keyOut->size);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    ((struct KeyMaterialRsa *)(keyOut->data))->dSize = 0;
    keyOut->size = outLen;

    return HKS_SUCCESS;
}
#endif /* HKS_SUPPORT_RSA_GET_PUBLIC_KEY */
#endif /* HKS_SUPPORT_RSA_C */
