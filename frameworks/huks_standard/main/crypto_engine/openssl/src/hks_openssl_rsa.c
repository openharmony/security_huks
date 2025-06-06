/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifdef HKS_SUPPORT_RSA_C

#include "hks_openssl_rsa.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <stdbool.h>
#include <stddef.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_openssl_engine.h"
#include "hks_template.h"
#include "securec.h"

static int32_t RsaGenKeyCheckParam(const struct HksKeySpec *spec)
{
#ifdef HKS_SUPPORT_RSA_C_FLEX_KEYSIZE
    if (spec->keyLen > HKS_RSA_KEY_SIZE_1024 && spec->keyLen < HKS_RSA_KEY_SIZE_2048 &&
        spec->keyLen % HKS_RSA_KEY_BLOCK_SIZE == 0) {
        return HKS_SUCCESS;
    }
#endif
    switch (spec->keyLen) {
        case HKS_RSA_KEY_SIZE_512:
        case HKS_RSA_KEY_SIZE_768:
        case HKS_RSA_KEY_SIZE_1024:
        case HKS_RSA_KEY_SIZE_2048:
        case HKS_RSA_KEY_SIZE_3072:
        case HKS_RSA_KEY_SIZE_4096:
            return HKS_SUCCESS;
        default:
            HKS_LOG_E("Invlid rsa key len %" LOG_PUBLIC "x!", spec->keyLen);
            return HKS_ERROR_INVALID_ARGUMENT;
    }
}

static int32_t GetRsaPssSaltLen(const struct HksUsageSpec *usageSpec)
{
    switch (usageSpec->pssSaltLenType) {
        case HKS_RSA_PSS_SALTLEN_DIGEST:
            return RSA_PSS_SALTLEN_DIGEST;
        case HKS_RSA_PSS_SALTLEN_MAX:
            return RSA_PSS_SALTLEN_MAX;
        default:
            HKS_LOG_E("Invalid rsa salt len type %" LOG_PUBLIC "x!", usageSpec->pssSaltLenType);
            return HKS_ERROR_NOT_SUPPORTED;
    }
}

static int32_t RsaCheckKeyMaterial(const struct HksBlob *key)
{
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(key->data);
    if (keyMaterial->keyAlg != HKS_ALG_RSA) {
        return HKS_ERROR_INVALID_KEY_INFO;
    }
    if (key->size != sizeof(struct KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize + keyMaterial->dSize) {
        return HKS_ERROR_INVALID_KEY_INFO;
    }
    return HKS_SUCCESS;
}

int32_t InitRsaKeyBuf(const struct KeyMaterialRsa *keyMaterial, struct HksBlob *bufBlob)
{
    uint32_t maxSize = keyMaterial->nSize >= keyMaterial->eSize ? keyMaterial->nSize : keyMaterial->eSize;

    if (maxSize < keyMaterial->dSize) {
        maxSize = keyMaterial->dSize;
    }

    bufBlob->data = (uint8_t *)HksMalloc(maxSize);
    HKS_IF_NULL_LOGE_RETURN(bufBlob->data, HKS_ERROR_MALLOC_FAIL, "HksMalloc failed!")

    bufBlob->size = maxSize;
    return HKS_SUCCESS;
}

static RSA *InitRsaStruct(const struct HksBlob *key, const bool needPrivateExponent)
{
    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(key->data);
    struct HksBlob bufBlob = { 0, NULL };
    int32_t ret = InitRsaKeyBuf(keyMaterial, &bufBlob);
    HKS_IF_NOT_SUCC_RETURN(ret, NULL)
    bool copyFail = false;
    uint32_t offset = sizeof(*keyMaterial);
    if (memcpy_s(bufBlob.data, bufBlob.size, key->data + offset, keyMaterial->nSize) != EOK) {
        copyFail = true;
    }
    BIGNUM *n = BN_bin2bn(bufBlob.data, keyMaterial->nSize, NULL);
    offset += keyMaterial->nSize;
    if (memcpy_s(bufBlob.data, bufBlob.size, key->data + offset, keyMaterial->eSize) != EOK) {
        copyFail = true;
    }
    BIGNUM *e = BN_bin2bn(bufBlob.data, keyMaterial->eSize, NULL);
    offset += keyMaterial->eSize;
    BIGNUM *d = NULL;
    if (needPrivateExponent) {
        if (memcpy_s(bufBlob.data, bufBlob.size, key->data + offset, keyMaterial->dSize) != EOK) {
            copyFail = true;
        }
        d = BN_bin2bn(bufBlob.data, keyMaterial->dSize, NULL);
    }
    RSA *rsa = NULL;
    do {
        if (copyFail) {
            break;
        }
        rsa = RSA_new();
        if (rsa != NULL) {
            ret = RSA_set0_key(rsa, n, e, d);
            if (ret != HKS_OPENSSL_SUCCESS) {
                RSA_free(rsa);
                rsa = NULL;
                break;
            }
        }
    } while (0);
    if (rsa == NULL) {
        SELF_FREE_PTR(n, BN_free);
        SELF_FREE_PTR(e, BN_free);
        SELF_FREE_PTR(d, BN_free);
    }
    memset_s(bufBlob.data, bufBlob.size, 0, bufBlob.size);
    HKS_MEMSET_FREE_BLOB(bufBlob);
    return rsa;
}

int32_t HksOpensslCheckRsaKey(const struct HksBlob *key)
{
    struct KeyMaterialRsa *pubKeyMaterial = (struct KeyMaterialRsa *)key->data;
    BIGNUM *e = NULL;
    BIGNUM *eMin = NULL;
    uint8_t bnE[] = { 0x01, 0x00, 0x01 };
    int32_t ret = HKS_SUCCESS;
    do {
        e = BN_bin2bn(key->data + sizeof(struct KeyMaterialRsa) + pubKeyMaterial->nSize, pubKeyMaterial->eSize, NULL);
        if (e == NULL) {
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        eMin = BN_bin2bn(bnE, sizeof(bnE), NULL);
        if (eMin == NULL) {
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        if (BN_cmp(e, eMin) < 0) {
            HKS_LOG_E("rsa public key is not secure");
            ret = HKS_ERROR_INVALID_KEY_INFO;
        }
    } while (0);

    BN_free(e);
    BN_free(eMin);
    return ret;
}

#ifdef HKS_SUPPORT_RSA_GENERATE_KEY
static int32_t RsaSaveKeyMaterial(const RSA *rsa, const uint32_t keySize, struct HksBlob *key)
{
    const uint32_t keyByteLen = keySize / HKS_BITS_PER_BYTE;
    const uint32_t rawMaterialLen = sizeof(struct KeyMaterialRsa) + keyByteLen * HKS_RSA_KEYPAIR_CNT;
    uint8_t *rawMaterial = (uint8_t *)HksMalloc(rawMaterialLen);
    HKS_IF_NULL_RETURN(rawMaterial, HKS_ERROR_MALLOC_FAIL)

    (void)memset_s(rawMaterial, rawMaterialLen, 0, rawMaterialLen);

    struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)rawMaterial;
    keyMaterial->keyAlg = HKS_ALG_RSA;
    keyMaterial->keySize = keySize;

    uint8_t tmp_buff[keyByteLen];
    if (memset_s(tmp_buff, keyByteLen, 0, keyByteLen) != EOK) {
        HKS_FREE(rawMaterial);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    uint32_t offset = sizeof(*keyMaterial);
    keyMaterial->nSize = (uint32_t)BN_bn2bin(RSA_get0_n(rsa), tmp_buff);
    if (memcpy_s(rawMaterial + offset, keyByteLen, tmp_buff, keyMaterial->nSize) != EOK) {
        HKS_FREE(rawMaterial);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    offset += keyMaterial->nSize;
    keyMaterial->eSize = (uint32_t)BN_bn2bin(RSA_get0_e(rsa), tmp_buff);
    if (memcpy_s(rawMaterial + offset, keyByteLen, tmp_buff, keyMaterial->eSize) != EOK) {
        HKS_FREE(rawMaterial);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    offset += keyMaterial->eSize;
    keyMaterial->dSize = (uint32_t)BN_bn2bin(RSA_get0_d(rsa), tmp_buff);
    if (memcpy_s(rawMaterial + offset, keyByteLen, tmp_buff, keyMaterial->dSize) != EOK) {
        HKS_FREE(rawMaterial);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    key->data = rawMaterial;
    key->size = sizeof(struct KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize + keyMaterial->dSize;

    return HKS_SUCCESS;
}

int32_t HksOpensslRsaGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(RsaGenKeyCheckParam(spec),
        HKS_ERROR_INVALID_ARGUMENT, "rsa generate key invalid params!")

    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    if (rsa == NULL || e == NULL) {
        SELF_FREE_PTR(rsa, RSA_free);
        SELF_FREE_PTR(e, BN_free);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    if (BN_set_word(e, RSA_F4) != HKS_OPENSSL_SUCCESS) {
        SELF_FREE_PTR(rsa, RSA_free);
        SELF_FREE_PTR(e, BN_free);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    if (RSA_generate_key_ex(rsa, spec->keyLen, e, NULL) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        BN_free(e);
        RSA_free(rsa);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    BN_free(e);

    int32_t ret = RsaSaveKeyMaterial(rsa, spec->keyLen, key);

    RSA_free(rsa);

    return ret;
}
#endif /* HKS_SUPPORT_RSA_GENERATE_KEY */

#ifdef HKS_SUPPORT_RSA_GET_PUBLIC_KEY
int32_t HksOpensslGetRsaPubKey(const struct HksBlob *input, struct HksBlob *output)
{
    struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)input->data;
    output->size = sizeof(struct KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize;

    struct KeyMaterialRsa *publickeyMaterial = (struct KeyMaterialRsa *)output->data;
    publickeyMaterial->keyAlg = keyMaterial->keyAlg;
    publickeyMaterial->keySize = keyMaterial->keySize;
    publickeyMaterial->nSize = keyMaterial->nSize;
    publickeyMaterial->eSize = keyMaterial->eSize;
    publickeyMaterial->dSize = 0;

    if (memcpy_s(output->data + sizeof(struct KeyMaterialRsa), output->size - sizeof(struct KeyMaterialRsa),
        input->data + sizeof(struct KeyMaterialRsa), keyMaterial->nSize + keyMaterial->eSize) != EOK) {
            HKS_LOG_E("copy output->data + sizeof(struct KeyMaterialRsa) failed!");
            return HKS_ERROR_INSUFFICIENT_MEMORY;
        }

    return HKS_SUCCESS;
}
#endif /* HKS_SUPPORT_RSA_GET_PUBLIC_KEY */

#ifdef HKS_SUPPORT_RSA_CRYPT
static int32_t GetRsaCryptPadding(uint32_t padding, uint32_t *rsaPadding)
{
    switch (padding) {
#ifdef HKS_SUPPORT_RSA_ECB_NOPADDING
        case HKS_PADDING_NONE:
            *rsaPadding = RSA_NO_PADDING;
            return HKS_SUCCESS;
#endif
#ifdef HKS_SUPPORT_RSA_ECB_PKCS1PADDING
        case HKS_PADDING_PKCS1_V1_5:
            *rsaPadding = RSA_PKCS1_PADDING;
            return HKS_SUCCESS;
#endif
#if defined(HKS_SUPPORT_RSA_ECB_OEAPPADDING) || defined(HKS_SUPPORT_RSA_ECB_OAEPPADDING_SHA1MGF1) ||              \
    defined(HKS_SUPPORT_RSA_ECB_OAEPPADDING_SHA224MGF1) || defined(HKS_SUPPORT_RSA_ECB_OAEPPADDING_SHA256MGF1) || \
    defined(HKS_SUPPORT_RSA_ECB_OAEPPADDING_SHA384MGF1) || defined(HKS_SUPPORT_RSA_ECB_OAEPPADDING_SHA512MGF1)
        case HKS_PADDING_OAEP:
            *rsaPadding = RSA_PKCS1_OAEP_PADDING;
            return HKS_SUCCESS;
#endif
        default:
            return HKS_ERROR_NOT_SUPPORTED;
    }
}

static EVP_PKEY_CTX *InitEvpPkeyCtx(const struct HksBlob *key, bool encrypt)
{
    int32_t ret = RsaCheckKeyMaterial(key);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, NULL, "check key material failed")

    RSA *rsa = InitRsaStruct(key, !encrypt);
    HKS_IF_NULL_LOGE_RETURN(rsa, NULL, "initialize rsa key failed")

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        RSA_free(rsa);
        HksLogOpensslError();
        return NULL;
    }

    ret = EVP_PKEY_assign_RSA(pkey, rsa);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) {
        HksLogOpensslError();
        EVP_PKEY_free(pkey);
        return NULL;
    }

    if (encrypt) {
        ret = EVP_PKEY_encrypt_init(ctx);
    } else {
        ret = EVP_PKEY_decrypt_init(ctx);
    }
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_free(pkey);
    return ctx;
}

static int32_t HksOpensslRsaCryptInit(EVP_PKEY_CTX *ctx, const struct HksUsageSpec *usageSpec)
{
    int32_t ret;
    uint32_t padding = 0;
    HKS_IF_NOT_SUCC_LOGE_RETURN(GetRsaCryptPadding(usageSpec->padding, &padding),
        HKS_ERROR_CRYPTO_ENGINE_ERROR, "Unsupport padding.")

    ret = EVP_PKEY_CTX_set_rsa_padding(ctx, padding);
    if (ret <= 0) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    if (usageSpec->padding == HKS_PADDING_OAEP) {
        const EVP_MD *md = GetOpensslAlg(usageSpec->digest);
        const EVP_MD *mgfMd;
        if (usageSpec->digest == HKS_DIGEST_SHA256 && usageSpec->mgfDigest == HKS_DIGEST_SHA1) {
            mgfMd = GetOpensslAlg(usageSpec->mgfDigest);
        } else {
            mgfMd = md;
        }
        if ((md == NULL) || mgfMd == NULL || (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) ||
            (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgfMd) <= 0)) {
            return HKS_ERROR_CRYPTO_ENGINE_ERROR;
        }
    }
    return HKS_SUCCESS;
}

static int32_t HksOpensslRsaCrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const bool encrypt, struct HksBlob *cipherText)
{
    int32_t ret;
    EVP_PKEY_CTX *ctx = InitEvpPkeyCtx(key, encrypt);
    if (ctx == NULL) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    if (HksOpensslRsaCryptInit(ctx, usageSpec) != HKS_SUCCESS) {
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    size_t outLen;
    if (encrypt) {
        ret = EVP_PKEY_encrypt(ctx, NULL, &outLen, message->data, message->size);
    } else {
        ret = EVP_PKEY_decrypt(ctx, NULL, &outLen, message->data, message->size);
    }
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    if (outLen > cipherText->size) {
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (encrypt) {
        ret = EVP_PKEY_encrypt(ctx, cipherText->data, &outLen, message->data, message->size);
    } else {
        ret = EVP_PKEY_decrypt(ctx, cipherText->data, &outLen, message->data, message->size);
    }
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    cipherText->size = outLen;

    EVP_PKEY_CTX_free(ctx);
    return HKS_SUCCESS;
}

int32_t HksOpensslRsaEncrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText, struct HksBlob *tagAead)
{
    (void)tagAead;
    return HksOpensslRsaCrypt(key, usageSpec, message, true, cipherText);
}

int32_t HksOpensslRsaDecrypt(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *cipherText)
{
    return HksOpensslRsaCrypt(key, usageSpec, message, false, cipherText);
}
#endif /* HKS_SUPPORT_RSA_CRYPT */

#ifdef HKS_SUPPORT_RSA_SIGN_VERIFY
static int32_t GetRsaSignPadding(uint32_t padding, uint32_t *rsaPadding)
{
    switch (padding) {
        case HKS_PADDING_PKCS1_V1_5:
            *rsaPadding = RSA_PKCS1_PADDING;
            return HKS_SUCCESS;
        case HKS_PADDING_PSS:
            *rsaPadding = RSA_PKCS1_PSS_PADDING;
            return HKS_SUCCESS;
        case HKS_PADDING_NONE:
            *rsaPadding = RSA_NO_PADDING;
            return HKS_SUCCESS;
        default:
            return HKS_ERROR_NOT_SUPPORTED;
    }
}

static int32_t SetRsaPadding(EVP_PKEY_CTX *ctx, const struct HksUsageSpec *usageSpec)
{
    uint32_t opensslPadding = 0;
    int32_t ret = GetRsaSignPadding(usageSpec->padding, &opensslPadding);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_PADDING, "Unsupport padding.")

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, opensslPadding) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    if (usageSpec->padding == HKS_PADDING_PSS) {
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, GetRsaPssSaltLen(usageSpec)) != HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            return HKS_ERROR_CRYPTO_ENGINE_ERROR;
        }
    }
    return HKS_SUCCESS;
}

static EVP_PKEY *InitRsaEvpKey(const struct HksBlob *key, bool signing)
{
    RSA *rsa = InitRsaStruct(key, signing);
    HKS_IF_NULL_LOGE_RETURN(rsa, NULL, "initialize rsa key failed")

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        HKS_LOG_E("evp pkey new failed");
        SELF_FREE_PTR(rsa, RSA_free);
        return NULL;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        SELF_FREE_PTR(rsa, RSA_free);
        SELF_FREE_PTR(pkey, EVP_PKEY_free);
        return NULL;
    }

    return pkey;
}

static EVP_PKEY_CTX *InitRsaCtx(const struct HksBlob *key, const struct HksUsageSpec *usageSpec, bool signing,
    uint32_t len)
{
    const EVP_MD *opensslAlg = GetOpensslAlg(usageSpec->digest);
    if (usageSpec->digest == HKS_DIGEST_NONE) {
        opensslAlg = GetOpensslAlgFromLen(len);
    }

    if (opensslAlg == NULL) {
        HKS_LOG_E("get openssl algorithm fail");
        return NULL;
    }
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    do {
        pkey = InitRsaEvpKey(key, signing);
        HKS_IF_NULL_BREAK(pkey)

        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        HKS_IF_NULL_BREAK(ctx)

        if (signing) {
            ret = EVP_PKEY_sign_init(ctx);
        } else {
            ret = EVP_PKEY_verify_init(ctx);
        }
        HKS_IF_TRUE_BREAK(ret != HKS_OPENSSL_SUCCESS)

        ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
        HKS_IF_NOT_SUCC_BREAK(SetRsaPadding(ctx, usageSpec))
        HKS_IF_TRUE_BREAK(EVP_PKEY_CTX_set_signature_md(ctx, opensslAlg) != HKS_OPENSSL_SUCCESS)
        ret = HKS_SUCCESS;
    } while (0);

    SELF_FREE_PTR(pkey, EVP_PKEY_free);
    if (ret != HKS_SUCCESS) {
        HksLogOpensslError();
        SELF_FREE_PTR(ctx, EVP_PKEY_CTX_free);
    }

    return ctx;
}

static int32_t RsaCheckNoPadding(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message)
{
    if (usageSpec->digest != HKS_DIGEST_NONE) {
        HKS_LOG_E("check rsa digest fail");
        return HKS_ERROR_INVALID_DIGEST;
    }

    const struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)(key->data);
    if (message->size * HKS_BITS_PER_BYTE != keyMaterial->keySize) {
        HKS_LOG_E("check rsa message size fail");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}

static int32_t HksOpensslRsaSignForNoPadding(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    int32_t ret = RsaCheckKeyMaterial(key);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check rsa key material fail")

    ret = RsaCheckNoPadding(key, usageSpec, message);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check rsa no padding fail")

    RSA *rsa = InitRsaStruct(key, true);
    HKS_IF_NULL_LOGE_RETURN(rsa, HKS_ERROR_INSUFFICIENT_MEMORY, "initialize rsa key fail")

    int sigSize = RSA_private_encrypt((int)message->size, message->data, signature->data, rsa, RSA_NO_PADDING);
    if (sigSize < 0) {
        HksLogOpensslError();
        HKS_LOG_E("rsa nopadding sign fail");
        SELF_FREE_PTR(rsa, RSA_free);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    signature->size = (uint32_t)sigSize;

    SELF_FREE_PTR(rsa, RSA_free);
    return HKS_SUCCESS;
}

static int32_t HksOpensslRsaSignForNomal(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    EVP_PKEY_CTX *ctx = InitRsaCtx(key, usageSpec, true, message->size);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_INVALID_KEY_INFO, "initialize rsa context failed")

    size_t sigSize = (size_t)signature->size;
    if (EVP_PKEY_sign(ctx, signature->data, &sigSize, message->data, message->size) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    signature->size = (uint32_t)sigSize;
    EVP_PKEY_CTX_free(ctx);
    return HKS_SUCCESS;
}

int32_t HksOpensslRsaSign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    int32_t ret = 0;
    if (usageSpec->padding == HKS_PADDING_NONE) {
        ret = HksOpensslRsaSignForNoPadding(key, usageSpec, message, signature);
    } else {
        ret = HksOpensslRsaSignForNomal(key, usageSpec, message, signature);
    }

    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksOpensslRsaSign fail, ret = %" LOG_PUBLIC "u", ret);
    }
    return ret;
}

static int32_t HksOpensslRsaVerifyForNoPadding(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    int32_t ret = RsaCheckKeyMaterial(key);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check rsa key material fail")

    ret = RsaCheckNoPadding(key, usageSpec, message);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check rsa no padding fail")

    RSA *rsa = InitRsaStruct(key, true);
    HKS_IF_NULL_LOGE_RETURN(rsa, HKS_ERROR_INSUFFICIENT_MEMORY, "initialize rsa key fail")

    uint8_t *decryptedHash = (uint8_t *)HksMalloc(message->size);
    if (decryptedHash == NULL) {
        HKS_LOG_E("HksMalloc failed");
        SELF_FREE_PTR(rsa, RSA_free);
        return HKS_ERROR_MALLOC_FAIL;
    }

    do {
        if (RSA_public_decrypt((int)signature->size, signature->data, decryptedHash, rsa, RSA_NO_PADDING) < 0) {
            HksLogOpensslError();
            HKS_LOG_E("get message hash from rsa signature failed");
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        if (memcmp(decryptedHash, message->data, message->size) != 0) {
            HKS_LOG_E("rsa nopadding verify failed");
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
    } while (0);

    HKS_FREE(decryptedHash);
    SELF_FREE_PTR(rsa, RSA_free);
    return ret;
}

static int32_t HksOpensslRsaVerifyForNormal(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    EVP_PKEY_CTX *ctx = InitRsaCtx(key, usageSpec, false, message->size);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_INVALID_KEY_INFO, "initialize rsa context failed")

    if (EVP_PKEY_verify(ctx, signature->data, signature->size, message->data, message->size) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    EVP_PKEY_CTX_free(ctx);
    return HKS_SUCCESS;
}

int32_t HksOpensslRsaVerify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    int32_t ret = 0;
    if (usageSpec->padding == HKS_PADDING_NONE) {
        ret = HksOpensslRsaVerifyForNoPadding(key, usageSpec, message, signature);
    } else {
        ret = HksOpensslRsaVerifyForNormal(key, usageSpec, message, signature);
    }

    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksOpensslRsaVerify fail, ret = %" LOG_PUBLIC "u", ret);
    }
    return ret;
}
#endif /* HKS_SUPPORT_RSA_SIGN_VERIFY */
#endif /* HKS_SUPPORT_RSA_C */
