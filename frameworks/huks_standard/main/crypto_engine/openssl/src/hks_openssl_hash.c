/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifdef HKS_SUPPORT_HASH_C

#include "hks_openssl_hash.h"

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <stddef.h>

#include "hks_log.h"
#include "hks_openssl_engine.h"
#include "hks_template.h"

static int32_t CheckDigestAlg(uint32_t alg)
{
    switch (alg) {
#ifdef HKS_SUPPORT_HASH_SHA1
        case HKS_DIGEST_SHA1:
#endif
#ifdef HKS_SUPPORT_HASH_SHA224
        case HKS_DIGEST_SHA224:
#endif
#ifdef HKS_SUPPORT_HASH_SHA256
        case HKS_DIGEST_SHA256:
#endif
#ifdef HKS_SUPPORT_HASH_SHA384
        case HKS_DIGEST_SHA384:
#endif
#ifdef HKS_SUPPORT_HASH_SHA512
        case HKS_DIGEST_SHA512:
#endif
#ifdef HKS_SUPPORT_HASH_MD5
        case HKS_DIGEST_MD5:
#endif
#ifdef HKS_SUPPORT_HASH_SM3
        case HKS_DIGEST_SM3:
#endif
            break;
        default:
            HKS_LOG_E("Unsupport HASH Type!");
            return HKS_ERROR_INVALID_DIGEST;
    }
    return HKS_SUCCESS;
}

static int32_t HashCheckParam(uint32_t alg, const struct HksBlob *msg, struct HksBlob *hash)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckDigestAlg(alg), HKS_ERROR_INVALID_DIGEST, "Unsupport HASH Type!")

    HKS_IF_NOT_SUCC_LOGE_RETURN(HksOpensslCheckBlob(hash), HKS_ERROR_INVALID_ARGUMENT, "Invalid param hash!")

    HKS_IF_NOT_SUCC_LOGE_RETURN(HksOpensslCheckBlob(msg), HKS_ERROR_INVALID_ARGUMENT, "Invalid param msg!")
    return HKS_SUCCESS;
}

int32_t HksOpensslHash(uint32_t alg, const struct HksBlob *msg, struct HksBlob *hash)
{
    int32_t ret = HashCheckParam(alg, msg, hash);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT, "Invalid Params!")

    const EVP_MD *opensslAlg = GetOpensslAlg(alg);
    HKS_IF_NULL_LOGE_RETURN(opensslAlg, HKS_ERROR_CRYPTO_ENGINE_ERROR, "get openssl algorithm fail")

    ret = EVP_Digest(msg->data, msg->size, hash->data, &hash->size, opensslAlg, NULL);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return HKS_SUCCESS;
}

int32_t HksOpensslHashInit(void **cryptoCtx, uint32_t alg)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(CheckDigestAlg(alg), HKS_ERROR_INVALID_DIGEST, "Unsupport HASH Type!")

    const EVP_MD *opensslAlg = NULL;
    if (alg == HKS_DIGEST_SM3) {
        opensslAlg = EVP_sm3();
    } else {
        opensslAlg = GetOpensslAlg(alg);
    }

    HKS_IF_NULL_LOGE_RETURN(opensslAlg, HKS_ERROR_CRYPTO_ENGINE_ERROR, "hash_init get openssl algorithm fail")

    EVP_MD_CTX *tmpctx = EVP_MD_CTX_new();
    HKS_IF_NULL_RETURN(opensslAlg, HKS_ERROR_NULL_POINTER)

    EVP_MD_CTX_set_flags(tmpctx, EVP_MD_CTX_FLAG_ONESHOT);
    int32_t ret = EVP_DigestInit_ex(tmpctx, opensslAlg, NULL);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_MD_CTX_free(tmpctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    *cryptoCtx = (void*)tmpctx;
    return HKS_SUCCESS;
}

int32_t HksOpensslHashUpdate(void *cryptoCtx, const struct HksBlob *msg)
{
    HKS_IF_NULL_LOGE_RETURN(cryptoCtx, HKS_ERROR_INVALID_ARGUMENT, "Invalid param cryptoCtx!")

    HKS_IF_NOT_SUCC_LOGE_RETURN(HksOpensslCheckBlob(msg),
        HKS_ERROR_INVALID_ARGUMENT, "Invalid param msg!")

    int32_t ret = EVP_DigestUpdate(cryptoCtx, msg->data, msg->size);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return HKS_SUCCESS;
}

int32_t HksOpensslHashFinal(void **cryptoCtx, const struct HksBlob *msg, struct HksBlob *hash)
{
    HKS_IF_TRUE_LOGE_RETURN(cryptoCtx == NULL || *cryptoCtx == NULL, HKS_ERROR_INVALID_ARGUMENT,
        "Invalid param cryptoCtx!")

    if (msg == NULL) {
        HKS_LOG_E("Invalid param msg!");
        EVP_MD_CTX_free((EVP_MD_CTX *)*cryptoCtx);
        *cryptoCtx = NULL;
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (HksOpensslCheckBlob(hash) != HKS_SUCCESS) {
        HKS_LOG_E("Invalid param hash!");
        EVP_MD_CTX_free((EVP_MD_CTX *)*cryptoCtx);
        *cryptoCtx = NULL;
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret;
    if (msg->size != 0) {
        ret = EVP_DigestUpdate((EVP_MD_CTX *)*cryptoCtx, msg->data, msg->size);
        if (ret != HKS_OPENSSL_SUCCESS) {
            HksLogOpensslError();
            EVP_MD_CTX_free((EVP_MD_CTX *)*cryptoCtx);
            *cryptoCtx = NULL;
            return HKS_ERROR_CRYPTO_ENGINE_ERROR;
        }
    }

    ret = EVP_DigestFinal_ex((EVP_MD_CTX *)*cryptoCtx, hash->data, &hash->size);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        EVP_MD_CTX_free((EVP_MD_CTX *)*cryptoCtx);
        *cryptoCtx = NULL;
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    EVP_MD_CTX_free((EVP_MD_CTX *)*cryptoCtx);
    *cryptoCtx = NULL;
    return HKS_SUCCESS;
}

void HksOpensslHashFreeCtx(void **cryptoCtx)
{
    HKS_IF_TRUE_LOGE_RETURN_VOID(cryptoCtx == NULL || *cryptoCtx == NULL, "Openssl Hash freeCtx param error")

    if (*cryptoCtx != NULL) {
        EVP_MD_CTX_free((EVP_MD_CTX *)*cryptoCtx);
        *cryptoCtx = NULL;
    }
}
#endif