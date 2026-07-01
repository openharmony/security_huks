/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "hks_error_code.h"
#include "hks_openssl_engine.h"
#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_openssl_mlkem.h"
#include "securec.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"

#define HKS_OPENSSL_SUCCESS 1

static int32_t MlKemEncapsulateInitCtx(const struct HksBlob *rawKey, EVP_PKEY **pkey)
{
    HKS_IF_TRUE_LOGE_RETURN(rawKey->size < sizeof(struct HksKeyMaterialMlKem), HKS_ERROR_INVALID_ARGUMENT,
        "invalid raw key size %" LOG_PUBLIC "u", rawKey->size)
    struct HksKeyMaterialMlKem *keyMaterial = (struct HksKeyMaterialMlKem *)rawKey->data;
    const char *algName = HksOpensslMlKemGetAlgName(keyMaterial->keyParamSet);
    HKS_IF_NULL_LOGE_RETURN(algName, HKS_ERROR_INVALID_ALGORITHM, "get ml-kem alg name failed")

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, NULL);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_CRYPTO_ENGINE_ERROR, "EVP_PKEY_CTX_new_from_name failed")

    int32_t ret = EVP_PKEY_fromdata_init(ctx);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("EVP_PKEY_fromdata_init failed");
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    uint32_t offset = sizeof(struct HksKeyMaterialMlKem);
    OSSL_PARAM params[2];
    size_t pubData = keyMaterial->pubKeySize;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
        rawKey->data + offset, pubData);
    params[1] = OSSL_PARAM_construct_end();

    ret = EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("EVP_PKEY_fromdata failed");
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    EVP_PKEY_CTX_free(ctx);
    return HKS_SUCCESS;
}

static int32_t MlKemEncapsulate(EVP_PKEY *pkey, struct HksEncapsulationResult *encapResult)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_CRYPTO_ENGINE_ERROR, "EVP_PKEY_CTX_new failed")

    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    int32_t sslRet = HKS_OPENSSL_SUCCESS;
    do {
        sslRet = EVP_PKEY_encapsulate_init(ctx, NULL);
        if (sslRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("EVP_PKEY_encapsulate_init failed");
            HksLogOpensslError();
            break;
        }

        size_t ciphertextLen = 0;
        size_t sharedSecretLen = 0;
        sslRet = EVP_PKEY_encapsulate(ctx, NULL, &ciphertextLen, NULL, &sharedSecretLen);
        if (sslRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("EVP_PKEY_encapsulate get length failed");
            HksLogOpensslError();
            break;
        }
        ret = HKS_ERROR_MALLOC_FAIL;
        encapResult->encapsulatedData.size = ciphertextLen;
        encapResult->encapsulatedData.data = (uint8_t *)HksMalloc(ciphertextLen);
        HKS_IF_NULL_LOGE_BREAK(encapResult->encapsulatedData.data, "malloc ciphertext failed")

        encapResult->sharedSecret.size = sharedSecretLen;
        encapResult->sharedSecret.data = (uint8_t *)HksMalloc(sharedSecretLen);
        HKS_IF_NULL_LOGE_BREAK(encapResult->sharedSecret.data, "malloc sharedSecret failed")

        sslRet = EVP_PKEY_encapsulate(ctx, encapResult->encapsulatedData.data, &ciphertextLen,
            encapResult->sharedSecret.data, &sharedSecretLen);
        if (sslRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("EVP_PKEY_encapsulate failed");
            HksLogOpensslError();
            break;
        }
        ret = HKS_SUCCESS;
    } while (0);

    EVP_PKEY_CTX_free(ctx);
    if (ret != HKS_SUCCESS) {
        HKS_FREE_ENCAPSULATION_RESULT(encapResult);
        HKS_IF_TRUE_LOGE_RETURN((sslRet != HKS_OPENSSL_SUCCESS), HKS_ERROR_CRYPTO_ENGINE_ERROR, "kem fail")
    }
    return ret;
}

int32_t HksOpensslMlKemEncapsulate(const struct HksBlob *rawKey, struct HksEncapsulationResult *encapResult)
{
    if (rawKey == NULL || encapResult == NULL) {
        HKS_LOG_E("invalid params");
        return HKS_ERROR_NULL_POINTER;
    }

    EVP_PKEY *pkey = NULL;
    int32_t ret = MlKemEncapsulateInitCtx(rawKey, &pkey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "MlKemEncapsulateInitCtx failed")

    ret = MlKemEncapsulate(pkey, encapResult);

    EVP_PKEY_free(pkey);
    return ret;
}

static int32_t MlKemDecapsulateInitCtx(const struct HksBlob *rawKey, EVP_PKEY **pkey)
{
    HKS_IF_TRUE_LOGE_RETURN(rawKey->size < sizeof(struct HksKeyMaterialMlKem), HKS_ERROR_INVALID_ARGUMENT, \
        "invalid raw key size %" LOG_PUBLIC "u", rawKey->size)
    struct HksKeyMaterialMlKem *keyMaterial = (struct HksKeyMaterialMlKem *)rawKey->data;
    const char *algName = HksOpensslMlKemGetAlgName(keyMaterial->keyParamSet);
    HKS_IF_NULL_LOGE_RETURN(algName, HKS_ERROR_INVALID_KEY_SIZE, "get ml-kem alg name failed")

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, NULL);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_CRYPTO_ENGINE_ERROR, "EVP_PKEY_CTX_new_from_name failed")

    int32_t ret = EVP_PKEY_fromdata_init(ctx);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("EVP_PKEY_fromdata_init failed");
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    uint32_t offset = sizeof(struct HksKeyMaterialMlKem);
    OSSL_PARAM params[3];
    uint32_t index = 0;
    
    params[index++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
        rawKey->data + offset, keyMaterial->pubKeySize);
    offset += keyMaterial->pubKeySize;
    
    params[index++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
        rawKey->data + offset, keyMaterial->priKeySize);
    params[index++] = OSSL_PARAM_construct_end();

    ret = EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_KEYPAIR, params);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("EVP_PKEY_fromdata failed");
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    EVP_PKEY_CTX_free(ctx);
    return HKS_SUCCESS;
}

static int32_t MlKemDecapsulate(EVP_PKEY *pkey, const struct HksBlob *ciphertext,
    struct HksBlob *sharedSecret)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_CRYPTO_ENGINE_ERROR, "EVP_PKEY_CTX_new failed")

    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    int32_t sslRet = HKS_OPENSSL_SUCCESS;
    do {
        sslRet = EVP_PKEY_decapsulate_init(ctx, NULL);
        if (sslRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("EVP_PKEY_decapsulate_init failed");
            HksLogOpensslError();
            break;
        }

        size_t sharedSecretLen = HKS_ML_KEM_SHARED_SECRET_LEN;
        size_t ciphertextSize = ciphertext->size;
        sslRet = EVP_PKEY_decapsulate(ctx, NULL, &sharedSecretLen, ciphertext->data, ciphertextSize);
        if (sslRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("EVP_PKEY_decapsulate get length failed");
            HksLogOpensslError();
            break;
        }

        sharedSecret->size = sharedSecretLen;
        sharedSecret->data = (uint8_t *)HksMalloc(sharedSecretLen);
        if (sharedSecret->data == NULL) {
            HKS_LOG_E("malloc sharedSecret failed");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        sslRet = EVP_PKEY_decapsulate(ctx, sharedSecret->data, &sharedSecretLen,
            ciphertext->data, ciphertextSize);
        if (sslRet != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("EVP_PKEY_decapsulate failed");
            HksLogOpensslError();
            break;
        }
        ret = HKS_SUCCESS;
    } while (0);

    EVP_PKEY_CTX_free(ctx);
    if (ret != HKS_SUCCESS) {
        HKS_MEMSET_FREE_PTR(sharedSecret->data, sharedSecret->size);
        sharedSecret->size = 0;
        HKS_IF_TRUE_LOGE_RETURN((sslRet != HKS_OPENSSL_SUCCESS), HKS_ERROR_CRYPTO_ENGINE_ERROR, "kem fail");
    }

    return ret;
}

int32_t HksOpensslMlKemDecapsulate(const struct HksBlob *rawKey, const struct HksBlob *ciphertext,
    struct HksBlob *sharedSecret)
{
    if (rawKey == NULL || ciphertext == NULL || sharedSecret == NULL) {
        HKS_LOG_E("invalid params");
        return HKS_ERROR_NULL_POINTER;
    }

    EVP_PKEY *pkey = NULL;
    int32_t ret = MlKemDecapsulateInitCtx(rawKey, &pkey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "MlKemDecapsulateInitCtx failed")

    ret = MlKemDecapsulate(pkey, ciphertext, sharedSecret);

    EVP_PKEY_free(pkey);
    return ret;
}