/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifdef HKS_SUPPORT_ML_DSA_C
#include "securec.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include "hks_openssl_engine.h"
#include "hks_openssl_ml_dsa.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"

#define ML_DSA_KEY_NUM 4
#define ML_DSA_CONTEXT "context-string"

typedef struct MlDsaParam {
    uint32_t paramSetId;
    uint32_t alg;
    uint32_t pubKeySize;
    uint32_t priKeySize;
} MlDsaParam;

static MlDsaParam g_validMlDsaParam[] = {
    {
        HKS_ML_DSA_KEY_PARAM_SET_44, EVP_PKEY_ML_DSA_44, HKS_ML_DSA_PUB_KEY_SIZE_1312,
        HKS_ML_DSA_PRI_KEY_SIZE_2560
    }, {
        HKS_ML_DSA_KEY_PARAM_SET_65, EVP_PKEY_ML_DSA_65, HKS_ML_DSA_PUB_KEY_SIZE_1952,
        HKS_ML_DSA_PRI_KEY_SIZE_4032
    }, {
        HKS_ML_DSA_KEY_PARAM_SET_87, EVP_PKEY_ML_DSA_87, HKS_ML_DSA_PUB_KEY_SIZE_2592,
        HKS_ML_DSA_PRI_KEY_SIZE_4896
    }
};

#ifdef HKS_SUPPORT_ML_DSA_GENERATE_KEY
static int32_t MlDsaGetKeyMaterial(EVP_PKEY *pkey, uint32_t paramSetId, struct HksBlob *key)
{
    uint32_t pubKeySize = 0;
    uint32_t priKeySize = 0;
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_validMlDsaParam); i++) {
        if (g_validMlDsaParam[i].paramSetId == paramSetId) {
            pubKeySize = g_validMlDsaParam[i].pubKeySize;
            priKeySize = g_validMlDsaParam[i].priKeySize;
        }
    }
    HKS_IF_TRUE_LOGE_RETURN(pubKeySize == 0, HKS_ERROR_INVALID_KEY_SIZE, "get ml-dsa key len failed");

    const uint32_t rawMaterialLen = sizeof(struct HksKeyMaterialMlDsa) + pubKeySize + priKeySize;
    uint8_t *rawMaterial = (uint8_t *)HksMalloc(rawMaterialLen);
    HKS_IF_NULL_LOGE_RETURN(rawMaterial, HKS_ERROR_MALLOC_FAIL, "ml-dsa key malloc failed")

    struct HksKeyMaterialMlDsa *keyMaterial = (struct HksKeyMaterialMlDsa *)rawMaterial;
    keyMaterial->keyAlg = HKS_ALG_ML_DSA;
    keyMaterial->keyParamSet = paramSetId;
    keyMaterial->pubKeySize = pubKeySize;
    keyMaterial->priKeySize = priKeySize;

    uint32_t offset = sizeof(*keyMaterial);
    int32_t ret = HKS_OPENSSL_SUCCESS;
    do {
        size_t pubSize = pubKeySize;
        ret = EVP_PKEY_get_raw_public_key(pkey, rawMaterial + offset, &pubSize);
        if (ret != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("get ml-dsa pub key failed, ret = 0x%x", ret);
            HksLogOpensslError();
            break;
        }

        size_t priSize = priKeySize;
        offset += keyMaterial->pubKeySize;
        ret = EVP_PKEY_get_raw_private_key(pkey, rawMaterial + offset, &priSize);
        if (ret != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("get ml-dsa pri key failed, ret = 0x%x", ret);
            HksLogOpensslError();
            break;
        }
    } while (0);

    if (ret != HKS_OPENSSL_SUCCESS) {
        (void)memset_s(rawMaterial, rawMaterialLen, 0, rawMaterialLen);
        HKS_FREE(rawMaterial);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    key->data = rawMaterial;
    key->size = sizeof(struct HksKeyMaterialMlDsa) + keyMaterial->pubKeySize + keyMaterial->priKeySize;

    return HKS_SUCCESS;
}

int32_t HksOpensslMlDsaGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    uint32_t alg = 0;
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_validMlDsaParam); i++) {
        if (g_validMlDsaParam[i].paramSetId == spec->keyLen) {
            alg = g_validMlDsaParam[i].alg;
        }
    }
    HKS_IF_TRUE_LOGE_RETURN(alg == 0, HKS_ERROR_INVALID_KEY_SIZE, "get ml-dsa alg failed");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(alg, NULL);
    if (ctx == NULL) {
        HKS_LOG_E("failed to create context");
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    EVP_PKEY *pkey = NULL;
    do {
        if (EVP_PKEY_keygen_init(ctx) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("failed to initialize context");
            HksLogOpensslError();
            break;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("failed to generate evp key");
            HksLogOpensslError();
            break;
        }

        ret = MlDsaGetKeyMaterial(pkey, spec->keyLen, key);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("ml-dsa generate key: MlDsaGetKeyMaterial failed ret = %d", ret);
        }
    } while (0);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}
#endif

#ifdef HKS_SUPPORT_ML_DSA_GET_PUBLIC_KEY
int32_t HksOpensslMlDsaGetPubKey(const struct HksBlob *keyIn, struct HksBlob *keyOut)
{
    HKS_IF_TRUE_LOGE_RETURN(keyIn->size < sizeof(struct HksKeyMaterialMlDsa), HKS_ERROR_INVALID_ARGUMENT,
        "invalid keyIn size %" LOG_PUBLIC "u", keyIn->size)
    struct HksKeyMaterialMlDsa *keyMaterial = (struct HksKeyMaterialMlDsa *)keyIn->data;
    if (keyMaterial->pubKeySize == 0 || keyOut->size < sizeof(struct HksKeyMaterialMlDsa)) {
        HKS_LOG_E("get ml-dsa public key size or output size invalid");
        return HKS_ERROR_INVALID_ALGORITHM;
    }

    struct HksKeyMaterialMlDsa *publickeyMaterial = (struct HksKeyMaterialMlDsa *)keyOut->data;
    publickeyMaterial->keyAlg = keyMaterial->keyAlg;
    publickeyMaterial->keyParamSet = keyMaterial->keyParamSet;
    publickeyMaterial->pubKeySize = keyMaterial->pubKeySize;
    publickeyMaterial->priKeySize = 0;
    publickeyMaterial->reserved = 0;

    if (memcpy_s(keyOut->data + sizeof(struct HksKeyMaterialMlDsa), keyOut->size - sizeof(struct HksKeyMaterialMlDsa),
        keyIn->data + sizeof(struct HksKeyMaterialMlDsa), keyMaterial->pubKeySize) != EOK) {
        HKS_LOG_E("copy ml-dsa public key fail");
        return HKS_ERROR_INVALID_OPERATION;
    }

    keyOut->size = sizeof(struct HksKeyMaterialMlDsa) + keyMaterial->pubKeySize;
    return HKS_SUCCESS;
}
#endif

#ifdef HKS_SUPPORT_ML_DSA_SIGN_VERIFY
static int32_t MlDsaSignVerifyInitCtx(const struct HksBlob *key, const struct HksUsageSpec *usageSpec, EVP_PKEY **pkey)
{
    HKS_IF_TRUE_LOGE_RETURN(key->size < sizeof(struct HksKeyMaterialMlDsa), HKS_ERROR_INVALID_ARGUMENT,
        "invalid key size %" LOG_PUBLIC "u", key->size)
    struct HksKeyMaterialMlDsa *keyMaterial = (struct HksKeyMaterialMlDsa *)key->data;
    uint32_t alg = 0;
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_validMlDsaParam); i++) {
        if (g_validMlDsaParam[i].paramSetId == keyMaterial->keyParamSet) {
            alg = g_validMlDsaParam[i].alg;
        }
    }
    HKS_IF_TRUE_LOGE_RETURN(alg == 0, HKS_ERROR_INVALID_KEY_SIZE, "get ml-dsa alg failed");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(alg, NULL);
    if (ctx == NULL) {
        HKS_LOG_E("failed to create ml-dsa ctx");
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    int32_t ret = EVP_PKEY_fromdata_init(ctx);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("failed to initialize ml-dsa ctx");
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    uint32_t offset = sizeof(struct HksKeyMaterialMlDsa);
    OSSL_PARAM params[ML_DSA_KEY_NUM];
    uint32_t index = 0;
    params[index++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
        key->data + offset, keyMaterial->pubKeySize);
    offset += keyMaterial->pubKeySize;
    if (keyMaterial->priKeySize != 0) {
        params[index++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
            key->data + offset, keyMaterial->priKeySize);
    }

    struct HksBlob *context = (struct HksBlob *)usageSpec->algParam;
    params[index++] = OSSL_PARAM_construct_octet_string(ML_DSA_CONTEXT, context->data, context->size);
    params[index++] = OSSL_PARAM_construct_end();
    
    ret = EVP_PKEY_fromdata(ctx, pkey, (keyMaterial->priKeySize == 0) ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, params);
    if (ret != HKS_OPENSSL_SUCCESS) {
        HKS_LOG_E("failed to create key from data");
        HksLogOpensslError();
        EVP_PKEY_CTX_free(ctx);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    EVP_PKEY_CTX_free(ctx);
    return HKS_SUCCESS;
}

int32_t HksOpensslMlDsaSign(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, struct HksBlob *signature)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdCtx = NULL;
    int32_t ret = HKS_SUCCESS;
    do {
        ret = MlDsaSignVerifyInitCtx(key, usageSpec, &pkey);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("failed to init sign/verify ctx");
            HksLogOpensslError();
            break;
        }

        mdCtx = EVP_MD_CTX_new();
        if (mdCtx == NULL) {
            HKS_LOG_E("failed to create ml-dsa md ctx");
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        if (EVP_DigestSignInit(mdCtx, NULL, NULL, NULL, pkey) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("evp ml-dsa signature init failed");
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        size_t outSize = signature->size;
        if (EVP_DigestSign(mdCtx, signature->data, &outSize, message->data, message->size) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("evp ml-dsa signature failed");
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        signature->size = (uint32_t)outSize;
    } while (0);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdCtx);
    return ret;
}

int32_t HksOpensslMlDsaVerify(const struct HksBlob *key, const struct HksUsageSpec *usageSpec,
    const struct HksBlob *message, const struct HksBlob *signature)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdCtx = NULL;
    int32_t ret = HKS_SUCCESS;
    do {
        ret = MlDsaSignVerifyInitCtx(key, usageSpec, &pkey);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("failed to init sign/verify ctx");
            HksLogOpensslError();
            break;
        }

        mdCtx = EVP_MD_CTX_new();
        if (mdCtx == NULL) {
            HKS_LOG_E("failed to create ml-dsa md ctx");
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        if (EVP_DigestVerifyInit(mdCtx, NULL, NULL, NULL, pkey) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("evp ml-dsa verification init failed");
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        if (EVP_DigestVerify(mdCtx, signature->data, signature->size, message->data,
            message->size) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("evp ml-dsa verification failed");
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
        }
    } while (0);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdCtx);
    return ret;
}
#endif //HKS_SUPPORT_ML_DSA_SIGN_VERIFY

#endif // HKS_SUPPORT_ML_DSA_C
