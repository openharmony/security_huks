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

#ifdef HKS_SUPPORT_ML_KEM_C
#include "securec.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include "hks_openssl_engine.h"
#include "hks_openssl_ml_kem.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_openssl_mlkem.h"

static int32_t GetMlKemKeySizes(uint32_t paramSetId, uint32_t *pubKeySize, uint32_t *priKeySize)
{
    if (paramSetId == HKS_ML_KEM_KEY_PARAM_SET_768) {
        *pubKeySize = HKS_ML_KEM_PUB_KEY_SIZE_1184;
        *priKeySize = HKS_ML_KEM_PRI_KEY_SIZE_2400;
        return HKS_SUCCESS;
    } else if (paramSetId == HKS_ML_KEM_KEY_PARAM_SET_1024) {
        *pubKeySize = HKS_ML_KEM_PUB_KEY_SIZE_1568;
        *priKeySize = HKS_ML_KEM_PRI_KEY_SIZE_3168;
        return HKS_SUCCESS;
    }
    return HKS_ERROR_INVALID_KEY_SIZE;
}

#ifdef HKS_SUPPORT_ML_KEM_GENERATE_KEY
static int32_t MlKemGetKeyMaterial(EVP_PKEY *pkey, uint32_t paramSetId, struct HksBlob *key)
{
    uint32_t pubKeySize = 0;
    uint32_t priKeySize = 0;
    int32_t ret = GetMlKemKeySizes(paramSetId, &pubKeySize, &priKeySize);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get ml-kem key sizes failed")

    const uint32_t rawMaterialLen = sizeof(struct HksKeyMaterialMlKem) + pubKeySize + priKeySize;
    uint8_t *rawMaterial = (uint8_t *)HksMalloc(rawMaterialLen);
    HKS_IF_NULL_LOGE_RETURN(rawMaterial, HKS_ERROR_MALLOC_FAIL, "ml-kem key malloc failed")

    struct HksKeyMaterialMlKem *keyMaterial = (struct HksKeyMaterialMlKem *)rawMaterial;
    keyMaterial->keyAlg = HKS_ALG_ML_KEM;
    keyMaterial->keyParamSet = paramSetId;
    keyMaterial->pubKeySize = pubKeySize;
    keyMaterial->priKeySize = priKeySize;

    uint32_t offset = sizeof(*keyMaterial);
    ret = HKS_SUCCESS;
    do {
        size_t pubData = pubKeySize;
        if (EVP_PKEY_get_raw_public_key(pkey, rawMaterial + offset, &pubData) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("get ml-kem pub key failed");
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }

        offset += keyMaterial->pubKeySize;
        size_t priData = priKeySize;
        if (EVP_PKEY_get_raw_private_key(pkey, rawMaterial + offset, &priData) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("get ml-kem pri key failed");
            HksLogOpensslError();
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
    } while (0);

    if (ret != HKS_SUCCESS) {
        (void)memset_s(rawMaterial, rawMaterialLen, 0, rawMaterialLen);
        HKS_FREE(rawMaterial);
        return ret;
    }

    key->data = rawMaterial;
    key->size = rawMaterialLen;
    return HKS_SUCCESS;
}

int32_t HksOpensslMlKemGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    const char *algName = HksOpensslMlKemGetAlgName(spec->keyLen);
    HKS_IF_NULL_LOGE_RETURN(algName, HKS_ERROR_INVALID_KEY_SIZE, "get ml-kem alg name failed");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algName, NULL);
    HKS_IF_NULL_LOGE_RETURN(ctx, HKS_ERROR_CRYPTO_ENGINE_ERROR, "create ml-kem context failed")

    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    EVP_PKEY *pkey = NULL;
    do {
        if (EVP_PKEY_keygen_init(ctx) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("initialize ml-kem context failed");
            HksLogOpensslError();
            break;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("generate ml-kem key failed");
            HksLogOpensslError();
            break;
        }

        ret = MlKemGetKeyMaterial(pkey, spec->keyLen, key);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "extract ml-kem key material failed ret = %d", ret)
    } while (0);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}
#endif

#ifdef HKS_SUPPORT_ML_KEM_GET_PUBLIC_KEY
int32_t HksOpensslMlKemGetPubKey(const struct HksBlob *keyIn, struct HksBlob *keyOut)
{
    HKS_IF_TRUE_LOGE_RETURN(keyIn->size < sizeof(struct HksKeyMaterialMlKem), HKS_ERROR_INVALID_ARGUMENT,
        "invalid keyIn size %" LOG_PUBLIC "u", keyIn->size)
    struct HksKeyMaterialMlKem *keyMaterial = (struct HksKeyMaterialMlKem *)keyIn->data;
    if (keyMaterial->pubKeySize == 0 || keyOut->size < sizeof(struct HksKeyMaterialMlKem)) {
        HKS_LOG_E("get ml-kem public key size or output size invalid");
        return HKS_ERROR_INVALID_ALGORITHM;
    }

    struct HksKeyMaterialMlKem *publickeyMaterial = (struct HksKeyMaterialMlKem *)keyOut->data;
    publickeyMaterial->keyAlg = keyMaterial->keyAlg;
    publickeyMaterial->keyParamSet = keyMaterial->keyParamSet;
    publickeyMaterial->pubKeySize = keyMaterial->pubKeySize;
    publickeyMaterial->priKeySize = 0;
    publickeyMaterial->reserved = 0;

    if (memcpy_s(keyOut->data + sizeof(struct HksKeyMaterialMlKem),
        keyOut->size - sizeof(struct HksKeyMaterialMlKem),
        keyIn->data + sizeof(struct HksKeyMaterialMlKem),
        keyMaterial->pubKeySize) != EOK) {
        HKS_LOG_E("copy ml-kem public key fail");
        return HKS_ERROR_INVALID_OPERATION;
    }

    keyOut->size = sizeof(struct HksKeyMaterialMlKem) + keyMaterial->pubKeySize;
    return HKS_SUCCESS;
}
#endif

#endif // HKS_SUPPORT_ML_KEM_C