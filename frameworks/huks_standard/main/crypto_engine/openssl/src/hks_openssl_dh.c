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

#ifdef HKS_SUPPORT_DH_C

#include "hks_openssl_dh.h"

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <stdbool.h>
#include <stddef.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_openssl_engine.h"
#include "hks_template.h"
#include "securec.h"

static int32_t HksOpensslGetNid(uint32_t keySize, int *nid)
{
    switch (keySize) {
        case HKS_DH_KEY_SIZE_2048:
            *nid = NID_ffdhe2048;
            return HKS_SUCCESS;
        case HKS_DH_KEY_SIZE_3072:
            *nid = NID_ffdhe3072;
            return HKS_SUCCESS;
        case HKS_DH_KEY_SIZE_4096:
            *nid = NID_ffdhe4096;
            return HKS_SUCCESS;
        default:
            HKS_LOG_E("invalid key size, keySize = %" LOG_PUBLIC "u", keySize);
            return HKS_ERROR_INVALID_KEY_SIZE;
    }
}

static void HksFreeBigNum(BIGNUM *numOne, BIGNUM *numTwo, BIGNUM *numThree)
{
    if (numOne != NULL) {
        BN_free(numOne);
    }
    if (numTwo != NULL) {
        BN_free(numTwo);
    }
    if (numThree != NULL) {
        BN_free(numThree);
    }
}

static DH *InitDhStruct(const struct HksBlob *key)
{
    const struct KeyMaterialDh *keyMaterial = (struct KeyMaterialDh *)(key->data);
    if (key->size != sizeof(struct KeyMaterialDh) + keyMaterial->pubKeySize + keyMaterial->priKeySize) {
        return NULL;
    }

    int nid = 0;
    int32_t ret = HksOpensslGetNid(keyMaterial->keySize, &nid);
    HKS_IF_NOT_SUCC_RETURN(ret, NULL)

    DH *dh = DH_new_by_nid(nid);
    if (dh == NULL) {
        HksLogOpensslError();
        return NULL;
    }

    uint32_t offset = sizeof(struct KeyMaterialDh);
    BIGNUM *pubKey = BN_bin2bn(key->data + offset, keyMaterial->pubKeySize, NULL);
    offset += keyMaterial->pubKeySize;
    BIGNUM *privKey = BN_bin2bn(key->data + offset, keyMaterial->priKeySize, NULL);

    if (DH_set0_key(dh, pubKey, privKey) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        DH_free(dh);
        return NULL;
    }

    return dh;
}

static DH *InitDhPubStruct(const struct HksBlob *key)
{
    const struct KeyMaterialDh *keyMaterial = (struct KeyMaterialDh *)(key->data);

    int nid = 0;
    int32_t ret = HksOpensslGetNid(keyMaterial->keySize, &nid);
    HKS_IF_NOT_SUCC_RETURN(ret, NULL)

    DH *dh = DH_new_by_nid(nid);
    if (dh == NULL) {
        HksLogOpensslError();
        return NULL;
    }

    uint32_t offset = sizeof(struct KeyMaterialDh);
    BIGNUM *pubKey = BN_bin2bn(key->data + offset, keyMaterial->pubKeySize, NULL);

    if (DH_set0_key(dh, pubKey, NULL) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        DH_free(dh);
        return NULL;
    }

    return dh;
}

#ifdef HKS_SUPPORT_DH_GENERATE_KEY
static int32_t DhSaveKeyMaterial(const DH *dh, const uint32_t keySize, struct HksBlob *key)
{
    const BIGNUM *pubKey = NULL;
    const BIGNUM *privKey = NULL;
    DH_get0_key(dh, &pubKey, &privKey);
    const uint32_t rawMaterialLen = sizeof(struct KeyMaterialDh) + (uint32_t)BN_num_bytes(pubKey)
        + (uint32_t)BN_num_bytes(privKey);
    uint8_t *rawMaterial = (uint8_t *)HksMalloc(rawMaterialLen);
    HKS_IF_NULL_RETURN(rawMaterial, HKS_ERROR_MALLOC_FAIL)

    (void)memset_s(rawMaterial, rawMaterialLen, 0, rawMaterialLen);

    struct KeyMaterialDh *keyMaterial = (struct KeyMaterialDh *)rawMaterial;
    keyMaterial->keyAlg = HKS_ALG_DH;
    keyMaterial->keySize = keySize;
    keyMaterial->pubKeySize = (uint32_t)BN_num_bytes(pubKey);
    keyMaterial->priKeySize = (uint32_t)BN_num_bytes(privKey);
    keyMaterial->reserved = 0;

    uint32_t offset = sizeof(struct KeyMaterialDh);
    BN_bn2bin(pubKey, rawMaterial + offset);
    offset += keyMaterial->pubKeySize;
    BN_bn2bin(privKey, rawMaterial + offset);

    key->size = rawMaterialLen;
    key->data = rawMaterial;

    return HKS_SUCCESS;
}

int32_t HksOpensslDhGenerateKey(const struct HksKeySpec *spec, struct HksBlob *key)
{
    int32_t ret;
    int nid = 0;
    ret = HksOpensslGetNid(spec->keyLen, &nid);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    DH *dh = DH_new_by_nid(nid);
    if (dh == NULL) {
        HksLogOpensslError();
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    if (DH_generate_key(dh) != HKS_OPENSSL_SUCCESS) {
        HksLogOpensslError();
        DH_free(dh);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = DhSaveKeyMaterial(dh, spec->keyLen, key);

    DH_free(dh);

    return ret;
}
#endif /* HKS_SUPPORT_DH_GENERATE_KEY */

#ifdef HKS_SUPPORT_DH_GET_PUBLIC_KEY
int32_t HksOpensslGetDhPubKey(const struct HksBlob *input, struct HksBlob *output)
{
    struct KeyMaterialDh *keyMaterial = (struct KeyMaterialDh *)input->data;
    if (input->size < sizeof(struct KeyMaterialDh) + keyMaterial->pubKeySize) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (output->size < sizeof(struct KeyMaterialDh) + keyMaterial->pubKeySize) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (memcpy_s(output->data, output->size, input->data, sizeof(struct KeyMaterialDh) +
        keyMaterial->pubKeySize) != EOK) {
        HKS_LOG_E("copy output data failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    ((struct KeyMaterialDh *)output->data)->priKeySize = 0;
    ((struct KeyMaterialDh *)output->data)->reserved = 0;
    output->size = sizeof(struct KeyMaterialDh) + keyMaterial->pubKeySize;

    return HKS_SUCCESS;
}
#endif /* HKS_SUPPORT_DH_GET_PUBLIC_KEY */

#ifdef HKS_SUPPORT_DH_AGREE_KEY
static int32_t HksOpensslDhCheckPubKey(const struct HksBlob *nativeKey, DH *dh)
{
    int32_t ret = HKS_ERROR_INVALID_KEY_INFO;
    struct KeyMaterialDh *pubKeyMaterial = (struct KeyMaterialDh *)nativeKey->data;
    BIGNUM *pub = BN_bin2bn(nativeKey->data + sizeof(struct KeyMaterialDh), pubKeyMaterial->pubKeySize, NULL);
    const BIGNUM *p = NULL;
    BIGNUM *one = BN_new();
    BIGNUM *r = BN_new();
    do {
        if (one == NULL || r == NULL || pub == NULL) {
            HKS_LOG_E("compute bignum fail");
            break;
        }
        if (BN_is_zero(pub) == HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("pub is not secure, pub equals 0");
            break;
        }
        if (BN_is_one(pub) == HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("pub is not secure, pub equals 1");
            break;
        }
        DH_get0_pqg((const DH *)dh, &p, NULL, NULL);
        if (BN_cmp(pub, p) == 0) {
            HKS_LOG_E("pub is not secure, pub equals p");
            break;
        }

        if (BN_one(one) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("set one fail");
            break;
        }
        if (BN_sub(r, p, one) != HKS_OPENSSL_SUCCESS) {
            HKS_LOG_E("compute p-1 fail");
            break;
        }
        if (BN_cmp(pub, r) == 0) {
            HKS_LOG_E("pub is not secure, pub equals p-1");
            break;
        }
        ret = HKS_SUCCESS;
    } while (0);

    HksFreeBigNum(one, r, pub);
    return ret;
}

int32_t HksOpensslCheckDhKey(const struct HksBlob *key, enum HksImportKeyType importKeyType)
{
    DH *dh = NULL;
    if (importKeyType == HKS_KEY_TYPE_KEY_PAIR) {
        dh = InitDhStruct(key);
    } else if (importKeyType == HKS_KEY_TYPE_PUBLIC_KEY) {
        dh = InitDhPubStruct(key);
    }
    if (dh == NULL) {
        HKS_LOG_E("Init dh struct fail");
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    int32_t ret = HksOpensslDhCheckPubKey(key, dh);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("dh public key is not secure");
    }
    DH_free(dh);
    return ret;
}

int32_t HksOpensslDhAgreeKey(const struct HksBlob *nativeKey, const struct HksBlob *pubKey,
    const struct HksKeySpec *spec, struct HksBlob *sharedKey)
{
    int32_t ret;
    if (HKS_KEY_BYTES(spec->keyLen) > sharedKey->size) {
        return HKS_ERROR_INVALID_KEY_SIZE;
    }

    struct KeyMaterialDh *pubKeyMaterial = (struct KeyMaterialDh *)pubKey->data;
    BIGNUM *pub = BN_bin2bn(pubKey->data + sizeof(struct KeyMaterialDh), pubKeyMaterial->pubKeySize, NULL);
    HKS_IF_NULL_RETURN(pub, HKS_ERROR_CRYPTO_ENGINE_ERROR)

    ret = HksOpensslCheckDhKey(pubKey, HKS_KEY_TYPE_PUBLIC_KEY);
    if (ret != HKS_SUCCESS) {
        BN_free(pub);
        return ret;
    }

    DH *dh = InitDhStruct(nativeKey);
    uint8_t *computeKey = HksMalloc(DH_size(dh));
    if (computeKey == NULL) {
        BN_free(pub);
        DH_free(dh);
        return HKS_ERROR_MALLOC_FAIL;
    }

    if (DH_compute_key_padded(computeKey, pub, dh) <= 0) {
        HksLogOpensslError();
        BN_free(pub);
        DH_free(dh);
        HKS_FREE(computeKey);
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }

    if (HKS_KEY_BYTES(spec->keyLen) > (uint32_t)DH_size(dh)) {
        ret = HKS_ERROR_INVALID_KEY_SIZE;
    } else {
        if (memcpy_s(sharedKey->data, sharedKey->size, computeKey, HKS_KEY_BYTES(spec->keyLen)) != EOK) {
            ret = HKS_ERROR_INSUFFICIENT_MEMORY;
        } else {
            HKS_LOG_I("get agreed key size %" LOG_PUBLIC "u", HKS_KEY_BYTES(spec->keyLen));
            sharedKey->size = HKS_KEY_BYTES(spec->keyLen);
            ret = HKS_SUCCESS;
        }
    }

    (void)memset_s(computeKey, DH_size(dh), 0, DH_size(dh));
    BN_free(pub);
    DH_free(dh);
    HKS_FREE(computeKey);
    return ret;
}
#endif /* HKS_SUPPORT_DH_AGREE_KEY */

#endif /* HKS_SUPPORT_DH_C */