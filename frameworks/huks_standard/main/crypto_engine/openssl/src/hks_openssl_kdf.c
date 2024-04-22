/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "hks_openssl_kdf.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ossl_typ.h>
#include <stddef.h>

#include "hks_crypto_hal.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_openssl_engine.h"
#include "hks_openssl_hash.h"
#include "hks_template.h"
#include "securec.h"

#ifdef HKS_SUPPORT_KDF_SM3
#define HKS_DIGEST_SM3_LEN 32
#define HKS_BITS_PER_INT 32
#define HKS_BYTE_PER_INT 4
#define HKS_START_NUM 1
#endif
static const EVP_MD *GetDeriveDigestType(uint32_t digestAlg)
{
    switch (digestAlg) {
        case (HKS_DIGEST_SHA256):
            return EVP_sha256();
        case (HKS_DIGEST_SHA384):
            return EVP_sha384();
        case (HKS_DIGEST_SHA512):
            return EVP_sha512();
        default:
            return NULL;
    }
}

int32_t HksOpensslPbkdf2(const struct HksBlob *mainKey, const struct HksKeySpec *derivationSpec,
    struct HksBlob *derivedKey)
{
    struct HksKeyDerivationParam *deriveParam = (struct HksKeyDerivationParam *)derivationSpec->algParam;
    const EVP_MD *md = GetDeriveDigestType(deriveParam->digestAlg);
    if (PKCS5_PBKDF2_HMAC((char *)mainKey->data, mainKey->size, deriveParam->salt.data, deriveParam->salt.size,
        deriveParam->iterations, md, derivedKey->size, derivedKey->data) != 1) {
        HKS_LOG_E("derive pbkdf2 key using openssl interface failed");
        return HKS_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return HKS_SUCCESS;
}

int32_t HksOpensslHkdf(const struct HksBlob *mainKey, const struct HksKeySpec *derivationSpec,
    struct HksBlob *derivedKey)
{
    struct HksKeyDerivationParam *deriveParam = (struct HksKeyDerivationParam *)derivationSpec->algParam;
    const EVP_MD *md = GetDeriveDigestType(deriveParam->digestAlg);
    EVP_PKEY_CTX *pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    int32_t ret = HKS_ERROR_CRYPTO_ENGINE_ERROR;
    do {
        if (EVP_PKEY_derive_init(pctx) <= 0) {
            HksLogOpensslError();
            break;
        }
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0) {
            HksLogOpensslError();
            break;
        }
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, deriveParam->salt.data, deriveParam->salt.size) <= 0) {
            HksLogOpensslError();
            break;
        }
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, mainKey->data, mainKey->size) <= 0) {
            HksLogOpensslError();
            break;
        }
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, deriveParam->info.data, deriveParam->info.size) <= 0) {
            HksLogOpensslError();
            break;
        }
        size_t keyLen = derivedKey->size;
        if (EVP_PKEY_derive(pctx, derivedKey->data, &keyLen) <= 0) {
            HksLogOpensslError();
            break;
        }
        derivedKey->size = (uint32_t)keyLen;
        ret = HKS_SUCCESS;
    } while (0);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

#ifdef HKS_SUPPORT_KDF_SM3

static int32_t AppendKekAndFactor(const struct HksBlob *kekData, const struct HksBlob *factor,
    struct HksBlob *appendedData)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksOpensslCheckBlob(factor), HKS_ERROR_INVALID_ARGUMENT, "Invalid param mainKey!");
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksOpensslCheckBlob(kekData), HKS_ERROR_INVALID_ARGUMENT, "Invalid param derivedKey!");
    struct HksBlob destData = {0, NULL};
    destData.size = kekData->size + factor->size;
    destData.data = (uint8_t *)HksMalloc(destData.size);
    HKS_IF_NULL_LOGE_RETURN(destData.data, HKS_ERROR_MALLOC_FAIL, "malloc destData memory failed!");
    (void)memcpy_s(destData.data, destData.size, kekData->data, kekData->size);
    (void)memcpy_s(destData.data + kekData->size, destData.size - kekData->size, factor->data, factor->size);
    appendedData->size = destData.size;
    appendedData->data = destData.data;
    return HKS_SUCCESS;
}

int32_t HksOpensslSmKdf(const struct HksBlob *mainKey, const struct HksKeySpec *derivationSpec,
    struct HksBlob *derivedKey)
{
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksOpensslCheckBlob(mainKey), HKS_ERROR_INVALID_ARGUMENT, "Invalid param mainKey!");
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksOpensslCheckBlob(derivedKey),
        HKS_ERROR_INVALID_ARGUMENT, "Invalid param derivedKey!");
    struct HksKeyDerivationParam *deriveParam = (struct HksKeyDerivationParam *)derivationSpec->algParam;
    struct HksBlob appendedKeyData = { 0, NULL };
    int32_t ret = AppendKekAndFactor(mainKey, &deriveParam->info, &appendedKeyData);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT, "append data failed!")
    unsigned int hashSize = appendedKeyData.size + HKS_BYTE_PER_INT;
    struct HksBlob inputHashBlob = { 0, NULL };
    inputHashBlob.size = hashSize;
    inputHashBlob.data = (uint8_t *)HksMalloc(inputHashBlob.size);
    if (inputHashBlob.data == NULL) {
        HKS_FREE(appendedKeyData.data);
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(inputHashBlob.data, inputHashBlob.size, appendedKeyData.data, appendedKeyData.size);

    uint8_t digestDataArray[HKS_DIGEST_SM3_LEN] = { 0 };
    unsigned int digestLength = HKS_DIGEST_SM3_LEN;
    struct HksBlob cdgstBlob = {digestLength, digestDataArray};
    unsigned int index = (derivedKey->size - 1) / HKS_DIGEST_SM3_LEN + 1; // round up
    unsigned char counterBytes[HKS_BYTE_PER_INT] = { 0 };
    unsigned int counter = HKS_START_NUM;
    for (unsigned int i = 0; i < index; i++) {
        for (unsigned int j = HKS_START_NUM; j <= HKS_BYTE_PER_INT; j++) {
            counterBytes[j - 1] = (counter >> (HKS_BITS_PER_INT - HKS_BITS_PER_BYTE * j)) & 0xFF;
        }
        (void)memcpy_s(inputHashBlob.data + appendedKeyData.size, HKS_BYTE_PER_INT,
            counterBytes, HKS_BYTE_PER_INT);
        if (HksOpensslHash(HKS_DIGEST_SM3, &inputHashBlob, &cdgstBlob) != HKS_SUCCESS) {
            HKS_LOG_E("Hash data failed.");
            HKS_FREE_BLOB(appendedKeyData);
            HKS_FREE_BLOB(inputHashBlob);
            return HKS_ERROR_CRYPTO_ENGINE_ERROR;
        }
        if ((i == (index - 1)) && (derivedKey->size % HKS_DIGEST_SM3_LEN != 0)) {
            digestLength = (derivedKey->size) % HKS_DIGEST_SM3_LEN;
        }
        (void)memcpy_s(derivedKey->data + HKS_DIGEST_SM3_LEN * i, digestLength, cdgstBlob.data, digestLength);
        counter++;
    }
    HKS_FREE_BLOB(appendedKeyData);
    HKS_FREE_BLOB(inputHashBlob);
    HKS_LOG_I("HksOpensslSmKdf success.");
    return HKS_SUCCESS;
}
#endif /* HKS_SUPPORT_KDF_SM3 */
