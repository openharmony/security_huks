/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#include "hks_chipset_platform_key.h"

#include "hks_chipset_platform_decrypt.h"
#include "hks_crypto_hal.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"

#include "securec.h"

static const uint8_t PLATFORM_KEY_PLATFORM_PRI_KEY[PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE] = {
    0xF1, 0xDB, 0x27, 0xE9, 0xD8, 0x3A, 0xB6, 0x3F, 0xD6, 0x65, 0x1B, 0x2E, 0xC6, 0x2F, 0x67, 0x60,
    0xE7, 0x90, 0x67, 0x47, 0x8A, 0xA3, 0x03, 0x06, 0x1F, 0x5F, 0xC9, 0x32, 0x4B, 0xA4, 0x9A, 0x50,
};

static const uint8_t PLATFORM_KEY_PLATFORM_PUB_KEY[PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE] = {
    0x28, 0x22, 0xFE, 0xDC, 0xCF, 0x23, 0x14, 0x19, 0x16, 0xA6, 0xBE, 0x98, 0x1D, 0x7A, 0x11, 0x19,
    0x25, 0xAA, 0xBC, 0xCF, 0x01, 0x97, 0x93, 0x33, 0xB5, 0x86, 0x6C, 0xB7, 0xE6, 0x09, 0x9A, 0x93,
    0xB9, 0x46, 0xD5, 0xBB, 0x6B, 0x8E, 0x03, 0x53, 0xC0, 0xA6, 0x2D, 0x99, 0x3D, 0x5A, 0x10, 0xCF,
    0x8D, 0x8A, 0xEC, 0x9C, 0x39, 0xFE, 0xD5, 0x84, 0x37, 0xE7, 0x44, 0x0C, 0xF4, 0xFC, 0xAD, 0xB2,
};

enum {
    FULL_PLATFORM_PUBLIC_KEY_SIZE = sizeof(struct KeyMaterialEcc) + PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE,
    FULL_PLATFORM_PRIVATE_KEY_SIZE = FULL_PLATFORM_PUBLIC_KEY_SIZE + PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE,
};

// Notice: you MUST call HKS_FREE_BLOB after using fullHksPubKey
static int32_t MallocAndFillFullHksPublicKey(const struct HksBlob *rawPubKey, struct HksBlob *fullHksPubKey)
{
    struct KeyMaterialEcc publicKeyMaterial = {
        .keyAlg = HKS_ALG_ECC,
        .keySize = PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE * HKS_BITS_PER_BYTE,
        .xSize = PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE,
        .ySize = PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE,
        .zSize = 0,
    };

    fullHksPubKey->data = (uint8_t *)HksMalloc(FULL_PLATFORM_PUBLIC_KEY_SIZE);
    HKS_IF_NULL_LOGE_RETURN(fullHksPubKey->data, HKS_ERROR_MALLOC_FAIL, "malloc full hks public key failed")
    fullHksPubKey->size = FULL_PLATFORM_PUBLIC_KEY_SIZE;
    int32_t ret;
    do {
        ret = memcpy_s(fullHksPubKey->data, fullHksPubKey->size,
            &publicKeyMaterial, sizeof(publicKeyMaterial));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy public key material failed")
        ret = memcpy_s(fullHksPubKey->data + sizeof(publicKeyMaterial),
            fullHksPubKey->size - sizeof(publicKeyMaterial),
            rawPubKey->data, rawPubKey->size);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy raw public key failed")
        return HKS_SUCCESS;
    } while (false);
    (void)memset_s(fullHksPubKey->data, FULL_PLATFORM_PUBLIC_KEY_SIZE, 0, FULL_PLATFORM_PUBLIC_KEY_SIZE);
    HKS_FREE_BLOB(*fullHksPubKey);
    return HKS_ERROR_INTERNAL_ERROR;
}

/**
 * malloc a new blob and fill with full platform private key
 * Notice: you MUST free the blob data after using
 */
static int32_t MallocFullPlatformPrivateKey(struct HksBlob *privateKey)
{
    struct KeyMaterialEcc privateKeyMaterial = {
        .keyAlg = HKS_ALG_ECC,
        .keySize = PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE * HKS_BITS_PER_BYTE,
        .xSize = PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE,
        .ySize = PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE,
        .zSize = PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE,
    };
    privateKey->data = (uint8_t *)HksMalloc(FULL_PLATFORM_PRIVATE_KEY_SIZE);
    HKS_IF_NULL_LOGE_RETURN(privateKey->data, HKS_ERROR_MALLOC_FAIL, "malloc private key failed")
    privateKey->size = FULL_PLATFORM_PRIVATE_KEY_SIZE;
    do {
        int32_t ret = memcpy_s(privateKey->data, privateKey->size, &privateKeyMaterial, sizeof(privateKeyMaterial));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy private key material failed")
        ret = memcpy_s(privateKey->data + sizeof(privateKeyMaterial), privateKey->size - sizeof(privateKeyMaterial),
            PLATFORM_KEY_PLATFORM_PUB_KEY, PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy public key failed")
        ret = memcpy_s(privateKey->data + sizeof(privateKeyMaterial) + PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE,
            privateKey->size - sizeof(privateKeyMaterial) - PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE,
            PLATFORM_KEY_PLATFORM_PRI_KEY, PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "copy private key failed")
        return HKS_SUCCESS;
    } while (false);
    (void)(memset_s(privateKey->data, FULL_PLATFORM_PRIVATE_KEY_SIZE, 0, FULL_PLATFORM_PRIVATE_KEY_SIZE));
    HKS_FREE_BLOB(*privateKey);
    return HKS_ERROR_INTERNAL_ERROR;
}

int32_t HksChipsetPlatformDeriveKeyAndEcdh(const struct HksBlob *peerPk, const struct HksBlob *salt,
    struct HksBlob *sharedKey)
{
    // salt is ignored in the hardcoded key implementation,
    // and it SHOULD be used in true hardware based implementations.
    (void)(salt);
    struct HksKeySpec ecdhSpec = {
        .algType = HKS_ALG_ECDH,
        .keyLen = HKS_ECC_KEY_SIZE_256,
        .algParam = NULL,
    };
    struct HksBlob platformPrivateKey = { .size = 0, .data = NULL };
    struct HksBlob peerHksPubKey = { .size = 0, .data = NULL };
    int32_t ret = MallocFullPlatformPrivateKey(&platformPrivateKey);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "malloc full platform private key failed")
    do {
        ret = MallocAndFillFullHksPublicKey(peerPk, &peerHksPubKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "malloc or fill full hks pub key failed");

        HKS_LOG_I("DoGenEcdhSharedKey hal start");
        ret = HksCryptoHalAgreeKey(&platformPrivateKey, &peerHksPubKey, &ecdhSpec, sharedKey);
        HKS_LOG_I("DoGenEcdhSharedKey hal end");
    } while (false);
    (void)(memset_s(peerHksPubKey.data, peerHksPubKey.size, 0, peerHksPubKey.size));
    (void)(memset_s(platformPrivateKey.data, platformPrivateKey.size, 0, platformPrivateKey.size));
    HKS_FREE_BLOB(peerHksPubKey);
    HKS_FREE_BLOB(platformPrivateKey);
    return ret;
}

int32_t HksChipsetPlatformDerivePubKey(const struct HksBlob *salt, struct HksBlob *pubKey)
{
    // salt is ignored in the hardcoded key implementation,
    // and it SHOULD be used in true hardware based implementations.
    (void)(salt);
    if (CheckBlob(pubKey) != HKS_SUCCESS || pubKey->size != PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE) {
        HKS_LOG_E("invalid out param pub key");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    (void)memcpy_s(pubKey->data, PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE,
        PLATFORM_KEY_PLATFORM_PUB_KEY, PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE);
    return HKS_SUCCESS;
}
