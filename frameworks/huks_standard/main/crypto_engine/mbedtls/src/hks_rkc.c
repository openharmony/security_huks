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

#ifndef _CUT_AUTHENTICATE_

#include "hks_rkc.h"

#include "hks_crypto_hal.h"
#include "hks_get_udid.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_rkc_rw.h"
#include "hks_template.h"

/* the default initialized parameter of root key component */
const struct HksRkcInitParam g_hksRkcDefaultInitParam = {
    .rkVersion = HKS_RKC_VER,
    .mkVersion = HKS_MK_VER,
    .storageType = HKS_RKC_STORAGE_FILE_SYS,
    .rkcKsfAttr = { HKS_KSF_NUM, { "rinfo1_v2.data", "rinfo2_v2.data" } },
    .mkKsfAttr = { HKS_KSF_NUM, { "minfo1_v2.data", "minfo2_v2.data" } },
    .rmkIter = HKS_RKC_RMK_ITER,
    .rmkHashAlg = HKS_RKC_RMK_HMAC_SHA256,
    .mkEncryptAlg = HKS_RKC_MK_CRYPT_ALG_AES256_GCM,
};

/* the data of main key */
struct HksRkcMk g_hksRkcMk = { false, { 0, 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0, 0 }, {0} };

/* the additional data of main key. 'H', 'K', 'S', 'R', 'K', 'C', 'M', 'K' */
const uint8_t g_hksRkcMkAddData[HKS_RKC_MK_ADD_DATA_LEN] = { 0x48, 0x4B, 0x53, 0x52, 0x4B, 0x43, 0x4D, 0x4B };

static int32_t RkcReadAllKsf(int32_t *allKsfRet, struct HksRkcKsfData *allKsfData, uint32_t ksfCount,
    struct HksRkcKsfData **validKsfData, uint32_t *validKsfIndex)
{
    if (ksfCount > g_hksRkcCfg.ksfAttrRkc.num) {
        HKS_LOG_E("Invalid rkc ksf count!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    /* Read all ksf */
    bool someCaseSuccess = false;
    for (uint32_t i = 0; i < g_hksRkcCfg.ksfAttrRkc.num; ++i) {
        allKsfRet[i] = HksRkcReadKsf(g_hksRkcCfg.ksfAttrRkc.name[i], &(allKsfData[i]));
        if (allKsfRet[i] != HKS_SUCCESS) {
            continue;
        }

        /* the first valid ksf is found, save data and index */
        if (*validKsfData == NULL) {
            *validKsfData = &(allKsfData[i]);
            *validKsfIndex = i;
            someCaseSuccess = true;
        }
    }

    return (someCaseSuccess ? HKS_SUCCESS : HKS_ERROR_INVALID_KEY_FILE);
}

static int32_t MkReadAllKsf(int32_t *allKsfRet, struct HksKsfDataMk *allKsfData, uint32_t ksfCount,
    struct HksKsfDataMk **validKsfData, uint32_t *validKsfIndex)
{
    if (ksfCount > g_hksRkcCfg.ksfAttrMk.num) {
        HKS_LOG_E("Invalid mk ksf count!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    /* Read all ksf */
    bool someCaseSuccess = false;
    for (uint32_t i = 0; i < g_hksRkcCfg.ksfAttrMk.num; ++i) {
        allKsfRet[i] = HksMkReadKsf(g_hksRkcCfg.ksfAttrMk.name[i], &(allKsfData[i]));
        if (allKsfRet[i] != HKS_SUCCESS) {
            continue;
        }

        /* the first valid ksf is found, save data and index */
        if (*validKsfData == NULL) {
            *validKsfData = &(allKsfData[i]);
            *validKsfIndex = i;
            someCaseSuccess = true;
        }
    }

    return (someCaseSuccess ? HKS_SUCCESS : HKS_ERROR_INVALID_KEY_FILE);
}

static int32_t RkcRecoverRkTime(const struct HksRkcKsfData *ksfData)
{
    if (memcpy_s(&(g_hksRkcCfg.rkCreatedTime), sizeof(g_hksRkcCfg.rkCreatedTime),
        &(ksfData->rkCreatedTime), sizeof(ksfData->rkCreatedTime)) != EOK) {
        HKS_LOG_E("Memcpy rkCreatedTime failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    if (memcpy_s(&(g_hksRkcCfg.rkExpiredTime), sizeof(g_hksRkcCfg.rkExpiredTime),
        &(ksfData->rkExpiredTime), sizeof(ksfData->rkExpiredTime)) != EOK) {
        HKS_LOG_E("Memcpy rkExpiredTime failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    return HKS_SUCCESS;
}

static int32_t RkcGetFixedMaterial(struct HksBlob *material)
{
    /* consistent with the old hks */
    const uint8_t fixedMaterial[HKS_RKC_MATERIAL_LEN] = {
        0xB2, 0xA1, 0x0C, 0x73, 0x52, 0x73, 0x76, 0xA1,
        0x60, 0x62, 0x2E, 0x08, 0x52, 0x08, 0x2E, 0xA9,
        0x60, 0xBC, 0x2E, 0x73, 0x52, 0x0B, 0x0C, 0xBC,
        0xEE, 0x0A, 0x2E, 0x08, 0x52, 0x9C, 0x76, 0xA9
    };

    if (memcpy_s(material->data, material->size, fixedMaterial, HKS_RKC_MATERIAL_LEN) != EOK) {
        HKS_LOG_E("Memcpy fiexd material failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    return HKS_SUCCESS;
}

static int32_t RkcGetRmkRawKey(const struct HksRkcKsfData *ksfData, struct HksBlob *rawKey)
{
    uint8_t material3Data[HKS_RKC_MATERIAL_LEN] = {0};
    struct HksBlob material3 = { HKS_RKC_MATERIAL_LEN, material3Data };

    /* Get the fixed material */
    int32_t ret = RkcGetFixedMaterial(&material3);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Get fixed material failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* materials xor */
    for (uint32_t i = 0; i < HKS_RKC_MATERIAL_LEN; ++i) {
        rawKey->data[i] = ksfData->rkMaterial1[i] ^ ksfData->rkMaterial2[i] ^ material3.data[i];
    }

    /* append hardware UDID */
    ret = HksGetHardwareUdid(rawKey->data + HKS_RKC_MATERIAL_LEN, HKS_HARDWARE_UDID_LEN);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Get hardware udid failed! ret = 0x%" LOG_PUBLIC "X", ret)

    return HKS_SUCCESS;
}

static int32_t RkcGetRmkRawKeyV2(const struct HksKsfDataRkc *ksfDataRkc, struct HksBlob *rawKey)
{
    uint8_t udid[HKS_HARDWARE_UDID_LEN] = {0};
    ret = HksGetHardwareUdid(&udid, HKS_HARDWARE_UDID_LEN);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Get hardware udid failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* materials xor */
    for (uint32_t i = 0; i < HKS_RKC_MATERIAL_LEN; ++i) {
        rawKey->data[i] = ksfData->rkMaterial1[i] ^ ksfData->rkMaterial2[i] ^ udid[i];
    }

    return HKS_SUCCESS;
}

static uint32_t RkcDigestToHks(const uint32_t rkcDigest)
{
    if (rkcDigest == HKS_RKC_RMK_HMAC_SHA256) {
        return HKS_DIGEST_SHA256;
    }

    /* if digest is invalid, will use default digest */
    return HKS_DIGEST_SHA256;
}

static int32_t RkcPbkdf2Hmac(const uint32_t hashAlg, const struct HksBlob *rawKey,
    const struct HksBlob *salt, const uint32_t iterNum, struct HksBlob *dk)
{
    struct HksKeyDerivationParam derParam = {
        .salt = *salt,
        .iterations = iterNum,
        .digestAlg = RkcDigestToHks(hashAlg),
    };
    const struct HksKeySpec derivationSpec = { HKS_ALG_PBKDF2, dk->size, &derParam };
    int32_t ret = HksCryptoHalDeriveKey(rawKey, &derivationSpec, dk);
    HKS_IF_NOT_SUCC_LOGE(ret, "Crypto hal derive key failed! ret = 0x%" LOG_PUBLIC "X", ret)

    return ret;
}

static int32_t RkcDeriveRmk(const struct HksRkcKsfData *ksfData, struct HksBlob *rmk)
{
    struct HksBlob rawKey;
    rawKey.data = (uint8_t *)HksMalloc(HKS_RKC_RAW_KEY_LEN);
    HKS_IF_NULL_LOGE_RETURN(rawKey.data, HKS_ERROR_MALLOC_FAIL, "Malloc rawKey failed!")

    rawKey.size = HKS_RKC_RAW_KEY_LEN;
    (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);

    int32_t ret;
    do {
        /* get the raw key */
        ret = RkcGetRmkRawKey(ksfData, &rawKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Get rmk raw key failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* PBKDF2-HMAC */
        const struct HksBlob salt = { HKS_RKC_SALT_LEN, (uint8_t *)(ksfData->rmkSalt) };
        ret = RkcPbkdf2Hmac(ksfData->rmkHashAlg, &rawKey, &salt, ksfData->rmkIter, rmk);
        HKS_IF_NOT_SUCC_LOGE(ret, "Pbkdf2 failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
    HKS_FREE_BLOB(rawKey);
    return ret;
}

static int32_t RkcHkdfHmac(const uint32_t hashAlg, const struct HksBlob *rawKey,
    const struct HksBlob *salt, const uint32_t iterNum, struct HksBlob *dk)
{
    struct HksKeyDerivationParam derParam = {
        .salt = *salt,
        .iterations = iterNum,
        .digestAlg = RkcDigestToHks(hashAlg),
    };
    const struct HksKeySpec derivationSpec = { HKS_ALG_HKDF, dk->size, &derParam };
    int32_t ret = HksCryptoHalDeriveKey(rawKey, &derivationSpec, dk);
    HKS_IF_NOT_SUCC_LOGE(ret, "Crypto hal derive key failed! ret = 0x%" LOG_PUBLIC "X", ret)

    return ret;
}

static int32_t RkcDeriveRmkV2(const struct HksKsfDataRkc *ksfDataRkc, struct HksBlob *rmk)
{
    struct HksBlob rawKey;
    rawKey.data = (uint8_t *)HksMalloc(HKS_RKC_RAW_KEY_LEN);
    HKS_IF_NULL_LOGE_RETURN(rawKey.data, HKS_ERROR_MALLOC_FAIL, "Malloc rawKey failed!")

    rawKey.size = HKS_RKC_RAW_KEY_LEN;
    (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);

    int32_t ret;
    do {
        /* get the raw key */
        ret = RkcGetRmkRawKeyV2(ksfDataRkc, &rawKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Get rmk raw key failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* HKDF-HMAC */
        const struct HksBlob salt = { HKS_RKC_SALT_LEN, (uint8_t *)(ksfDataRkc->rmkSalt) };
        ret = RkcHkdfHmac(ksfData->rmkHashAlg, &rawKey, &salt, ksfData->rmkIter, rmk);
        HKS_IF_NOT_SUCC_LOGE(ret, "HKDF failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
    HKS_FREE_BLOB(rawKey);
    return ret;
}

static int32_t InitMkCryptUsageSpec(uint8_t *iv, const uint32_t ivSize, struct HksUsageSpec *usageSpec)
{
    usageSpec->mode = HKS_MODE_GCM;
    usageSpec->padding = HKS_PADDING_NONE;
    usageSpec->digest = HKS_DIGEST_NONE;
    usageSpec->algType = HKS_ALG_AES;

    struct HksAeadParam *aeadParam = (struct HksAeadParam *)usageSpec->algParam;
    aeadParam->aad.size = HKS_RKC_MK_ADD_DATA_LEN;
    aeadParam->aad.data = (uint8_t *)&g_hksRkcMkAddData;
    aeadParam->nonce.size = ivSize;
    aeadParam->nonce.data = iv;
    aeadParam->payloadLen = HKS_RKC_RMK_EK_LEN;

    return HKS_SUCCESS;
}

static int32_t RkcMkCrypt(const struct HksRkcKsfData *ksfData,
    struct HksBlob *plainText, struct HksBlob *cipherText, const bool encrypt)
{
    struct HksBlob rmk;
    rmk.data = (uint8_t *)HksMalloc(HKS_RKC_RMK_LEN);
    HKS_IF_NULL_LOGE_RETURN(rmk.data, HKS_ERROR_MALLOC_FAIL, "Malloc rmk failed!")

    rmk.size = HKS_RKC_RMK_LEN;
    (void)memset_s(rmk.data, rmk.size, 0, rmk.size);

    int32_t ret;
    do {
        ret = RkcDeriveRmk(ksfData, &rmk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Derive rmk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        struct HksAeadParam aeadParam;
        (void)memset_s(&aeadParam, sizeof(aeadParam), 0, sizeof(aeadParam));
        struct HksUsageSpec usageSpec = { .algParam = (void *)(&aeadParam) };
        ret = InitMkCryptUsageSpec((uint8_t *)ksfData->mkIv, HKS_RKC_MK_IV_LEN, &usageSpec);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init mk crypt usageSpec failed! ret = 0x%" LOG_PUBLIC "X", ret)

        const struct HksBlob key = { HKS_RKC_RMK_EK_LEN, rmk.data };
        if (encrypt) {
            aeadParam.tagLenEnc = HKS_AE_TAG_LEN;
            struct HksBlob tag = { HKS_AE_TAG_LEN, cipherText->data + key.size };
            ret = HksCryptoHalEncrypt(&key, &usageSpec, plainText, cipherText, &tag);
        } else {
            aeadParam.tagDec.size = HKS_AE_TAG_LEN;
            aeadParam.tagDec.data = cipherText->data + cipherText->size - HKS_AE_TAG_LEN;
            cipherText->size -= HKS_AE_TAG_LEN; /* the decrypt len should remove the tag len */
            ret = HksCryptoHalDecrypt(&key, &usageSpec, cipherText, plainText);
        }
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("Crypto mk failed! ret = 0x%" LOG_PUBLIC "X", ret);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR; /* need return this error code for hichian call refresh func */
        }
    } while (0);

    /* the data of root key should be cleared after use */
    (void)memset_s(rmk.data, rmk.size, 0, rmk.size);
    HKS_FREE_BLOB(rmk);
    return ret;
}

static int32_t RkcMkCryptV2(const struct HksKsfDataRkc *ksfDataRkc, const struct HksKsfDataMk *ksfDataMk,
    struct HksBlob *plainText, struct HksBlob *cipherText, const bool encrypt)
{
    struct HksBlob rmk;
    rmk.data = (uint8_t *)HksMalloc(HKS_RKC_RMK_LEN);
    HKS_IF_NULL_LOGE_RETURN(rmk.data, HKS_ERROR_MALLOC_FAIL, "Malloc rmk failed!")

    rmk.size = HKS_RKC_RMK_LEN;
    (void)memset_s(rmk.data, rmk.size, 0, rmk.size);

    int32_t ret;
    do {
        ret = RkcDeriveRmkV2(ksfDataRkc, &rmk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Derive rmk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        struct HksAeadParam aeadParam;
        (void)memset_s(&aeadParam, sizeof(aeadParam), 0, sizeof(aeadParam));
        struct HksUsageSpec usageSpec = { .algParam = (void *)(&aeadParam) };
        ret = InitMkCryptUsageSpec((uint8_t *)ksfData->mkIv, HKS_RKC_MK_IV_LEN, &usageSpec);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init mk crypt usageSpec failed! ret = 0x%" LOG_PUBLIC "X", ret)

        const struct HksBlob key = { HKS_RKC_RMK_EK_LEN, rmk.data };
        if (encrypt) {
            aeadParam.tagLenEnc = HKS_AE_TAG_LEN;
            struct HksBlob tag = { HKS_AE_TAG_LEN, cipherText->data + key.size };
            ret = HksCryptoHalEncrypt(&key, &usageSpec, plainText, cipherText, &tag);
        } else {
            aeadParam.tagDec.size = HKS_AE_TAG_LEN;
            aeadParam.tagDec.data = cipherText->data + cipherText->size - HKS_AE_TAG_LEN;
            cipherText->size -= HKS_AE_TAG_LEN; /* the decrypt len should remove the tag len */
            ret = HksCryptoHalDecrypt(&key, &usageSpec, cipherText, plainText);
        }
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("Crypto mk failed! ret = 0x%" LOG_PUBLIC "X", ret);
            ret = HKS_ERROR_CRYPTO_ENGINE_ERROR; /* need return this error code for hichian call refresh func */
        }
    } while (0);

    /* the data of root key should be cleared after use */
    (void)memset_s(rmk.data, rmk.size, 0, rmk.size);
    HKS_FREE_BLOB(rmk);
    return ret;
}

static void RkcMaskMk(const struct HksBlob *mk)
{
    for (uint32_t i = 0; i < HKS_RKC_MK_LEN; ++i) {
        g_hksRkcMk.mkWithMask[i] = mk->data[i] ^ g_hksRkcCfg.mkMask[i];
    }

    g_hksRkcMk.valid = true;
}

static int32_t RkcRecoverMkTime(const struct HksRkcKsfData *rkcKsfData, const struct HksKsfDataRkc *ksfDataRkc, const struct HksKsfDataMk *ksfDataMk)
{
    // todo
    if (rkcKsfData != NULL) {
        // old version
        struct HksRkcKsfData *ksfDataRkc = rkcKsfData;
        struct Hks
    } else {
        // new version
        struct HksKsfDataMk *ksfData = ksfDataMk;
    }

    if (memcpy_s(&(g_hksRkcMk.mkCreatedTime), sizeof(g_hksRkcMk.mkCreatedTime),
        &(ksfDataMk->mkCreatedTime), sizeof(ksfDataMk->mkCreatedTime)) != EOK) {
        HKS_LOG_E("Memcpy mkCreatedTime failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    if (memcpy_s(&(g_hksRkcMk.mkExpiredTime), sizeof(g_hksRkcMk.mkExpiredTime),
        &(ksfDataMk->mkExpiredTime), sizeof(ksfDataMk->mkExpiredTime)) != EOK) {
        HKS_LOG_E("Memcpy mkExpiredTime failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    struct HksBlob mk;
    mk.data = (uint8_t *)HksMalloc(HKS_RKC_MK_LEN);
    HKS_IF_NULL_LOGE_RETURN(mk.data, HKS_ERROR_MALLOC_FAIL, "Malloc mk failed!")

    mk.size = HKS_RKC_MK_LEN;

    int32_t ret;
    do {
        struct HksBlob mkMaskBlob = { HKS_RKC_MK_LEN, g_hksRkcCfg.mkMask };
        ret = HksCryptoHalFillPrivRandom(&mkMaskBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        struct HksBlob mkCipherText = { HKS_RKC_MK_CIPHER_TEXT_LEN, (uint8_t *)ksfData->mkCiphertext };
        ret = RkcMkCrypt(ksfDataRkc, &mk, &mkCipherText, false); /* false: decrypt */
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Main key crypt failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* the main key in memory should be masked */
        (void)RkcMaskMk(&mk);
    } while (0);

    (void)memset_s(mk.data, mk.size, 0, mk.size);
    HKS_FREE_BLOB(mk);
    return ret;
}

static int32_t RkcCheckKsf(const char *ksfName, int32_t ret,
    const struct HksRkcKsfData *ksfData, const struct HksRkcKsfData *validKsfData)
{
    /* If this ksf is different from the first valid ksf, try to overwrite it by the first valid ksf. */
    if ((ret != HKS_SUCCESS) || (HksMemCmp(validKsfData, ksfData, sizeof(struct HksRkcKsfData)) != 0)) {
        HKS_LOG_E("Repair ksf[%" LOG_PUBLIC "s]", ksfName);
        return HksRkcWriteKsf(ksfName, validKsfData);
    }

    return HKS_SUCCESS;
}

static int32_t RkcCheckAllKsf(const int32_t *allKsfRet, const struct HksRkcKsfData *allKsfData,
    uint32_t ksfCount, const struct HksRkcKsfData *validKsfData, const uint32_t validKsfIndex)
{
    if (ksfCount > g_hksRkcCfg.ksfAttrRkc.num) {
        HKS_LOG_E("Invalid ksf count!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    for (uint32_t i = 0; i < g_hksRkcCfg.ksfAttrRkc.num; ++i) {
        if (i == validKsfIndex) {
            continue;
        }

        /* if fail, continue */
        int32_t ret = RkcCheckKsf(g_hksRkcCfg.ksfAttrRkc.name[i], allKsfRet[i], allKsfData + i, validKsfData);
        HKS_IF_NOT_SUCC_LOGE(ret, "Check 0x%" LOG_PUBLIC "X ksf failed! ret = 0x%" LOG_PUBLIC "X", i, ret)
    }

    return HKS_SUCCESS;
}

static int32_t RkcLoadKsf(void)
{
    const uint32_t allKsfDataSize = sizeof(struct HksRkcKsfData) * HKS_KSF_NUM;
    struct HksRkcKsfData *allKsfData = (struct HksRkcKsfData *)HksMalloc(allKsfDataSize);
    HKS_IF_NULL_LOGE_RETURN(allKsfData, HKS_ERROR_MALLOC_FAIL,
        "Malloc all rkc ksf data failed! malloc size = 0x%" LOG_PUBLIC "X", allKsfDataSize)

    (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);

    int32_t ret;
    do {
        int32_t allKsfRet[HKS_KSF_NUM] = {0};
        uint32_t validKsfIndex = 0;
        struct HksRkcKsfData *validKsfData = NULL;

        ret = RkcReadAllKsf(allKsfRet, allKsfData, HKS_KSF_NUM, &validKsfData, &validKsfIndex);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All rkc ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcRecoverRkTime(validKsfData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover root key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcRecoverMkTime(validKsfData, NULL);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover main key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcCheckAllKsf(allKsfRet, allKsfData, HKS_KSF_NUM, validKsfData, validKsfIndex);
        HKS_IF_NOT_SUCC_LOGE(ret, "Check all rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);
    HKS_FREE_PTR(allKsfData);
    return ret;
}

static int32_t RkcLoadKsfV2(struct HksKsfDataRkc **validKsfData)
{
    const uint32_t allKsfDataSize = sizeof(struct HksKsfDataRkc) * HKS_KSF_NUM;
    struct HksKsfDataRkc *allKsfData = (struct HksKsfDataRkc *)HksMalloc(allKsfDataSize);
    HKS_IF_NULL_LOGE_RETURN(allKsfData, HKS_ERROR_MALLOC_FAIL,
        "Malloc all rkc ksf data failed! malloc size = 0x%" LOG_PUBLIC "X", allKsfDataSize)

    (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);

    int32_t ret;
    do {
        int32_t allKsfRet[HKS_KSF_NUM] = {0};
        uint32_t validKsfIndex = 0;

        ret = RkcReadAllKsf(allKsfRet, allKsfData, HKS_KSF_NUM, validKsfData, &validKsfIndex);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All rkc ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcRecoverRkTime(validKsfData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover root key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcCheckAllKsf(allKsfRet, allKsfData, HKS_KSF_NUM, validKsfData, validKsfIndex);
        HKS_IF_NOT_SUCC_LOGE(ret, "Check all rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);
    HKS_FREE_PTR(allKsfData);
    return ret;
}

static int32_t MkLoadKsf(void)
{
    const uint32_t allKsfDataSize = sizeof(struct HksKsfDataMk) * HKS_KSF_NUM;
    struct HksKsfDataMk *allKsfData = (struct HksKsfDataMk *)HksMalloc(allKsfDataSize);
    HKS_IF_NULL_LOGE_RETURN(allKsfData, HKS_ERROR_MALLOC_FAIL,
        "Malloc all mk ksf data failed! malloc size = 0x%" LOG_PUBLIC "X", allKsfDataSize)

    (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);

    int32_t ret;
    do {
        int32_t allKsfRet[HKS_KSF_NUM] = {0};
        uint32_t validKsfIndex = 0;
        struct HksKsfDataMk *validKsfData = NULL;

        ret = MkReadAllKsf(allKsfRet, allKsfData, HKS_KSF_NUM, &validKsfData, &validKsfIndex);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All mk ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcRecoverMkTime(NULL, validKsfData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover main key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcCheckAllKsf(allKsfRet, allKsfData, HKS_KSF_NUM, validKsfData, validKsfIndex);
        HKS_IF_NOT_SUCC_LOGE(ret, "Check all mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);
    HKS_FREE_PTR(allKsfData);
    return ret;
}

static int32_t RkcMakeRandomMaterial(struct HksKsfDataRkc *ksfDataRkc)
{
    /* two random number */
    uint8_t random1Data[HKS_RKC_MATERIAL_LEN] = {0};
    uint8_t random2Data[HKS_RKC_MATERIAL_LEN] = {0};
    struct HksBlob random1 = { HKS_RKC_MATERIAL_LEN, random1Data };
    struct HksBlob random2 = { HKS_RKC_MATERIAL_LEN, random2Data };

    int32_t ret;
    do {
        /* Generate 32 * 2 random number: R1 + R2 */
        ret = HksCryptoHalFillPrivRandom(&random1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate random1 failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = HksCryptoHalFillPrivRandom(&random2);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate random2 failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* Fill material */
        if (memcpy_s(ksfDataRkc->rkMaterial1, HKS_RKC_MATERIAL_LEN, random1Data, HKS_RKC_MATERIAL_LEN) != EOK) {
            HKS_LOG_E("Memcpy rkMaterial1 failed!");
            ret = HKS_ERROR_INSUFFICIENT_MEMORY;
        }
        if (memcpy_s(ksfDataRkc->rkMaterial2, HKS_RKC_MATERIAL_LEN, random2Data, HKS_RKC_MATERIAL_LEN) != EOK) {
            HKS_LOG_E("Memcpy rkMaterial2 failed!");
            ret = HKS_ERROR_INSUFFICIENT_MEMORY;
        }
    } while (0);

    (void)memset_s(random1Data, HKS_RKC_MATERIAL_LEN, 0, HKS_RKC_MATERIAL_LEN);
    (void)memset_s(random2Data, HKS_RKC_MATERIAL_LEN, 0, HKS_RKC_MATERIAL_LEN);
    return ret;
}

static int32_t RkcMakeMk(struct HksKsfDataRkc *ksfDataRkc, struct HksKsfDataMk *ksfDataMk)
{
    struct HksBlob mk;
    mk.data = (uint8_t *)HksMalloc(HKS_RKC_MK_LEN);
    HKS_IF_NULL_LOGE_RETURN(mk.data, HKS_ERROR_MALLOC_FAIL, "Malloc mk failed!")

    mk.size = HKS_RKC_MK_LEN;

    int32_t ret;
    do {
        /* generate main key */
        ret = HksCryptoHalFillPrivRandom(&mk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* generate the mask of main key */
        struct HksBlob mkMaskBlob = { HKS_RKC_MK_LEN, g_hksRkcCfg.mkMask };
        ret = HksCryptoHalFillPrivRandom(&mkMaskBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate mkMask failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* generate the IV of main key */
        struct HksBlob mkIvBlob = { HKS_RKC_MK_IV_LEN, ksfData->mkIv };
        ret = HksCryptoHalFillPrivRandom(&mkIvBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate mkIv failed! ret = 0x%" LOG_PUBLIC "X", ret)

        struct HksBlob cipherTextBlob = { HKS_RKC_MK_CIPHER_TEXT_LEN, ksfData->mkCiphertext };
        ret = RkcMkCryptV2(ksfDataRkc, ksfDataMk, &mk, &cipherTextBlob, true); /* true: encrypt */
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Encrypt mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* the main key in memory should be masked */
        (void)RkcMaskMk(&mk);
        
    } while (0);

    (void)memset_s(mk.data, mk.size, 0, mk.size);
    HKS_FREE_BLOB(mk);
    return ret;
}

static int32_t RkcWriteAllKsf(const struct HksKsfDataRkc *ksfDataRkc, const struct HksKsfDataMk *ksfDataMk)
{
    bool isSuccess = false;
    for (uint32_t i = 0; i < g_hksRkcCfg.ksfAttrRkc.num; ++i) {
        int32_t ret = HksRkcWriteKsf(g_hksRkcCfg.ksfAttrRkc.name[i], ksfDataRkc);
    }
    for (uint32_t i = 0; i < g_hksRkcCfg.ksfAttrMk.num; ++i) {
        int32_t ret = HksMkWriteKsf(g_hksRkcCfg.ksfAttrMk.name[i], ksfDataMk);
        if (ret == HKS_SUCCESS) {
            isSuccess = true;
        }
    }

    /* If all keystore file were written fail, return error code, otherwise, return success code. */
    return (isSuccess ? HKS_SUCCESS : HKS_ERROR_WRITE_FILE_FAIL);
}

static int32_t RkcCreateKsf(void)
{
    struct HksKsfDataRkc *newKsfDataRkc = (struct HksKsfDataRkc *)HksMalloc(sizeof(struct HksKsfDataRkc));
    HKS_IF_NULL_LOGE_RETURN(newKsfDataRkc, HKS_ERROR_MALLOC_FAIL, "Malloc rkc ksf data failed!")
    struct HksKsfDataMk *newKsfDataMk = (struct HksKsfDataMk *)HksMalloc(sizeof(struct HksKsfDataMk));
    HKS_IF_NULL_LOGE_RETURN(newKsfDataMk, HKS_ERROR_MALLOC_FAIL, "Malloc mk ksf data failed!")

    (void)memset_s(newKsfDataRkc, sizeof(struct HksKsfDataRkc), 0, sizeof(struct HksKsfDataRkc));
    (void)memset_s(newKsfDataMk, sizeof(struct HksKsfDataMk), 0, sizeof(struct HksKsfDataMk));

    /* Fill some fixed field. */
    newKsfDataRkc->rkVersion = g_hksRkcCfg.rkVersion;
    newKsfDataRkc->rmkIter = g_hksRkcCfg.rmkIter;
    newKsfDataRkc->rmkHashAlg = g_hksRkcCfg.rmkHashAlg;
    newKsfDataMk->mkVersion = g_hksRkcCfg.mkVersion;
    newKsfDataMk->mkEncryptAlg = g_hksRkcCfg.mkEncryptAlg;

    int32_t ret;
    do {
        /* Two material are generated by random number. */
        ret = RkcMakeRandomMaterial(newKsfDataRkc);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate material failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* The salt value is generated by random number. */
        struct HksBlob salt = { HKS_RKC_SALT_LEN, newKsfDataRkc->rmkSalt };
        ret = HksCryptoHalFillPrivRandom(&salt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate salt failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* make main key. */
        ret = RkcMakeMk(newKsfDataRkc, newKsfDataMk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "make mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* Write the root key component and the main key data into all keystore files */
        ret = RkcWriteAllKsf(newKsfDataRkc, newKsfDataMk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Write rkc & mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    /* the data of root&main key should be cleared after use */
    (void)memset_s(newKsfDataRkc, sizeof(struct HksKsfDataRkc), 0, sizeof(struct HksKsfDataRkc));
    (void)memset_s(newKsfDataMk, sizeof(struct HksKsfDataMk), 0, sizeof(struct HksKsfDataMk));
    HKS_FREE_PTR(newKsfDataRkc);
    HKS_FREE_PTR(newKsfDataMk);
    return ret;
}

static char *CloneNewStr(const char *srcStr, const uint32_t strLenMax)
{
    HKS_IF_NULL_LOGE_RETURN(srcStr, NULL, "Invalid input string!")

    const uint32_t strLen = strlen(srcStr);
    if ((strLen == 0) || (strLen > strLenMax)) {
        HKS_LOG_E("Invalid input string! len = 0x%" LOG_PUBLIC "X, maxLen = 0x%" LOG_PUBLIC "X", strLen, strLenMax);
        return NULL;
    }

    char *newBuf = (char *)HksMalloc(strLen + 1); /* 1: end char */
    HKS_IF_NULL_LOGE_RETURN(newBuf, NULL, "Malloc new buffer failed!")

    if (memcpy_s(newBuf, strLen, srcStr, strLen) != EOK) {
        HKS_LOG_E("Memcpy new buffer failed!");
        HKS_FREE_PTR(newBuf);
        return NULL;
    }
    newBuf[strLen] = '\0';

    return newBuf;
}

static int32_t RkcInitKsfAttr(const struct HksKsfAttrRkc *ksfAttrRkc)
{
    /* clone keystore filename from parameter. */
    for (uint8_t i = 0; i < ksfAttrRkc->num; ++i) {
        char *fileName = CloneNewStr(ksfAttrRkc->name[i], HKS_KSF_NAME_LEN_MAX);
        /* the memory will be freed by hksRkcDestroy() */
        HKS_IF_NULL_RETURN(fileName, HKS_ERROR_MALLOC_FAIL)

        g_hksRkcCfg.ksfAttrRkc.name[i] = fileName;
    }

    g_hksRkcCfg.ksfAttrRkc.num = ksfAttrRkc->num;
    return HKS_SUCCESS;
}

static int32_t MkInitKsfAttr(const struct HksKsfAttrMk *ksfAttrMk)
{
    /* clone keystore filename from parameter. */
    for (uint8_t i = 0; i < ksfAttrMk->num; ++i) {
        char *fileName = CloneNewStr(ksfAttrMk->name[i], HKS_KSF_NAME_LEN_MAX);
        /* the memory will be freed by hksMkDestroy() */
        HKS_IF_NULL_RETURN(fileName, HKS_ERROR_MALLOC_FAIL)

        g_hksRkcCfg.ksfAttrMk.name[i] = fileName;
    }

    g_hksRkcCfg.ksfAttrMk.num = ksfAttrMk->num;
    return HKS_SUCCESS;
}

int32_t HksRkcInit(void)
{
    if (g_hksRkcCfg.state == HKS_RKC_STATE_VALID) {
        HKS_LOG_I("Hks rkc is running!");NULL
        return HKS_SUCCESS;
    }

    if (KsfExist(HKS_KSF_TYPE_MK)) {
        // mk keystore file exists
        int32_t ret;
        const struct HksRkcInitParam initParamInner = {
            .rkVersion = 0,
            .mkVersion = 0,
            .storageType = HKS_RKC_STORAGE_FILE_SYS,
            .ksfAttrRkc = { HKS_KSF_NUM, { "rinfo1_v2.data", "rinfo2_v2.data" } },
            .ksfAttrMk = { HKS_KSF_NUM, { "minfo1_v2.data", "minfo2_v2.data" } },
            .rmkIter = HKS_RKC_RMK_ITER,
            .rmkHashAlg = HKS_RKC_RMK_HMAC_SHA256,
            .mkEncryptAlg = HKS_RKC_MK_CRYPT_ALG_AES256_GCM,
        };

        do {
            g_hksRkcCfg.rkVersion = initParamInner->rkVersion;
            g_hksRkcCfg.mkVersion = initParamInner->mkVersion;
            g_hksRkcCfg.storageType = initParamInner->storageType;
            g_hksRkcCfg.rmkIter = initParamInner->rmkIter;
            g_hksRkcCfg.rmkHashAlg = initParamInner->rmkHashAlg;
            g_hksRkcCfg.mkEncryptAlg = initParamInner->mkEncryptAlg;

            /* Initialize the attribute of mk keystore file */
            ret = MkInitKsfAttr(&(initParamInner->ksfAttrRkc));
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

            HKS_LOG_I("mk ksf is exist, start to read ksf");

            const uint32_t allKsfDataSize = sizeof(struct HksKsfDataMk) * HKS_KSF_NUM;
            struct HksKsfDataMk *allKsfData = (struct HksKsfDataMk *)HksMalloc(allKsfDataSize);
            HKS_IF_NULL_LOGE_RETURN(allKsfData, HKS_ERROR_MALLOC_FAIL,
                "Malloc all mk ksf data failed! malloc size = 0x%" LOG_PUBLIC "X", allKsfDataSize)

            (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);

            int32_t allKsfRet[HKS_KSF_NUM] = {0};
            uint32_t validKsfIndex = 0;
            struct HksKsfDataMk *validKsfDataMk = NULL;

            ret = MkReadAllKsf(allKsfRet, allKsfData, HKS_KSF_NUM, &validKsfDataMk, &validKsfIndex);
            HKS_IF_NOT_SUCC_LOGE(ret, "All mk ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

            if (ret != HKS_SUCCESS) {
                (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);
                HKS_FREE_PTR(allKsfData);
                HKS_IF_NOT_SUCC_LOGE(ret, "read mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
            }

            /* Initialize the attribute of rkc keystore file */
            ret = RkcInitKsfAttr(&(initParamInner->ksfAttrRkc));
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

            HKS_LOG_I("Rkc ksf is exist, start to load ksf");
            struct HksKsfDataRkc *validKsfDataRkc = NULL;
            ret = RkcLoadKsfV2(&validKsfDataRkc);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Load rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)

            // decrypt main key
            ret = RkcRecoverMkTime(NULL, validKsfData);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover main key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

            if (validKsfData->mkVersion != HKS_MK_VER) {
                // need update
                // generate new materials and encrypt main key
                do {
                    struct HksKsfDataRkc *newKsfDataRkc = (struct HksKsfDataRkc *)HksMalloc(sizeof(struct HksKsfDataRkc));
                    HKS_IF_NULL_LOGE_RETURN(newKsfDataRkc, HKS_ERROR_MALLOC_FAIL, "Malloc rkc ksf data failed!")
                    struct HksKsfDataMk *newKsfDataMk = (struct HksKsfDataMk *)HksMalloc(sizeof(struct HksKsfDataMk));
                    HKS_IF_NULL_LOGE_RETURN(newKsfDataMk, HKS_ERROR_MALLOC_FAIL, "Malloc mk ksf data failed!")

                    (void)memset_s(newKsfDataRkc, sizeof(struct HksKsfDataRkc), 0, sizeof(struct HksKsfDataRkc));
                    (void)memset_s(newKsfDataMk, sizeof(struct HksKsfDataMk), 0, sizeof(struct HksKsfDataMk));

                    /* Fill some fixed field. */
                    newKsfDataRkc->rkVersion = g_hksRkcCfg.rkVersion;
                    newKsfDataRkc->rmkIter = g_hksRkcCfg.rmkIter;
                    newKsfDataRkc->rmkHashAlg = g_hksRkcCfg.rmkHashAlg;
                    newKsfDataMk->mkVersion = g_hksRkcCfg.mkVersion;
                    newKsfDataMk->mkEncryptAlg = g_hksRkcCfg.mkEncryptAlg;

                    /* Two material are generated by random number. */
                    ret = RkcMakeRandomMaterial(newKsfDataRkc);
                    HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate material failed! ret = 0x%" LOG_PUBLIC "X", ret)

                    /* The salt value is generated by random number. */
                    struct HksBlob salt = { HKS_RKC_SALT_LEN, newKsfDataRkc->rmkSalt };
                    ret = HksCryptoHalFillPrivRandom(&salt);
                    HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate salt failed! ret = 0x%" LOG_PUBLIC "X", ret)

                    struct HksBlob mk;
                    mk.data = (uint8_t *)HksMalloc(HKS_RKC_MK_LEN);
                    HKS_IF_NULL_LOGE_RETURN(mk.data, HKS_ERROR_MALLOC_FAIL, "Malloc mk failed!")

                    mk.size = HKS_RKC_MK_LEN;

                    /* remove mask */
                    for (uint32_t i = 0; i < HKS_RKC_MK_LEN; ++i) {
                        mk->data[i] = g_hksRkcMk.mkWithMask[i] ^ g_hksRkcCfg.mkMask[i];
                    }

                    struct HksBlob cipherTextBlob = { HKS_RKC_MK_CIPHER_TEXT_LEN, newKsfDataMk->mkCiphertext };
                    ret = RkcMkCryptV2(newKsfDataRkc, newKsfDataMk, &mk, &cipherTextBlob, true); /* true: encrypt */
                    HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Encrypt mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

                    /* Write the root key component and the main key data into all keystore files */
                    ret = RkcWriteAllKsf(newKsfDataRkc, newKsfDataMk);
                    HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Write rkc & mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
                } while (0);

                /* the data of root&main key should be cleared after use */
                (void)memset_s(newKsfDataRkc, sizeof(struct HksKsfDataRkc), 0, sizeof(struct HksKsfDataRkc));
                (void)memset_s(newKsfDataMk, sizeof(struct HksKsfDataMk), 0, sizeof(struct HksKsfDataMk));
                (void)memset_s(mk.data, mk.size, 0, mk.size);
                HKS_FREE_PTR(newKsfDataRkc);
                HKS_FREE_PTR(newKsfDataMk);
                HKS_FREE_BLOB(mk);

                // todo delete old files
            }
        } while (0);

        // todo
        // (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);
        // HKS_FREE_PTR(allKsfData);
        // return ret;

        if (ret != HKS_SUCCESS) {
            (void)HksRkcDestroy();
            (void)HksMkDestroy();
            return ret;
        }
    } else {
        if (KsfExist(HKS_KSF_TYPE_RKC)) {
            // rkc keystore file exists
            int32_t ret;
            const struct HksRkcInitParam initParamInner = {
                .rkVersion = 1,
                .mkVersion = 0,
                .storageType = HKS_RKC_STORAGE_FILE_SYS,
                .ksfAttrRkc = { HKS_KSF_NUM, { "info1.data", "info2.data" } },
                .ksfAttrMk = { HKS_KSF_NUM, { NULL, NULL } },
                .rmkIter = HKS_RKC_RMK_ITER,
                .rmkHashAlg = HKS_RKC_RMK_HMAC_SHA256,
                .mkEncryptAlg = HKS_RKC_MK_CRYPT_ALG_AES256_GCM,
            };

            do {
                g_hksRkcCfg.rkVersion = initParamInner->rkVersion;
                g_hksRkcCfg.mkVersion = initParamInner->mkVersion;
                g_hksRkcCfg.storageType = initParamInner->storageType;
                g_hksRkcCfg.rmkIter = initParamInner->rmkIter;
                g_hksRkcCfg.rmkHashAlg = initParamInner->rmkHashAlg;
                g_hksRkcCfg.mkEncryptAlg = initParamInner->mkEncryptAlg;

                /* Initialize the attribute of rkc keystore file */
                ret = RkcInitKsfAttr(&(initParamInner->ksfAttrRkc));
                HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

                HKS_LOG_I("Rkc ksf is exist, start to load ksf");
                ret = RkcLoadKsf();
                HKS_IF_NOT_SUCC_LOGE(ret, "Load rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
            } while (0);

            if (ret != HKS_SUCCESS) {
                (void)HksRkcDestroy();
                (void)HksMkDestroy();
                return ret;
            }

            // generate new materials and encrypt main key
            do {
                struct HksKsfDataRkc *newKsfDataRkc = (struct HksKsfDataRkc *)HksMalloc(sizeof(struct HksKsfDataRkc));
                HKS_IF_NULL_LOGE_RETURN(newKsfDataRkc, HKS_ERROR_MALLOC_FAIL, "Malloc rkc ksf data failed!")
                struct HksKsfDataMk *newKsfDataMk = (struct HksKsfDataMk *)HksMalloc(sizeof(struct HksKsfDataMk));
                HKS_IF_NULL_LOGE_RETURN(newKsfDataMk, HKS_ERROR_MALLOC_FAIL, "Malloc mk ksf data failed!")

                (void)memset_s(newKsfDataRkc, sizeof(struct HksKsfDataRkc), 0, sizeof(struct HksKsfDataRkc));
                (void)memset_s(newKsfDataMk, sizeof(struct HksKsfDataMk), 0, sizeof(struct HksKsfDataMk));

                /* Fill some fixed field. */
                newKsfDataRkc->rkVersion = g_hksRkcCfg.rkVersion;
                newKsfDataRkc->rmkIter = g_hksRkcCfg.rmkIter;
                newKsfDataRkc->rmkHashAlg = g_hksRkcCfg.rmkHashAlg;
                newKsfDataMk->mkVersion = g_hksRkcCfg.mkVersion;
                newKsfDataMk->mkEncryptAlg = g_hksRkcCfg.mkEncryptAlg;

                /* Two material are generated by random number. */
                ret = RkcMakeRandomMaterial(newKsfDataRkc);
                HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate material failed! ret = 0x%" LOG_PUBLIC "X", ret)

                /* The salt value is generated by random number. */
                struct HksBlob salt = { HKS_RKC_SALT_LEN, newKsfDataRkc->rmkSalt };
                ret = HksCryptoHalFillPrivRandom(&salt);
                HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate salt failed! ret = 0x%" LOG_PUBLIC "X", ret)

                struct HksBlob mk;
                mk.data = (uint8_t *)HksMalloc(HKS_RKC_MK_LEN);
                HKS_IF_NULL_LOGE_RETURN(mk.data, HKS_ERROR_MALLOC_FAIL, "Malloc mk failed!")

                mk.size = HKS_RKC_MK_LEN;

                /* remove mask */
                for (uint32_t i = 0; i < HKS_RKC_MK_LEN; ++i) {
                    mk->data[i] = g_hksRkcMk.mkWithMask[i] ^ g_hksRkcCfg.mkMask[i];
                }

                struct HksBlob cipherTextBlob = { HKS_RKC_MK_CIPHER_TEXT_LEN, newKsfDataMk->mkCiphertext };
                ret = RkcMkCryptV2(newKsfDataRkc, newKsfDataMk, &mk, &cipherTextBlob, true); /* true: encrypt */
                HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Encrypt mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

                /* Write the root key component and the main key data into all keystore files */
                ret = RkcWriteAllKsf(newKsfDataRkc, newKsfDataMk);
                HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Write rkc & mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
            } while (0);

            /* the data of root&main key should be cleared after use */
            (void)memset_s(newKsfDataRkc, sizeof(struct HksKsfDataRkc), 0, sizeof(struct HksKsfDataRkc));
            (void)memset_s(newKsfDataMk, sizeof(struct HksKsfDataMk), 0, sizeof(struct HksKsfDataMk));
            (void)memset_s(mk.data, mk.size, 0, mk.size);
            HKS_FREE_PTR(newKsfDataRkc);
            HKS_FREE_PTR(newKsfDataMk);
            HKS_FREE_BLOB(mk);

            // todo delete old files
        } else {
            // no file exists, no compatibility
            ret = RkcCreateKsf();
            HKS_IF_NOT_SUCC_LOGE(ret, "Create root & main ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
        }
    }

    g_hksRkcCfg.state = HKS_RKC_STATE_VALID;
    return HKS_SUCCESS;
}

void HksRkcDestroy(void)
{
    g_hksRkcCfg.state = HKS_RKC_STATE_INVALID;
    HksRkcClearMem();
}

void HksMkDestroy(void)
{
    HksMkClearMem();
}

void HksRkcClearMem(void)
{
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        HKS_FREE_PTR(g_hksRkcCfg.ksfAttrRkc.name[i]);
    }

    (void)memset_s(&g_hksRkcCfg, sizeof(g_hksRkcCfg), 0, sizeof(g_hksRkcCfg));
    // (void)memset_s(&g_hksRkcMk, sizeof(g_hksRkcMk), 0, sizeof(g_hksRkcMk));
}

void HksMkClearMem(void)
{
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        HKS_FREE_PTR(g_hksRkcCfg.ksfAttrMk.name[i]);
    }

    (void)memset_s(&g_hksRkcMk, sizeof(g_hksRkcMk), 0, sizeof(g_hksRkcMk));
}

int32_t HksRkcGetMainKey(struct HksBlob *mainKey)
{
    if (!g_hksRkcMk.valid) {
        HKS_LOG_E("Main key is invalid now, initialization is required before Getting main key!");
        return HKS_FAILURE;
    }

    if (mainKey->size != HKS_RKC_MK_LEN) {
        HKS_LOG_E("Invalid mainKey size! size = 0x%" LOG_PUBLIC "X", mainKey->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    /* remove mask */
    for (uint32_t i = 0; i < HKS_RKC_MK_LEN; ++i) {
        mainKey->data[i] = g_hksRkcMk.mkWithMask[i] ^ g_hksRkcCfg.mkMask[i];
    }

    return HKS_SUCCESS;
}
#endif /* _CUT_AUTHENTICATE_ */
