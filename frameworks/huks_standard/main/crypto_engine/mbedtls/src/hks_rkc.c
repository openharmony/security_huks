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

/* the configuration of root key component */
static struct HksRkcCfg g_hksRkcCfg = {
    .state = HKS_RKC_STATE_INVALID,
    .rkVersion = HKS_RKC_VER,
    .mkVersion = HKS_MK_VER,
    .storageType = HKS_RKC_STORAGE_FILE_SYS,
    .rkCreatedTime = { 0, 0, 0, 0, 0, 0 },
    .rkExpiredTime = { 0, 0, 0, 0, 0, 0 },
    .ksfAttrRkc = {  NULL, NULL },
    .ksfAttrMk = { NULL, NULL },
    .rmkIter = HKS_RKC_RMK_ITER,
    .rmkHashAlg = HKS_RKC_RMK_HMAC_SHA256,
    .mkMask = {0},
    .mkEncryptAlg = HKS_RKC_MK_CRYPT_ALG_AES256_GCM,
    .reserve = {0}
};

struct HksKsfAttr *GetGlobalKsfAttrRkc()
{
    return &g_hksRkcCfg.ksfAttrRkc;
}

struct HksKsfAttr *GetGlobalKsfAttrMk()
{
    return &g_hksRkcCfg.ksfAttrMk;
}

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

// static int32_t ReadAllKsf(int32_t *allKsfRet, struct HksRkcKsfData *allKsfData, uint32_t ksfCount,
//     struct HksRkcKsfData **validKsfData, uint32_t *validKsfIndex)
// {
//     if (ksfCount > HKS_KSF_NUM) {
//         HKS_LOG_E("Invalid rkc ksf count!");
//         return HKS_ERROR_INVALID_ARGUMENT;
//     }

//     /* Read all ksf */
//     bool someCaseSuccess = false;
//     for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
//         allKsfRet[i] = HksRkcReadKsf(g_hksRkcCfg.ksfAttrRkc.name[i], &(allKsfData[i]));
//         if (allKsfRet[i] != HKS_SUCCESS) {
//             continue;
//         }

//         /* the first valid ksf is found, save data and index */
//         if (*validKsfData == NULL) {
//             *validKsfData = &(allKsfData[i]);
//             *validKsfIndex = i;
//             someCaseSuccess = true;
//         }
//     }

//     // todo: 在读取到一个文件成功，另一个文件失败的时候，立马覆写失败文件。本函数最终只保留一个出参struct HksRkcKsfData **validKsfData

//     return (someCaseSuccess ? HKS_SUCCESS : HKS_ERROR_INVALID_KEY_FILE);
// }

// 1、 读文件（文件名）
// 2、 校验文件格式和结构体是否相符 （结构体）
// 3、 对于备份文件不存在或已损坏，则覆写该文件
static int32_t RkcReadAllKsf(struct HksRkcKsfData **validKsfData)
{
    /* Read all ksf */
    int32_t readRet[HKS_KSF_NUM] = { 0 };
    struct HksRkcKsfData allRkcData[HKS_KSF_NUM] = { 0 };
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        readRet[i] = HksRkcReadKsf(g_hksRkcCfg.ksfAttrRkc.name[i], &(allRkcData[i]));
    }

    int32_t validIndex = 0;
    for (; validIndex < HKS_KSF_NUM; validIndex++) {
        if (readRet[validIndex] == HKS_SUCCESS) {
            break;
        }
    }
    if (validIndex == HKS_KSF_NUM) {
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    *validKsfData = (struct HksRkcKsfData *)HksMalloc(sizeof(struct HksRkcKsfData));
    if (validKsfData == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(*validKsfData, sizeof(struct HksRkcKsfData), allRkcData[validIndex], sizeof(struct HksRkcKsfData));
    return HKS_SUCCESS;
}

static int32_t RkcReadAllKsfV2(struct HksKsfDataRkc **validKsfData)
{
    /* Read all ksf */
    int32_t readRet[HKS_KSF_NUM] = { 0 };
    struct HksKsfDataRkc allRkcData[HKS_KSF_NUM] = { 0 };
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        readRet[i] = HksReadKsfRkc(g_hksRkcCfg.ksfAttrRkc.name[i], &(allRkcData[i]));
    }

    int32_t validIndex = 0;
    for (; validIndex < HKS_KSF_NUM; validIndex++) {
        if (readRet[validIndex] == HKS_SUCCESS) {
            break;
        }
    }
    if (validIndex == HKS_KSF_NUM) {
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    // todo: 在读取到一个文件成功，另一个文件失败的时候，立马覆写失败文件。本函数最终只保留一个出参struct HksRkcKsfData **HksKsfDataRkc
    for (uint32_t i = 0; i < HKS_KSF_NUM; i++) {
        if (readRet[i] != HKS_SUCCESS) {
            int32_t ret = HksWriteKsfRkc(g_hksRkcCfg.ksfAttrRkc.name[i], allRkcData[validIndex]); // todo: 老的rkc是否需要write?
            HKS_IF_NOT_SUCC_LOGE(ret, "rewrite rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
        }
    }

    *validKsfData = (struct HksKsfDataRkc *)HksMalloc(sizeof(struct HksKsfDataRkc));
    if (validKsfData == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(*validKsfData, sizeof(struct HksKsfDataRkc), allRkcData[validIndex], sizeof(struct HksKsfDataRkc));
    return HKS_SUCCESS;
}

static int32_t MkReadAllKsf(struct HksKsfDataMk **validKsfData)
{
    /* Read all ksf */
    int32_t readRet[HKS_KSF_NUM] = { 0 };
    struct HksKsfDataMk allMkData[HKS_KSF_NUM] = { 0 };
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        readRet[i] = HksReadKsfMk(g_hksRkcCfg.ksfAttrMk.name[i], &(allMkData[i]));
    }

    int32_t validIndex = 0;
    for (; validIndex < HKS_KSF_NUM; validIndex++) {
        if (readRet[validIndex] == HKS_SUCCESS) {
            break;
        }
    }
    if (validIndex == HKS_KSF_NUM) {
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    // todo: 在读取到一个文件成功，另一个文件失败的时候，立马覆写失败文件。本函数最终只保留一个出参struct HksKsfDataMk **validKsfData
    for (uint32_t i = 0; i < HKS_KSF_NUM; i++) {
        if (readRet[i] != HKS_SUCCESS) {
            int32_t ret = HksWriteKsfMk(g_hksRkcCfg.ksfAttrMk.name[i], allMkData[validIndex]);
            HKS_IF_NOT_SUCC_LOGE(ret, "rewrite rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
        }
    }

    *validKsfData = (struct HksKsfDataMk *)HksMalloc(sizeof(struct HksKsfDataMk));
    if (validKsfData == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(*validKsfData, sizeof(struct HksKsfDataMk), allMkData[validIndex], sizeof(struct HksKsfDataMk));
    return HKS_SUCCESS;
}

// static int32_t MkReadAllKsf(int32_t *allKsfRet, struct HksKsfDataMk *allKsfData, uint32_t ksfCount,
//     struct HksKsfDataMk **validKsfData, uint32_t *validKsfIndex)
// {
//     if (ksfCount > HKS_KSF_NUM) {
//         HKS_LOG_E("Invalid mk ksf count!");
//         return HKS_ERROR_INVALID_ARGUMENT;
//     }

//     /* Read all ksf */
//     bool someCaseSuccess = false;
//     for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
//         allKsfRet[i] = HksMkReadKsf(g_hksRkcCfg.ksfAttrMk.name[i], &(allKsfData[i])); // todo: 待实现
//         if (allKsfRet[i] != HKS_SUCCESS) {
//             continue;
//         }

//         /* the first valid ksf is found, save data and index */
//         if (*validKsfData == NULL) {
//             *validKsfData = &(allKsfData[i]);
//             *validKsfIndex = i;
//             someCaseSuccess = true;
//             // break;
//         }
//     }

//     return (someCaseSuccess ? HKS_SUCCESS : HKS_ERROR_INVALID_KEY_FILE);
// }

static int32_t RkcRecoverRkTime(const struct HksKsfDataRkc *KsfDataRkc)
{
    if (memcpy_s(&(g_hksRkcCfg.rkCreatedTime), sizeof(g_hksRkcCfg.rkCreatedTime),
        &(KsfDataRkc->rkCreatedTime), sizeof(KsfDataRkc->rkCreatedTime)) != EOK) {
        HKS_LOG_E("Memcpy rkCreatedTime failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    if (memcpy_s(&(g_hksRkcCfg.rkExpiredTime), sizeof(g_hksRkcCfg.rkExpiredTime),
        &(KsfDataRkc->rkExpiredTime), sizeof(KsfDataRkc->rkExpiredTime)) != EOK) {
        HKS_LOG_E("Memcpy rkExpiredTime failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    return HKS_SUCCESS;
}

/* todo: separate code of old version using macro */
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

/* todo: separate code of old version using macro */
static int32_t RkcGetRmkRawKey(const struct HksKsfDataRkc *KsfDataRkc, struct HksBlob *rawKey)
{
    uint8_t material3Data[HKS_RKC_MATERIAL_LEN] = {0};
    struct HksBlob material3 = { HKS_RKC_MATERIAL_LEN, material3Data };

    /* Get the fixed material */
    int32_t ret = RkcGetFixedMaterial(&material3);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Get fixed material failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* materials xor */
    for (uint32_t i = 0; i < HKS_RKC_MATERIAL_LEN; ++i) {
        rawKey->data[i] = KsfDataRkc->rkMaterial1[i] ^ KsfDataRkc->rkMaterial2[i] ^ material3.data[i];
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
        rawKey->data[i] = ksfDataRkc->rkMaterial1[i] ^ ksfDataRkc->rkMaterial2[i] ^ udid[i];
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

/* todo: separate code of old version using macro */
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

/* todo: separate code of old version using macro */
static int32_t RkcDeriveRmk(const struct HksKsfDataRkc *ksfDataRkc, struct HksBlob *rmk)
{
    struct HksBlob rawKey;
    rawKey.data = (uint8_t *)HksMalloc(HKS_RKC_RAW_KEY_LEN);
    HKS_IF_NULL_LOGE_RETURN(rawKey.data, HKS_ERROR_MALLOC_FAIL, "Malloc rawKey failed!")

    rawKey.size = HKS_RKC_RAW_KEY_LEN;
    (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);

    int32_t ret;
    do {
        /* get the raw key */
        ret = RkcGetRmkRawKey(ksfDataRkc, &rawKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Get rmk raw key failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* PBKDF2-HMAC */
        const struct HksBlob salt = { HKS_RKC_SALT_LEN, (uint8_t *)(ksfDataRkc->rmkSalt) };
        ret = RkcPbkdf2Hmac(ksfDataRkc->rmkHashAlg, &rawKey, &salt, ksfDataRkc->rmkIter, rmk);
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
        ret = RkcHkdfHmac(ksfDataRkc->rmkHashAlg, &rawKey, &salt, ksfDataRkc->rmkIter, rmk);
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

static int32_t ExecuteMkCrypt(const struct HksKsfDataMk *ksfDataMk, const struct HksBlob *rmk,
    struct HksBlob *plainText, struct HksBlob *cipherText, const bool encrypt)
{
    struct HksAeadParam aeadParam;
    (void)memset_s(&aeadParam, sizeof(aeadParam), 0, sizeof(aeadParam));
    struct HksUsageSpec usageSpec = { .algParam = (void *)(&aeadParam) };
    ret = InitMkCryptUsageSpec((uint8_t *)ksfDataMk->mkIv, HKS_RKC_MK_IV_LEN, &usageSpec);
    HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init mk crypt usageSpec failed! ret = 0x%" LOG_PUBLIC "X", ret)

    const struct HksBlob key = { HKS_RKC_RMK_EK_LEN, rmk->data };
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

    return HKS_SUCCESS;
}

/* todo: separate code of old version using macro */
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
        ret = RkcDeriveRmk(&(ksfData->ksfDataRkc), &rmk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Derive rmk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = ExecuteMkCrypt(ksfData->ksfDataMk, &rmk, plainText, cipherText, encrypt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Crypto mk failed! ret = 0x%" LOG_PUBLIC "X", ret)
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

        ret = ExecuteMkCrypt(ksfDataMk, &rmk, plainText, cipherText, encrypt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Crypto mk failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    /* the data of root key should be cleared after use */
    (void)memset_s(rmk.data, rmk.size, 0, rmk.size);
    HKS_FREE_BLOB(rmk);
    return ret;
}

// static void RkcMaskMk(const struct HksBlob *mk)
// {
//     for (uint32_t i = 0; i < HKS_RKC_MK_LEN; ++i) {
//         g_hksRkcMk.mkWithMask[i] = mk->data[i] ^ g_hksRkcCfg.mkMask[i];
//     }

//     g_hksRkcMk.valid = true;
// }

static int32_t RkcMaskMk(const struct HksBlob *mk)
{
    struct HksBlob mkMaskBlob = { HKS_RKC_MK_LEN, g_hksRkcCfg.mkMask };
    int32_t ret = HksCryptoHalFillPrivRandom(&mkMaskBlob);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, "Generate mk mask failed! ret = 0x%" LOG_PUBLIC "X", ret)

    for (uint32_t i = 0; i < HKS_RKC_MK_LEN; ++i) {
        g_hksRkcMk.mkWithMask[i] = mk->data[i] ^ g_hksRkcCfg.mkMask[i];
    }

    g_hksRkcMk.valid = true;
    return ret;
}

static int32_t RkcRecoverMkTime(const struct HksKsfDataMk *ksfDataMk)
{
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

    return HKS_SUCCESS;
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
    if (ksfCount > HKS_KSF_NUM) {
        HKS_LOG_E("Invalid ksf count!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
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
    struct HksRkcKsfData *validKsfData = NULL;
    int32_t ret;
    do {
        ret = RkcReadAllKsf(&validKsfData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All rkc ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcRecoverRkTime(validKsfData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover root key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcRecoverMkTime(validKsfData, NULL);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover main key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

        HksBlob tempMkBlob = { HKS_RKC_MK_LEN, g_hksRkcMk.mkWithMask };
        struct HksBlob mkCipherText = { HKS_RKC_MK_CIPHER_TEXT_LEN, (uint8_t *)validKsfData->mkCiphertext };
        ret = RkcMkCrypt(validKsfData, &tempMkBlob, &mkCipherText, false); /* false: decrypt */
        HKS_IF_NOT_SUCC_LOGE(ret, "Main key crypt failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    HKS_MEMSET_FREE_PTR(validKsfData);
    return ret;
}

// static int32_t RkcLoadKsfV2(struct HksKsfDataRkc **validKsfData)
// {
//     const uint32_t allKsfDataSize = sizeof(struct HksKsfDataRkc) * HKS_KSF_NUM;
//     struct HksKsfDataRkc *allKsfData = (struct HksKsfDataRkc *)HksMalloc(allKsfDataSize);
//     HKS_IF_NULL_LOGE_RETURN(allKsfData, HKS_ERROR_MALLOC_FAIL,
//         "Malloc all rkc ksf data failed! malloc size = 0x%" LOG_PUBLIC "X", allKsfDataSize)

//     (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);

//     int32_t ret;
//     do {
//         int32_t allKsfRet[HKS_KSF_NUM] = {0};
//         uint32_t validKsfIndex = 0;

//         ret = RkcReadAllKsf(allKsfRet, allKsfData, HKS_KSF_NUM, validKsfData, &validKsfIndex);
//         HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All rkc ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

//         ret = RkcRecoverRkTime(validKsfData);
//         HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover root key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

//         ret = RkcCheckAllKsf(allKsfRet, allKsfData, HKS_KSF_NUM, validKsfData, validKsfIndex);
//         HKS_IF_NOT_SUCC_LOGE(ret, "Check all rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
//     } while (0);

//     (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);
//     HKS_FREE_PTR(allKsfData);
//     return ret;
// }

// static int32_t MkLoadKsf(struct HksKsfDataRkc *validKsfDataRkc)
// {
//     const uint32_t allKsfDataSize = sizeof(struct HksKsfDataMk) * HKS_KSF_NUM;
//     struct HksKsfDataMk *allKsfData = (struct HksKsfDataMk *)HksMalloc(allKsfDataSize);
//     HKS_IF_NULL_LOGE_RETURN(allKsfData, HKS_ERROR_MALLOC_FAIL,
//         "Malloc all mk ksf data failed! malloc size = 0x%" LOG_PUBLIC "X", allKsfDataSize)

//     (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);

//     struct HksBlob mk = { 0, NULL };
//     int32_t ret;
//     do {
//         int32_t allKsfRet[HKS_KSF_NUM] = {0};
//         uint32_t validKsfIndex = 0;
//         struct HksKsfDataMk *validKsfData = NULL;

//         ret = MkReadAllKsf(allKsfRet, allKsfData, HKS_KSF_NUM, &validKsfData, &validKsfIndex);
//         HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All mk ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

//         ret = RkcRecoverMkTime(NULL, validKsfData);
//         HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover main key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

//         mk.data = (uint8_t *)HksMalloc(HKS_RKC_MK_LEN);
//         HKS_IF_NULL_LOGE_RETURN(mk.data, HKS_ERROR_MALLOC_FAIL, "Malloc mk failed!")

//         mk.size = HKS_RKC_MK_LEN;

//         struct HksBlob mkCipherText = { HKS_RKC_MK_CIPHER_TEXT_LEN, (uint8_t *)ksfData->mkCiphertext };
//         ret = RkcMkCrypt(ksfDataRkc, &mk, &mkCipherText, false); /* false: decrypt */
//         HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Main key crypt failed! ret = 0x%" LOG_PUBLIC "X", ret)

//         /* the main key in memory should be masked */
//         ret = RkcMaskMk(&mk);

//         ret = RkcCheckAllKsf(allKsfRet, allKsfData, HKS_KSF_NUM, validKsfData, validKsfIndex);
//         HKS_IF_NOT_SUCC_LOGE(ret, "Check all mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
//     } while (0);

//     (void)memset_s(allKsfData, allKsfDataSize, 0, allKsfDataSize);
//     HKS_FREE_PTR(allKsfData);
//     (void)memset_s(mk.data, mk.size, 0, mk.size);
//     HKS_FREE_BLOB(mk);
//     return ret;
// }

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

        /* generate the IV of main key */
        struct HksBlob mkIvBlob = { HKS_RKC_MK_IV_LEN, ksfDataMk->mkIv };
        ret = HksCryptoHalFillPrivRandom(&mkIvBlob);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate mkIv failed! ret = 0x%" LOG_PUBLIC "X", ret)

        struct HksBlob cipherTextBlob = { HKS_RKC_MK_CIPHER_TEXT_LEN, ksfDataMk->mkCiphertext };
        ret = RkcMkCryptV2(ksfDataRkc, ksfDataMk, &mk, &cipherTextBlob, true); /* true: encrypt */
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Encrypt mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* the main key in memory should be masked */
        ret = RkcMaskMk(&mk);
    } while (0);

    (void)memset_s(mk.data, mk.size, 0, mk.size);
    HKS_FREE_BLOB(mk);
    return ret;
}

static int32_t RkcWriteAllKsf(const struct HksKsfDataRkc *ksfDataRkc, const struct HksKsfDataMk *ksfDataMk)
{
    bool isSuccess = false;
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        int32_t ret = HksRkcWriteKsf(g_hksRkcCfg.ksfAttrRkc.name[i], ksfDataRkc);
    }
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        int32_t ret = HksMkWriteKsf(g_hksRkcCfg.ksfAttrMk.name[i], ksfDataMk);
        if (ret == HKS_SUCCESS) {
            isSuccess = true;
        }
    }

    /* If all keystore file were written fail, return error code, otherwise, return success code. */
    return (isSuccess ? HKS_SUCCESS : HKS_ERROR_WRITE_FILE_FAIL);
}

static struct HksKsfDataRkc *CreateNewKsfDataRkc(void)
{
    struct HksKsfDataRkc *newKsfDataRkc = (struct HksKsfDataRkc *)HksMalloc(sizeof(struct HksKsfDataRkc));
    HKS_IF_NULL_LOGE_RETURN(newKsfDataRkc, NULL, "Malloc rkc ksf data failed!")

    (void)memset_s(newKsfDataRkc, sizeof(struct HksKsfDataRkc), 0, sizeof(struct HksKsfDataRkc));
    newKsfDataRkc->rkVersion = g_hksRkcCfg.rkVersion;
    newKsfDataRkc->rmkIter = g_hksRkcCfg.rmkIter;
    newKsfDataRkc->rmkHashAlg = g_hksRkcCfg.rmkHashAlg;

    do {
        /* Two material are generated by random number. */
        ret = RkcMakeRandomMaterial(newKsfDataRkc);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate material failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* The salt value is generated by random number. */
        struct HksBlob salt = { HKS_RKC_SALT_LEN, newKsfDataRkc->rmkSalt };
        ret = HksCryptoHalFillPrivRandom(&salt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate salt failed! ret = 0x%" LOG_PUBLIC "X", ret)

        return newKsfDataRkc;
    } while (0);
    HKS_MEMSET_FREE_PTR(newKsfDataRkc);
    return NULL;
}

static struct HksKsfDataMk *CreateNewKsfDataMk(void)
{
    struct HksKsfDataMk *newKsfDataMk = (struct HksKsfDataMk *)HksMalloc(sizeof(struct HksKsfDataMk));
    HKS_IF_NULL_LOGE_RETURN(newKsfDataMk, NULL, "Malloc mk ksf data failed!")

    (void)memset_s(newKsfDataMk, sizeof(struct HksKsfDataMk), 0, sizeof(struct HksKsfDataMk));

    newKsfDataMk->mkVersion = g_hksRkcCfg.mkVersion;
    newKsfDataMk->mkEncryptAlg = g_hksRkcCfg.mkEncryptAlg;
    return newKsfDataMk;
}

static int32_t RkcCreateKsf(void)
{
    struct HksKsfDataRkc *newKsfDataRkc = NULL;
    struct HksKsfDataMk *newKsfDataMk = NULL;
    int32_t ret;
    do {
        newKsfDataRkc = CreateNewKsfDataRkc();
        HKS_IF_NULL_LOGE_BREAK(newKsfDataRkc, HKS_ERROR_MALLOC_FAIL, "Malloc rkc ksf data failed!")
        newKsfDataMk = CreateNewKsfDataMk();
        HKS_IF_NULL_LOGE_BREAK(newKsfDataMk, HKS_ERROR_MALLOC_FAIL, "Malloc mk ksf data failed!")

        /* make main key. */
        ret = RkcMakeMk(newKsfDataRkc, newKsfDataMk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "make mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* Write the root key component and the main key data into all keystore files */
        ret = RkcWriteAllKsf(newKsfDataRkc, newKsfDataMk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Write rkc & mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    /* the data of root&main key should be cleared after use */
    HKS_MEMSET_FREE_PTR(newKsfDataRkc);
    HKS_MEMSET_FREE_PTR(newKsfDataMk);
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

static int32_t InitKsfAttr(const struct HksKsfAttr *ksfAttr, uint8_t ksfType)
{
    int32_t initRet = HKS_SUCCESS;

    /* clone keystore filename from parameter. */
    for (uint8_t i = 0; i < HKS_KSF_NUM; ++i) {
        char *fileName = CloneNewStr(ksfAttr->name[i], HKS_KSF_NAME_LEN_MAX);
        /* the memory will be freed by HksCfgDestroy() */
        if (fileName != NULL) {
            initRet = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        if (ksfType == HKS_KSF_TYPE_RKC) {
            g_hksRkcCfg.ksfAttrRkc.name[i] = fileName;
            // g_hksRkcCfg.ksfAttrRkc.num = ksfAttr->num;
        } else {
            g_hksRkcCfg.ksfAttrMk.name[i] = fileName;
            // g_hksRkcCfg.ksfAttrMk.num = ksfAttr->num;
        }
    }

    if (initRet != HKS_SUCCESS) {
        HksCfgClearMem();
    }
    return initRet;
}

// todo: 更新完RKC文件后，需要将全局变量中RKC的文件名改成新的，再落盘
static int32_t UpgradeMkIfNeeded(uint32_t mkVersion, const struct HksBlob *mk)
{
    if (mkVersion == HKS_MK_VER) {
        return HKS_SUCCESS; // no need upgrade
    }
    // reserved function for future upgrade, e.g. version 2->3
    return HKS_ERROR_NOT_SUPPORTED;
}

static int32_t ReadMk()
{
    int32_t ret;
    struct HksKsfDataMk *validKsfDataMk = NULL;
    struct HksKsfDataRkc *validKsfDataRkc = NULL;
    do {
        struct HksKsfAttr mkAttr = { "minfo1_v2.data", "minfo2_v2.data" };
        /* Initialize the attribute of mk keystore file */
        ret = InitKsfAttr(&mkAttr, HKS_KSF_TYPE_MK);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = MkReadAllKsf(&validKsfDataMk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All mk ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcRecoverMkTime(validKsfDataMk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover main key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

        struct HksKsfAttr rkcAttr = { "rinfo1_v2.data", "rinfo2_v2.data" };
        /* Initialize the attribute of rkc keystore file */
        ret = InitKsfAttr(&rkcAttr, HKS_KSF_TYPE_RKC);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

        // HKS_LOG_I("Rkc ksf is exist, start to load ksf");

        ret = RkcReadAllKsfV2(&validKsfDataRkc);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All rkc ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcRecoverRkTime(validKsfData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover root key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)
    
        // ret = RkcLoadKsfV2(&validKsfDataRkc);
        // HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Load rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)

        // decrypt main key
        struct HksBlob tempMkBlob = { HKS_RKC_MK_LEN, g_hksRkcMk.mkWithMask };
        struct HksBlob mkCipherText = { HKS_RKC_MK_CIPHER_TEXT_LEN, validKsfDataMk->mkCiphertext };
        ret = RkcMkCrypt(validKsfDataRkc, &tempMkBlob, &mkCipherText, false); /* false: decrypt */
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Main key crypt failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* the main key in memory should be masked */
        ret = RkcMaskMk(&tempMkBlob);
        HKS_IF_NOT_SUCC_BREAK(ret);

        ret = UpgradeMkIfNeeded(validKsfDataMk->mkVersion, &mk);
        // todo delete old files
    } while (0);

    HKS_MEMSET_FREE_PTR(validKsfDataRkc, sizeof(struct HksKsfDataRkc));
    HKS_MEMSET_FREE_PTR(validKsfDataMk, sizeof(struct HksKsfDataMk));
    return ret;
}

static int32_t UpgradeVersion1ToVersion2()
{
    /* Initialize the attribute of rkc keystore file */
    struct HksKsfAttr ksfAttrRkc = { "info1.data", "info2.data" };
    ret = InitKsfAttr(&ksfAttrRkc, HKS_KSF_TYPE_RKC);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

    HKS_LOG_I("Rkc ksf is exist, start to load ksf");
    ret = RkcLoadKsf();
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, "Load rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)

    // generate new materials and encrypt main key
    struct HksKsfDataRkc *newKsfDataRkc = NULL;
    struct HksKsfDataMk *newKsfDataMk = NULL;

    do {
        newKsfDataRkc = CreateNewKsfDataRkc();
        HKS_IF_NULL_LOGE_BREAK(newKsfDataRkc, HKS_ERROR_MALLOC_FAIL, "Malloc rkc ksf data failed!")
        newKsfDataMk = CreateNewKsfDataMk();
        HKS_IF_NULL_LOGE_BREAK(newKsfDataMk, HKS_ERROR_MALLOC_FAIL, "Malloc mk ksf data failed!")

        HksBlob tempMkBlob = { HKS_RKC_MK_LEN, g_hksRkcMk.mkWithMask };
        struct HksBlob cipherTextBlob = { HKS_RKC_MK_CIPHER_TEXT_LEN, newKsfDataMk->mkCiphertext };
        ret = RkcMkCryptV2(newKsfDataRkc, newKsfDataMk, &tempMkBlob, &cipherTextBlob, true); /* true: encrypt */
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Encrypt mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* Write the root key component and the main key data into all keystore files */
        ret = RkcWriteAllKsf(newKsfDataRkc, newKsfDataMk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Write rkc & mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
        
        ret = RkcMaskMk(&tempMkBlob);
    } while (0);

    /* the data of root&main key should be cleared after use */
    HKS_MEMSET_FREE_PTR(newKsfDataRkc);
    HKS_MEMSET_FREE_PTR(newKsfDataMk);

    // todo delete old files
    return ret;
}

int32_t HksRkcInit(void)
{
    if (g_hksRkcCfg.state == HKS_RKC_STATE_VALID) {
        HKS_LOG_I("Hks rkc is running!");NULL
        return HKS_SUCCESS;
    }

    int32_t ret;

    if (KsfExist(HKS_KSF_TYPE_MK)) {
        ret = ReadMk();
    } else if (KsfExist(HKS_KSF_TYPE_RKC)) { // mk not exist,  rkc keystore file exists => version 1
        ret = UpgradeVersion1ToVersion2();
    } else { // latest version
        ret = RkcCreateKsf();
    }

    if (ret != HKS_SUCCESS) {
        (void)HksCfgDestroy();
        (void)HksMkDestroy();
        return ret;
    }

    g_hksRkcCfg.state = HKS_RKC_STATE_VALID;
    return HKS_SUCCESS;
}

void HksCfgDestroy(void)
{
    g_hksRkcCfg.state = HKS_RKC_STATE_INVALID;
    HksCfgClearMem();
}

void HksMkDestroy(void)
{
    HksMkClearMem();
}

void HksCfgClearMem(void)
{
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        HKS_FREE_PTR(g_hksRkcCfg.ksfAttrRkc.name[i]);
        HKS_FREE_PTR(g_hksRkcCfg.ksfAttrMk.name[i]);
    }

    (void)memset_s(&g_hksRkcCfg, sizeof(g_hksRkcCfg), 0, sizeof(g_hksRkcCfg));
    // (void)memset_s(&g_hksRkcMk, sizeof(g_hksRkcMk), 0, sizeof(g_hksRkcMk));
}

void HksMkClearMem(void)
{
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
