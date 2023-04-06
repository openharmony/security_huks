/*
 * Copyright (c) 2020-2023 Huawei Device Co., Ltd.
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
#include "hks_rkc_v1.h"
#include "hks_template.h"

/* the configuration of root key component */
static struct HksRkcCfg g_hksRkcCfg = {
    .state = HKS_RKC_STATE_INVALID,
    .rkVersion = HKS_RKC_VER,
    .mkVersion = HKS_MK_VER,
    .storageType = HKS_RKC_STORAGE_FILE_SYS,
    .rkCreatedTime = { 0, 0, 0, 0, 0, 0 },
    .rkExpiredTime = { 0, 0, 0, 0, 0, 0 },
    .ksfAttrRkc = { NULL, NULL },
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

/* the data of main key */
struct HksRkcMk g_hksRkcMk = { false, { 0, 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0, 0 }, {0} };

/* the additional data of main key. 'H', 'K', 'S', 'R', 'K', 'C', 'M', 'K' */
const uint8_t g_hksRkcMkAddData[HKS_RKC_MK_ADD_DATA_LEN] = { 0x48, 0x4B, 0x53, 0x52, 0x4B, 0x43, 0x4D, 0x4B };

static int32_t ReadAllKsfRkc(struct HksKsfDataRkcWithVer **validKsfData)
{
    /* Read all rkc ksf */
    int32_t readRet[HKS_KSF_NUM] = { 0 };
    struct HksKsfDataRkcWithVer allRkcData[HKS_KSF_NUM] = { 0 };
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

    for (uint32_t i = 0; i < HKS_KSF_NUM; i++) {
        if (readRet[i] != HKS_SUCCESS) {
            int32_t ret = HksWriteKsfRkc(g_hksRkcCfg.ksfAttrRkc.name[i], allRkcData[validIndex]);
            HKS_IF_NOT_SUCC_LOGE(ret, "rewrite rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
        }
    }

    *validKsfData = (struct HksKsfDataRkcWithVer *)HksMalloc(sizeof(struct HksKsfDataRkcWithVer));
    if (validKsfData == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(*validKsfData, sizeof(struct HksKsfDataRkcWithVer),
        allRkcData[validIndex], sizeof(struct HksKsfDataRkcWithVer));
    return HKS_SUCCESS;
}

static int32_t ReadAllKsfMk(struct HksKsfDataMkWithVer **validKsfData)
{
    /* Read all ksf */
    int32_t readRet[HKS_KSF_NUM] = { 0 };
    struct HksKsfDataMkWithVer allMkData[HKS_KSF_NUM] = { 0 };
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

    for (uint32_t i = 0; i < HKS_KSF_NUM; i++) {
        if (readRet[i] != HKS_SUCCESS) {
            int32_t ret = HksWriteKsfMk(g_hksRkcCfg.ksfAttrMk.name[i], allMkData[validIndex]);
            HKS_IF_NOT_SUCC_LOGE(ret, "rewrite mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
        }
    }

    *validKsfData = (struct HksKsfDataMkWithVer *)HksMalloc(sizeof(struct HksKsfDataMkWithVer));
    if (validKsfData == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(*validKsfData, sizeof(struct HksKsfDataMkWithVer),
        allMkData[validIndex], sizeof(struct HksKsfDataMkWithVer));
    return HKS_SUCCESS;
}

static int32_t RkcGetRmkRawKey(const struct HksKsfDataRkc *ksfDataRkc, struct HksBlob *rawKey)
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

        /* HKDF-HMAC */
        const struct HksBlob salt = { HKS_RKC_SALT_LEN, (uint8_t *)(ksfDataRkc->rmkSalt) };
        ret = RkcHkdfHmac(ksfDataRkc->rmkHashAlg, &rawKey, &salt, ksfDataRkc->rmkIter, rmk);
        HKS_IF_NOT_SUCC_LOGE(ret, "HKDF failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);
    HKS_FREE_BLOB(rawKey);
    return ret;
}

int32_t RkcRecoverRkTime(const struct HksKsfDataRkc *ksfDataRkc)
{
    if (memcpy_s(&(g_hksRkcCfg.rkCreatedTime), sizeof(g_hksRkcCfg.rkCreatedTime),
        &(ksfDataRkc->rkCreatedTime), sizeof(ksfDataRkc->rkCreatedTime)) != EOK) {
        HKS_LOG_E("Memcpy rkCreatedTime failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    if (memcpy_s(&(g_hksRkcCfg.rkExpiredTime), sizeof(g_hksRkcCfg.rkExpiredTime),
        &(ksfDataRkc->rkExpiredTime), sizeof(ksfDataRkc->rkExpiredTime)) != EOK) {
        HKS_LOG_E("Memcpy rkExpiredTime failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    return HKS_SUCCESS;
}

int32_t RkcRecoverMkTime(const struct HksKsfDataMk *ksfDataMk)
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

int32_t ExecuteMkCrypt(const struct HksKsfDataMk *ksfDataMk, const struct HksBlob *rmk,
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

int32_t RkcMkCrypt(const struct HksKsfDataRkc *ksfDataRkc, const struct HksKsfDataMk *ksfDataMk,
    struct HksBlob *plainText, struct HksBlob *cipherText, const bool encrypt)
{
    struct HksBlob rmk;
    rmk.data = (uint8_t *)HksMalloc(HKS_RKC_RMK_LEN);
    HKS_IF_NULL_LOGE_RETURN(rmk.data, HKS_ERROR_MALLOC_FAIL, "Malloc rmk failed!")

    rmk.size = HKS_RKC_RMK_LEN;
    (void)memset_s(rmk.data, rmk.size, 0, rmk.size);

    int32_t ret;
    do {
        ret = RkcDeriveRmk(ksfDataRkc, &rmk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Derive rmk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = ExecuteMkCrypt(ksfDataMk, &rmk, plainText, cipherText, encrypt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Crypto mk failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    /* the data of root key should be cleared after use */
    (void)memset_s(rmk.data, rmk.size, 0, rmk.size);
    HKS_FREE_BLOB(rmk);
    return ret;
}

int32_t RkcMaskMk(const struct HksBlob *mk)
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
        ret = RkcMkCrypt(ksfDataRkc, ksfDataMk, &mk, &cipherTextBlob, true); /* true: encrypt */
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Encrypt mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* the main key in memory should be masked */
        ret = RkcMaskMk(&mk);
    } while (0);

    (void)memset_s(mk.data, mk.size, 0, mk.size);
    HKS_FREE_BLOB(mk);
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

int32_t InitKsfAttr(const struct HksKsfAttr *ksfAttr, uint8_t ksfType)
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
        } else {
            g_hksRkcCfg.ksfAttrMk.name[i] = fileName;
        }
    }

    if (initRet != HKS_SUCCESS) {
        HksCfgClearMem();
    }
    return initRet;
}

static int32_t UpgradeMkIfNeeded(uint32_t mkVersion, const struct HksBlob *mk)
{
    if (mkVersion == HKS_MK_VER) {
        return HKS_SUCCESS; // no need upgrade
    }
    // reserved function for future upgrade, e.g. version 2->3
    return HKS_ERROR_NOT_SUPPORTED;
}

static int32_t RkcLoadKsf()
{
    int32_t ret;
    struct HksKsfDataMkWithVer *validKsfDataMkWithVer = NULL;
    struct HksKsfDataRkcWithVer *validKsfDataRkcWithVer = NULL;
    do {
        ret = ReadAllKsfMk(&validKsfDataMkWithVer);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All mk ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcRecoverMkTime(&(validKsfDataMkWithVer->ksfDataMk));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover main key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* Initialize the attribute of rkc keystore file */
        struct HksKsfAttr ksfAttrRkc = { "rinfo1_v2.data", "rinfo2_v2.data" };
        ret = InitKsfAttr(&ksfAttrRkc, HKS_KSF_TYPE_RKC);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = ReadAllKsfRkc(&validKsfDataRkcWithVer);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All rkc ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcRecoverRkTime(&(validKsfDataRkcWithVer->ksfDataRkc));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover root key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

        // decrypt main key
        struct HksBlob tempMkBlob = { HKS_RKC_MK_LEN, g_hksRkcMk.mkWithMask };
        struct HksBlob mkCipherText = { HKS_RKC_MK_CIPHER_TEXT_LEN, validKsfDataMkWithVer->ksfDataMk.mkCiphertext };
        ret = RkcMkCrypt(&(validKsfDataRkcWithVer->ksfDataRkc), &tempMkBlob, &mkCipherText, false); /* false: decrypt */
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Main key decrypt failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* the main key in memory should be masked */
        ret = RkcMaskMk(&tempMkBlob);
        HKS_IF_NOT_SUCC_BREAK(ret);

        ret = UpgradeMkIfNeeded(validKsfDataMk->mkVersion, &mk);
    } while (0);

    HKS_MEMSET_FREE_PTR(validKsfDataRkc, sizeof(struct HksKsfDataRkc));
    HKS_MEMSET_FREE_PTR(validKsfDataMk, sizeof(struct HksKsfDataMk));
    return ret;
}

struct HksKsfDataRkcWithVer *CreateNewKsfDataRkcWithVer(void)
{
    struct HksKsfDataRkcWithVer *newKsfDataRkc = (struct HksKsfDataRkcWithVer *)HksMalloc(sizeof(struct HksKsfDataRkcWithVer));
    HKS_IF_NULL_LOGE_RETURN(newKsfDataRkc, NULL, "Malloc rkc ksf data failed!")

    (void)memset_s(newKsfDataRkc, sizeof(struct HksKsfDataRkcWithVer), 0, sizeof(struct HksKsfDataRkcWithVer));
    newKsfDataRkc->rkVersion = g_hksRkcCfg.rkVersion;
    newKsfDataRkc->ksfDataRkc.rmkIter = g_hksRkcCfg.rmkIter;
    newKsfDataRkc->ksfDataRkc.rmkHashAlg = g_hksRkcCfg.rmkHashAlg;

    do {
        /* Two material are generated by random number. */
        ret = RkcMakeRandomMaterial(&(newKsfDataRkc->ksfDataRkc));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate material failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* The salt value is generated by random number. */
        struct HksBlob salt = { HKS_RKC_SALT_LEN, newKsfDataRkc->ksfDataRkc.rmkSalt };
        ret = HksCryptoHalFillPrivRandom(&salt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate salt failed! ret = 0x%" LOG_PUBLIC "X", ret)

        return newKsfDataRkc;
    } while (0);
    HKS_MEMSET_FREE_PTR(newKsfDataRkc);
    return NULL;
}

struct HksKsfDataMkWithVer *CreateNewKsfDataMkWithVer(void)
{
    struct HksKsfDataMkWithVer *newKsfDataMk = (struct HksKsfDataMkWithVer *)HksMalloc(sizeof(struct HksKsfDataMkWithVer));
    HKS_IF_NULL_LOGE_RETURN(newKsfDataMk, NULL, "Malloc mk ksf data failed!")

    (void)memset_s(newKsfDataMk, sizeof(struct HksKsfDataMkWithVer), 0, sizeof(struct HksKsfDataMkWithVer));
    newKsfDataMk->mkVersion = g_hksRkcCfg.mkVersion;
    newKsfDataMk->ksfDataMk.mkEncryptAlg = g_hksRkcCfg.mkEncryptAlg;

    return newKsfDataMk;
}

int32_t RkcWriteAllKsf(const struct HksKsfDataRkcWithVer *ksfDataRkcWithVer, const struct HksKsfDataMkWithVer *ksfDataMkWithVer)
{
    bool isSuccess = false;
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        int32_t ret = HksWriteKsfRkc(g_hksRkcCfg.ksfAttrRkc.name[i], ksfDataRkc);
    }
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        int32_t ret = HksWriteKsfMk(g_hksRkcCfg.ksfAttrMk.name[i], ksfDataMk);
        if (ret == HKS_SUCCESS) {
            isSuccess = true;
        }
    }

    /* If all keystore file were written fail, return error code, otherwise, return success code. */
    return (isSuccess ? HKS_SUCCESS : HKS_ERROR_WRITE_FILE_FAIL);
}

static int32_t RkcCreateKsf(void)
{
    int32_t ret;
    struct HksKsfDataRkcWithVer *newKsfDataRkcWithVer = NULL;
    struct HksKsfDataMkWithVer *newKsfDataMkWithVer = NULL;

    do {
        newKsfDataRkcWithVer = CreateNewKsfDataRkcWithVer();
        HKS_IF_NULL_LOGE_BREAK(newKsfDataRkcWithVer, HKS_ERROR_MALLOC_FAIL, "Malloc rkc ksf data failed!")
        newKsfDataMkWithVer = CreateNewKsfDataMkWithVer();
        HKS_IF_NULL_LOGE_BREAK(newKsfDataMkWithVer, HKS_ERROR_MALLOC_FAIL, "Malloc mk ksf data failed!")

        /* make main key. */
        ret = RkcMakeMk(&(newKsfDataRkcWithVer->ksfDataRkc), &(newKsfDataMkWithVer->ksfDataMk));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "make mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* Initialize rkc keystore file name (mk already done in HksRkcInit) */
        struct HksKsfAttr ksfAttrRkc = { "rinfo1_v2.data", "rinfo2_v2.data" };
        ret = InitKsfAttr(&ksfAttrRkc, HKS_KSF_TYPE_RKC);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* Write the root key component and the main key data into all keystore files */
        ret = RkcWriteAllKsf(newKsfDataRkcWithVer, newKsfDataMkWithVer);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Write rkc & mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    /* the data of root & main key should be cleared after use */
    HKS_MEMSET_FREE_PTR(newKsfDataRkcWithVer);
    HKS_MEMSET_FREE_PTR(newKsfDataMkWithVer);
    return ret;
}

int32_t HksRkcInit(void)
{
    if (g_hksRkcCfg.state == HKS_RKC_STATE_VALID) {
        HKS_LOG_I("Hks rkc is running!");NULL
        return HKS_SUCCESS;
    }

    /* Initialize the attribute of mk keystore file */
    struct HksKsfAttr ksfAttrMk = { "minfo1_v2.data", "minfo2_v2.data" };
    ret = InitKsfAttr(&ksfAttrMk, HKS_KSF_TYPE_MK);
    HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of mk keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

    int32_t ret;
    if (KsfExist(HKS_KSF_TYPE_MK)) {
        ret = RkcLoadKsf();
    } else {
        /* Initialize the attribute of rkc keystore file */
        struct HksKsfAttr ksfAttrRkcV1 = { "info1.data", "info2.data" };
        ret = InitKsfAttr(&ksfAttrRkcV1, HKS_KSF_TYPE_RKC);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

        if (KsfExist(HKS_KSF_TYPE_RKC)) { // mk ksf not exists, rkc ksf exists => version 1
            ret = UpgradeV1ToV2();
        } else { // latest version
            ret = RkcCreateKsf();
        }
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
