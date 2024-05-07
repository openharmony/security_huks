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
#include "hks_param.h"
#include "hks_template.h"

#ifdef HKS_ENABLE_UPGRADE_RKC_DERIVE_ALG
#include "hks_rkc_v1.h"
#endif

/* the configuration of root key component */
static struct HksRkcCfg g_hksRkcCfg = {
    .state = HKS_RKC_STATE_INVALID,
    .rkVersion = HKS_RKC_VER,
    .mkVersion = HKS_MK_VER,
    .storageType = HKS_RKC_STORAGE_FILE_SYS,
    .rkCreatedTime = { 0, 0, 0, 0, 0, 0 },
    .rkExpiredTime = { 0, 0, 0, 0, 0, 0 },
    .ksfAttrRkc = {{ NULL, NULL }},
    .ksfAttrMk = {{ NULL, NULL }},
    .rmkIter = HKS_RKC_RMK_ITER,
    .rmkHashAlg = HKS_RKC_RMK_HMAC_SHA256,
    .mkMask = {0},
    .mkEncryptAlg = HKS_RKC_MK_CRYPT_ALG_AES256_GCM,
    .reserve = {0}
};

const struct HksKsfAttr *GetGlobalKsfAttrRkc(void)
{
    return &g_hksRkcCfg.ksfAttrRkc;
}

const struct HksKsfAttr *GetGlobalKsfAttrMk(void)
{
    return &g_hksRkcCfg.ksfAttrMk;
}

/* the data of main key */
struct HksRkcMk g_hksRkcMk = { false, { 0, 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0, 0 }, {0} };

/* the additional data of main key. 'H', 'K', 'S', 'R', 'K', 'C', 'M', 'K' */
const uint8_t g_hksRkcMkAddData[HKS_RKC_MK_ADD_DATA_LEN] = { 0x48, 0x4B, 0x53, 0x52, 0x4B, 0x43, 0x4D, 0x4B };

static int32_t ReadAllKsfRkc(struct HksKsfDataRkcWithVer *validKsfData)
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
            int32_t ret = HksWriteKsfRkc(g_hksRkcCfg.ksfAttrRkc.name[i], &allRkcData[validIndex]);
            HKS_IF_NOT_SUCC_LOGE(ret, "rewrite rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
        }
    }

    (void)memcpy_s(validKsfData, sizeof(struct HksKsfDataRkcWithVer),
        &allRkcData[validIndex], sizeof(struct HksKsfDataRkcWithVer));
    return HKS_SUCCESS;
}

static int32_t ReadAllKsfMk(struct HksKsfDataMkWithVer *validKsfData)
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
            int32_t ret = HksWriteKsfMk(g_hksRkcCfg.ksfAttrMk.name[i], &allMkData[validIndex]);
            HKS_IF_NOT_SUCC_LOGE(ret, "rewrite mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
        }
    }

    (void)memcpy_s(validKsfData, sizeof(struct HksKsfDataMkWithVer),
        &allMkData[validIndex], sizeof(struct HksKsfDataMkWithVer));
    return HKS_SUCCESS;
}

static int32_t RkcGetRmkRawKey(const struct HksKsfDataRkc *ksfDataRkc, struct HksBlob *rawKey)
{
    uint8_t udid[HKS_HARDWARE_UDID_LEN] = {0};
    int32_t ret = HksGetHardwareUdid(udid, HKS_HARDWARE_UDID_LEN);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Get hardware udid failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* materials xor */
    for (uint32_t i = 0; i < HKS_RKC_MATERIAL_LEN; ++i) {
        rawKey->data[i] = ksfDataRkc->rkMaterial1[i] ^ ksfDataRkc->rkMaterial2[i] ^ udid[i];
    }

    (void)memset_s(udid, HKS_HARDWARE_UDID_LEN, 0, HKS_HARDWARE_UDID_LEN);
    return HKS_SUCCESS;
}

uint32_t RkcDigestToHks(const uint32_t rkcDigest)
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

void RkcRecoverRkTime(struct HksTime createdTime, struct HksTime expiredTime)
{
    g_hksRkcCfg.rkCreatedTime = createdTime;
    g_hksRkcCfg.rkExpiredTime = expiredTime;
}

void RkcRecoverMkTime(struct HksTime createdTime, struct HksTime expiredTime)
{
    g_hksRkcMk.mkCreatedTime = createdTime;
    g_hksRkcMk.mkExpiredTime = expiredTime;
}

static int32_t RkcMakeRandomMaterial(struct HksKsfDataRkc *ksfDataRkc)
{
    /* two random number */
    struct HksBlob random1 = { HKS_RKC_MATERIAL_LEN, ksfDataRkc->rkMaterial1 };
    struct HksBlob random2 = { HKS_RKC_MATERIAL_LEN, ksfDataRkc->rkMaterial2 };

    int32_t ret;
    /* Generate 32 * 2 random number: R1 + R2 and fill material */
    ret = HksCryptoHalFillPrivRandom(&random1);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Generate random1 failed! ret = 0x%" LOG_PUBLIC "X", ret)
    ret = HksCryptoHalFillPrivRandom(&random2);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Generate random2 failed! ret = 0x%" LOG_PUBLIC "X", ret);
        (void)memset_s(random1.data, HKS_RKC_MATERIAL_LEN, 0, HKS_RKC_MATERIAL_LEN);
    }
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
    int32_t ret = InitMkCryptUsageSpec((uint8_t *)ksfDataMk->mkIv, HKS_RKC_MK_IV_LEN, &usageSpec);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Init mk crypt usageSpec failed! ret = 0x%" LOG_PUBLIC "X", ret)

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

    return ret;
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
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Generate mk mask failed! ret = 0x%" LOG_PUBLIC "X", ret)

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
        HKS_FREE(newBuf);
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
        if (fileName == NULL) {
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
    (void)mk;
    return HKS_SUCCESS;
}

static int32_t RkcLoadKsf(void)
{
    int32_t ret;
    struct HksKsfDataRkcWithVer *validKsfDataRkcWithVer =
        (struct HksKsfDataRkcWithVer *)HksMalloc(sizeof(struct HksKsfDataRkcWithVer));
    struct HksKsfDataMkWithVer *validKsfDataMkWithVer =
        (struct HksKsfDataMkWithVer *)HksMalloc(sizeof(struct HksKsfDataRkcWithVer));
    do {
        if (validKsfDataRkcWithVer == NULL || validKsfDataMkWithVer == NULL) {
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        ret = ReadAllKsfMk(validKsfDataMkWithVer);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All mk ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

        RkcRecoverMkTime(validKsfDataMkWithVer->ksfDataMk.mkCreatedTime,
            validKsfDataMkWithVer->ksfDataMk.mkExpiredTime);

        /* Initialize the attribute of rkc keystore file */
        struct HksKsfAttr ksfAttrRkc = {{ "rinfo1_v2.data", "rinfo2_v2.data" }};
        ret = InitKsfAttr(&ksfAttrRkc, HKS_KSF_TYPE_RKC);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = ReadAllKsfRkc(validKsfDataRkcWithVer);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All rkc ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

        RkcRecoverRkTime(validKsfDataRkcWithVer->ksfDataRkc.rkCreatedTime,
            validKsfDataRkcWithVer->ksfDataRkc.rkExpiredTime);

        // decrypt main key
        struct HksBlob tempMkBlob = { HKS_RKC_MK_LEN, g_hksRkcMk.mkWithMask };
        struct HksBlob mkCipherText = { HKS_RKC_MK_CIPHER_TEXT_LEN, validKsfDataMkWithVer->ksfDataMk.mkCiphertext };
        ret = RkcMkCrypt(&(validKsfDataRkcWithVer->ksfDataRkc), &(validKsfDataMkWithVer->ksfDataMk),
            &tempMkBlob, &mkCipherText, false); /* false: decrypt */
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Main key decrypt failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* the main key in memory should be masked */
        ret = RkcMaskMk(&tempMkBlob);
        HKS_IF_NOT_SUCC_BREAK(ret);

        ret = UpgradeMkIfNeeded(validKsfDataMkWithVer->mkVersion, &tempMkBlob);
    } while (0);

    HKS_MEMSET_FREE_PTR(validKsfDataRkcWithVer, sizeof(struct HksKsfDataRkcWithVer));
    HKS_MEMSET_FREE_PTR(validKsfDataMkWithVer, sizeof(struct HksKsfDataMkWithVer));
    return ret;
}

int32_t FillKsfDataRkcWithVer(struct HksKsfDataRkcWithVer *ksfDataRkcWithVer)
{
    HKS_IF_NULL_LOGE_RETURN(ksfDataRkcWithVer, HKS_ERROR_INVALID_ARGUMENT, "Invalid rkc ksf");

    (void)memset_s(ksfDataRkcWithVer, sizeof(struct HksKsfDataRkcWithVer), 0, sizeof(struct HksKsfDataRkcWithVer));
    ksfDataRkcWithVer->rkVersion = g_hksRkcCfg.rkVersion;
    ksfDataRkcWithVer->ksfDataRkc.rmkIter = g_hksRkcCfg.rmkIter;
    ksfDataRkcWithVer->ksfDataRkc.rmkHashAlg = g_hksRkcCfg.rmkHashAlg;
    int32_t ret;
    do {
        /* Two material are generated by random number. */
        ret = RkcMakeRandomMaterial(&(ksfDataRkcWithVer->ksfDataRkc));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate material failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* The salt value is generated by random number. */
        struct HksBlob salt = { HKS_RKC_SALT_LEN, ksfDataRkcWithVer->ksfDataRkc.rmkSalt };
        ret = HksCryptoHalFillPrivRandom(&salt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Generate salt failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    if (ret != HKS_SUCCESS) {
        (void)memset_s(ksfDataRkcWithVer, sizeof(struct HksKsfDataRkcWithVer), 0, sizeof(struct HksKsfDataRkcWithVer));
    }
    return ret;
}

void FillKsfDataMkWithVer(struct HksKsfDataMkWithVer *ksfDataMkWithVer)
{
    (void)memset_s(ksfDataMkWithVer, sizeof(struct HksKsfDataMkWithVer), 0, sizeof(struct HksKsfDataMkWithVer));
    ksfDataMkWithVer->mkVersion = g_hksRkcCfg.mkVersion;
    ksfDataMkWithVer->ksfDataMk.mkEncryptAlg = g_hksRkcCfg.mkEncryptAlg;
}

int32_t RkcWriteAllKsf(const struct HksKsfDataRkcWithVer *ksfDataRkcWithVer,
    const struct HksKsfDataMkWithVer *ksfDataMkWithVer)
{
    bool isSuccess = false;
    int32_t ret;
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        ret = HksWriteKsfRkc(g_hksRkcCfg.ksfAttrRkc.name[i], ksfDataRkcWithVer);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_WRITE_FILE_FAIL, "make mk failed! ret = 0x%" LOG_PUBLIC "X", ret)
    }
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        ret = HksWriteKsfMk(g_hksRkcCfg.ksfAttrMk.name[i], ksfDataMkWithVer);
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
    struct HksKsfDataRkcWithVer *newKsfDataRkcWithVer =
        (struct HksKsfDataRkcWithVer *)HksMalloc(sizeof(struct HksKsfDataRkcWithVer));
    struct HksKsfDataMkWithVer *newKsfDataMkWithVer =
        (struct HksKsfDataMkWithVer *)HksMalloc(sizeof(struct HksKsfDataMkWithVer));
    do {
        if (newKsfDataRkcWithVer == NULL || newKsfDataMkWithVer == NULL) {
            HKS_LOG_E("Malloc rkc or mk ksf data failed!");
            ret = HKS_ERROR_INSUFFICIENT_MEMORY;
            break;
        }

        FillKsfDataMkWithVer(newKsfDataMkWithVer);
        ret = FillKsfDataRkcWithVer(newKsfDataRkcWithVer);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Fill rkc data failed")

        /* make main key. */
        ret = RkcMakeMk(&(newKsfDataRkcWithVer->ksfDataRkc), &(newKsfDataMkWithVer->ksfDataMk));
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "make mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* Initialize rkc keystore file name (mk already done in HksRkcInit) */
        struct HksKsfAttr ksfAttrRkc = {{ "rinfo1_v2.data", "rinfo2_v2.data" }};
        ret = InitKsfAttr(&ksfAttrRkc, HKS_KSF_TYPE_RKC);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* Write the root key component and the main key data into all keystore files */
        ret = RkcWriteAllKsf(newKsfDataRkcWithVer, newKsfDataMkWithVer);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Write rkc & mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    /* the data of root & main key should be cleared after use */
    HKS_MEMSET_FREE_PTR(newKsfDataRkcWithVer, sizeof(struct HksKsfDataRkcWithVer));
    HKS_MEMSET_FREE_PTR(newKsfDataMkWithVer, sizeof(struct HksKsfDataMkWithVer));
    return ret;
}

int32_t HksRkcInit(void)
{
    if (g_hksRkcCfg.state == HKS_RKC_STATE_VALID) {
        HKS_LOG_I("Hks rkc is running!");
        return HKS_SUCCESS;
    }

    int32_t ret;
    do {
        /* Initialize the attribute of mk keystore file */
        struct HksKsfAttr ksfAttrMk = {{ "minfo1_v2.data", "minfo2_v2.data" }};
        ret = InitKsfAttr(&ksfAttrMk, HKS_KSF_TYPE_MK);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of mk keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

        if (KsfExist(HKS_KSF_TYPE_MK)) {
            ret = RkcLoadKsf();
        } else {
            /* Initialize the attribute of rkc keystore file */
            struct HksKsfAttr ksfAttrRkcV1 = {{ "info1.data", "info2.data" }};
            ret = InitKsfAttr(&ksfAttrRkcV1, HKS_KSF_TYPE_RKC);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret,
                "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)
#ifdef HKS_ENABLE_UPGRADE_RKC_DERIVE_ALG
            if (KsfExist(HKS_KSF_TYPE_RKC)) { // mk ksf not exists, rkc ksf exists => version 1
                ret = UpgradeV1ToV2();
            } else { // latest version
#endif
                ret = RkcCreateKsf();
#ifdef HKS_ENABLE_UPGRADE_RKC_DERIVE_ALG
            }
#endif
        }
    } while (0);

    if (ret != HKS_SUCCESS) {
        HksCfgDestroy();
        HksMkDestroy();
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
        HKS_FREE(g_hksRkcCfg.ksfAttrRkc.name[i]);
        HKS_FREE(g_hksRkcCfg.ksfAttrMk.name[i]);
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

int32_t HksRkcBuildParamSet(struct HksParamSet **paramSetOut)
{
    int32_t ret;
    struct HksParamSet *paramSet = NULL;
    do {
        ret = HksInitParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksInitParamSet failed")

        struct HksParam storageLevelParam;
        storageLevelParam.tag = HKS_TAG_AUTH_STORAGE_LEVEL;
        storageLevelParam.uint32Param = HKS_AUTH_STORAGE_LEVEL_DE;
        ret = HksAddParams(paramSet, &storageLevelParam, 1);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksAddParams failed")

        ret = HksBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksBuildParamSet failed")
        *paramSetOut = paramSet;
        return HKS_SUCCESS;
    } while (0);
    HksFreeParamSet(&paramSet);
    return ret;
}
#endif /* _CUT_AUTHENTICATE_ */
