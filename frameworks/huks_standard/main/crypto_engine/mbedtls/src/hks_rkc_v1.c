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

#include "hks_rkc_v1.h"

#include "hks_crypto_hal.h"
#include "hks_get_process_info.h"
#include "hks_get_udid.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_rkc.h"
#include "hks_storage.h"
#include "hks_template.h"

static int32_t ExtractKsfNoVerMk(const struct HksBlob *ksfFromFile,
    uint32_t *ksfBufOffset, struct HksKsfDataMk *ksfDataMk)
{
    /* Extract fields of main key */
    int32_t ret = ExtractKsfDataMk(ksfFromFile, ksfBufOffset, ksfDataMk);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return HKS_SUCCESS;
}

static int32_t RkcExtractKsfBufV1(const struct HksBlob *ksfFromFile, struct HksRkcKsfDataV1 *ksfData)
{
    uint32_t ksfBufOffset = 0;

    /* Extract file flag. */
    int32_t ret = RkcExtractKsfFileFlag(ksfFromFile, &ksfBufOffset);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract root key data */
    ret = ExtractKsfRkcWithVer(ksfFromFile, &ksfBufOffset, (struct HksKsfDataRkcWithVer*)ksfData);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Rkc extract ksf rk failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* Extract main key data */
    ret = ExtractKsfNoVerMk(ksfFromFile, &ksfBufOffset, &(ksfData->ksfDataMk));
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Rkc extract ksf mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* Extract hash */
    return RkcExtractKsfHash(ksfFromFile, &ksfBufOffset);
}

static int32_t HksRkcReadKsfV1(const char *ksfName, struct HksRkcKsfDataV1 *ksfData)
{
    struct HksBlob tmpKsf;
    int32_t ret = GetKeyBlobKsf(ksfName, &tmpKsf);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, "Get ksf file failed! ret = 0x%" LOG_PUBLIC "X", ret)
    
    ret = RkcExtractKsfBufV1(&tmpKsf, ksfData);

    /* the data of root key should be cleared after use */
    (void)memset_s(tmpKsf.data, tmpKsf.size, 0, tmpKsf.size);
    HKS_FREE_BLOB(tmpKsf);
    return ret;
}

static int32_t RkcReadAllKsfV1(struct HksRkcKsfDataV1 **validKsfData)
{
    /* Read all rkc ksf */
    int32_t readRet[HKS_KSF_NUM] = { 0 };
    struct HksRkcKsfDataV1 allRkcData[HKS_KSF_NUM] = { 0 };
    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        readRet[i] = HksRkcReadKsfV1(GetGlobalKsfAttrRkc()->name[i], &(allRkcData[i]));
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

    // version 1: no need to rewrite for recovery
    *validKsfData = (struct HksRkcKsfDataV1 *)HksMalloc(sizeof(struct HksRkcKsfDataV1));
    if (validKsfData == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(*validKsfData, sizeof(struct HksRkcKsfDataV1),
        allRkcData[validIndex], sizeof(struct HksRkcKsfDataV1));
    return HKS_SUCCESS;
}

static int32_t RkcGetFixedMaterialV1(struct HksBlob *material)
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

static int32_t RkcGetRmkRawKeyV1(const struct HksKsfDataRkc *ksfDataRkc, struct HksBlob *rawKey)
{
    uint8_t material3Data[HKS_RKC_MATERIAL_LEN] = {0};
    struct HksBlob material3 = { HKS_RKC_MATERIAL_LEN, material3Data };

    /* Get the fixed material */
    int32_t ret = RkcGetFixedMaterialV1(&material3);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Get fixed material failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* materials xor */
    for (uint32_t i = 0; i < HKS_RKC_MATERIAL_LEN; ++i) {
        rawKey->data[i] = ksfDataRkc->rkMaterial1[i] ^ ksfDataRkc->rkMaterial2[i] ^ material3.data[i];
    }

    /* append hardware UDID */
    ret = HksGetHardwareUdid(rawKey->data + HKS_RKC_MATERIAL_LEN, HKS_HARDWARE_UDID_LEN);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Get hardware udid failed! ret = 0x%" LOG_PUBLIC "X", ret)

    return HKS_SUCCESS;
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

static int32_t RkcDeriveRmkV1(const struct HksKsfDataRkc *ksfDataRkc, struct HksBlob *rmk)
{
    struct HksBlob rawKey;
    rawKey.data = (uint8_t *)HksMalloc(HKS_RKC_RAW_KEY_LEN);
    HKS_IF_NULL_LOGE_RETURN(rawKey.data, HKS_ERROR_MALLOC_FAIL, "Malloc rawKey failed!")

    rawKey.size = HKS_RKC_RAW_KEY_LEN;
    (void)memset_s(rawKey.data, rawKey.size, 0, rawKey.size);

    int32_t ret;
    do {
        /* get the raw key */
        ret = RkcGetRmkRawKeyV1(ksfDataRkc, &rawKey);
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

static int32_t RkcMkCryptV1(const struct HksRkcKsfDataV1 *ksfData,
    struct HksBlob *plainText, struct HksBlob *cipherText, const bool encrypt)
{
    struct HksBlob rmk;
    rmk.data = (uint8_t *)HksMalloc(HKS_RKC_RMK_LEN);
    HKS_IF_NULL_LOGE_RETURN(rmk.data, HKS_ERROR_MALLOC_FAIL, "Malloc rmk failed!")

    rmk.size = HKS_RKC_RMK_LEN;
    (void)memset_s(rmk.data, rmk.size, 0, rmk.size);

    int32_t ret;
    do {
        ret = RkcDeriveRmkV1(&(ksfData->ksfDataRkc), &rmk);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Derive rmk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = ExecuteMkCrypt(&(ksfData->ksfDataMk), &rmk, plainText, cipherText, encrypt);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Crypto mk failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    /* the data of root key should be cleared after use */
    (void)memset_s(rmk.data, rmk.size, 0, rmk.size);
    HKS_FREE_BLOB(rmk);
    return ret;
}

static int32_t RkcLoadKsfV1(void)
{
    struct HksRkcKsfDataV1 *validKsfData = NULL;
    int32_t ret;
    do {
        ret = RkcReadAllKsfV1(&validKsfData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "All rkc ksf file are invalid! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcRecoverRkTime(validKsfData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover root key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

        ret = RkcRecoverMkTime(validKsfData, NULL);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Recover main key memory failed! ret = 0x%" LOG_PUBLIC "X", ret)

        HksBlob tempMkBlob = { HKS_RKC_MK_LEN, g_hksRkcMk.mkWithMask };
        struct HksBlob mkCipherText = { HKS_RKC_MK_CIPHER_TEXT_LEN, (uint8_t *)validKsfData->mkCiphertext };
        ret = RkcMkCryptV1(validKsfData, &tempMkBlob, &mkCipherText, false); /* false: decrypt */
        HKS_IF_NOT_SUCC_LOGE(ret, "Main key crypt failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    HKS_MEMSET_FREE_PTR(validKsfData);
    return ret;
}

static int32_t RkcDeleteAllKsfV1()
{
    struct HksProcessInfo processInfo = {{0, NULL}, {0, NULL}, 0, 0};
    ret = GetProcessInfo(&processInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INTERNAL_ERROR, "get process info failed")

    struct HksBlob fileNameBlob = { strlen("info1.data"), "info1.data" };
    ret = HksStoreDeleteKeyBlob(&processInfo, &fileNameBlob, HKS_STORAGE_TYPE_ROOT_KEY);
    if ((ret != HKS_SUCCESS) && (ret != HKS_ERROR_NOT_EXIST)) {
        HKS_LOG_E("delete rkc keystore file failed, ret = %" LOG_PUBLIC "d", ret);
    }

    fileNameBlob.size = strlen("info2.data");
    fileNameBlob.data = "info2.data";
    ret = HksStoreDeleteKeyBlob(&processInfo, &fileNameBlob, HKS_STORAGE_TYPE_ROOT_KEY);
    if ((ret != HKS_SUCCESS) && (ret != HKS_ERROR_NOT_EXIST)) {
        HKS_LOG_E("delete rkc keystore file failed, ret = %" LOG_PUBLIC "d", ret);
    }

    return ret;
}

int32_t UpgradeV1ToV2(void)
{
    HKS_LOG_I("Rkc ksf is exist, start to load ksf");
    int32_t ret = RkcLoadKsfV1();
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, "Load rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)

    // generate new materials and encrypt main key
    struct HksKsfDataRkcWithVer *newKsfDataRkcWithVer = NULL;
    struct HksKsfDataMkWithVer *newKsfDataMkWithVer = NULL;

    do {
        newKsfDataRkcWithVer = CreateNewKsfDataRkcWithVer();
        HKS_IF_NULL_LOGE_BREAK(newKsfDataRkcWithVer, HKS_ERROR_MALLOC_FAIL, "Malloc rkc ksf data failed!")
        newKsfDataMkWithVer = CreateNewKsfDataMkWithVer();
        HKS_IF_NULL_LOGE_BREAK(newKsfDataMkWithVer, HKS_ERROR_MALLOC_FAIL, "Malloc mk ksf data failed!")

        HksBlob tempMkBlob = { HKS_RKC_MK_LEN, g_hksRkcMk.mkWithMask };
        struct HksBlob cipherTextBlob = { HKS_RKC_MK_CIPHER_TEXT_LEN, newKsfDataMkWithVer->mkCiphertext };
        ret = RkcMkCrypt(&newKsfDataRkcWithVer, &newKsfDataMkWithVer, &tempMkBlob, &cipherTextBlob, true); /* true: encrypt */
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Encrypt mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* Initialize rkc keystore file name (mk already done in HksRkcInit) */
        struct HksKsfAttr ksfAttrRkc = { "rinfo1_v2.data", "rinfo2_v2.data" };
        ret = InitKsfAttr(&ksfAttrRkc, HKS_KSF_TYPE_RKC);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Init attribute of rkc keystore file failed! ret = 0x%" LOG_PUBLIC "X", ret)

        /* Write the root key component and the main key data into all keystore files */
        ret = RkcWriteAllKsf(&newKsfDataRkcWithVer, &newKsfDataMkWithVer);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Write rkc & mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
        
        ret = RkcMaskMk(&tempMkBlob);
    } while (0);

    /* the data of root & main key should be cleared after use */
    HKS_MEMSET_FREE_PTR(newKsfDataRkcWithVer);
    HKS_MEMSET_FREE_PTR(newKsfDataMkWithVer);

    /* delete all old rkc keystore files */
    ret = RkcDeleteAllKsfV1()
    return ret;
}
