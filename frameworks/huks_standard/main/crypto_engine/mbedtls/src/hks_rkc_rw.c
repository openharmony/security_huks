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
#include "hks_rkc_rw.h"

#include "hks_crypto_hal.h"
#include "hks_get_process_info.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_rkc.h"
#include "hks_storage.h"
#include "hks_template.h"

#define HKS_RKC_HASH_LEN 32         /* the hash value length of root key component */
#define HKS_KSF_BUF_LEN 258         /* the length of rkc or mk keystore buffer */
#define USER_ID_ROOT_DEFAULT          "0"

/* the flag of keystore file, used to identify files as HKS keystore file, don't modify. */
const uint8_t g_hksRkcKsfFlag[HKS_RKC_KSF_FLAG_LEN] = { 0x5F, 0x64, 0x97, 0x8D, 0x19, 0x4F, 0x89, 0xCF };

int32_t GetProcessInfo(struct HksProcessInfo *processInfo)
{
    char *userId = NULL;
    char *processName = NULL;

    HKS_IF_NOT_SUCC_LOGE_RETURN(HksGetUserId(&userId), HKS_ERROR_INTERNAL_ERROR, "get user id failed")
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksGetProcessName(&processName), HKS_ERROR_INTERNAL_ERROR, "get process name failed")

    processInfo->userId.size = strlen(userId);
    processInfo->userId.data = (uint8_t *)userId;
    processInfo->processName.size = strlen(processName);
    processInfo->processName.data = (uint8_t *)processName;
    processInfo->userIdInt = 0;
    processInfo->accessTokenId = 0;

    return HKS_SUCCESS;
}

int32_t GetKeyBlobKsf(const char *ksfName, struct HksBlob *tmpKsf)
{
    tmpKsf->data = (uint8_t *)HksMalloc(HKS_KSF_BUF_LEN);
    HKS_IF_NULL_RETURN(tmpKsf->data, HKS_ERROR_MALLOC_FAIL)

    tmpKsf->size = HKS_KSF_BUF_LEN;
    (void)memset_s(tmpKsf->data, tmpKsf->size, 0, tmpKsf->size);

    int32_t ret;
    do {
        struct HksProcessInfo processInfo = {{0, NULL}, {0, NULL}, 0, 0};
        ret = GetProcessInfo(&processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get process info failed")

        const struct HksBlob fileNameBlob = { strlen(ksfName), (uint8_t *)ksfName };

        ret = HksStoreGetKeyBlob(&processInfo, &fileNameBlob, HKS_STORAGE_TYPE_ROOT_KEY, tmpKsf);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Get ksf file failed! ret = 0x%" LOG_PUBLIC "X", ret)

        return HKS_SUCCESS;
    } while(0);

    /* the data of root or main key should be cleared after use */
    (void)memset_s(tmpKsf->data, tmpKsf->size, 0, tmpKsf->size);
    HKS_FREE_BLOB(*tmpKsf);
    return ret;
}

int32_t RkcExtractKsfFileFlag(const struct HksBlob *ksfFromFile, uint32_t *ksfBufOffset)
{
    uint8_t fileFlag[HKS_RKC_KSF_FLAG_LEN] = {0};

    /* Extract file flag. */
    if (memcpy_s(fileFlag, HKS_RKC_KSF_FLAG_LEN, ksfFromFile->data + *ksfBufOffset, HKS_RKC_KSF_FLAG_LEN) != EOK) {
        HKS_LOG_E("Memcpy file flag failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    /* Check file flag. */
    if (HksMemCmp(fileFlag, g_hksRkcKsfFlag, HKS_RKC_KSF_FLAG_LEN) != 0) {
        HKS_LOG_E("Ksf file flag is invalid!");
        return HKS_ERROR_READ_FILE_FAIL;
    }

    *ksfBufOffset += HKS_RKC_KSF_FLAG_LEN;
    return HKS_SUCCESS;
}

static int32_t RkcExtractTime(const struct HksBlob *ksfFromFile, uint32_t *ksfBufOffset, struct HksTime *time)
{
    if (memcpy_s(&(time->hksYear), sizeof(uint16_t), ksfFromFile->data + *ksfBufOffset, sizeof(uint16_t)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint16_t);

    if (memcpy_s(&(time->hksMon), sizeof(uint8_t), ksfFromFile->data + *ksfBufOffset, sizeof(uint8_t)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint8_t);

    if (memcpy_s(&(time->hksDay), sizeof(uint8_t), ksfFromFile->data + *ksfBufOffset, sizeof(uint8_t)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint8_t);

    if (memcpy_s(&(time->hksHour), sizeof(uint8_t), ksfFromFile->data + *ksfBufOffset, sizeof(uint8_t)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint8_t);

    if (memcpy_s(&(time->hksMin), sizeof(uint8_t), ksfFromFile->data + *ksfBufOffset, sizeof(uint8_t)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint8_t);

    if (memcpy_s(&(time->hksSec), sizeof(uint8_t), ksfFromFile->data + *ksfBufOffset, sizeof(uint8_t)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint8_t);

    return HKS_SUCCESS;
}

static int32_t ExtractKsfDataRkc(const struct HksBlob *ksfFromFile,
    uint32_t *ksfBufOffset, struct HksKsfDataRkc *ksfDataRkc)
{
    /* Extract rkCreatedTime */
    int32_t ret = RkcExtractTime(ksfFromFile, ksfBufOffset, &(ksfDataRkc->rkCreatedTime));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract rkExpiredTime */
    ret = RkcExtractTime(ksfFromFile, ksfBufOffset, &(ksfDataRkc->rkExpiredTime));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract the first material */
    if (memcpy_s(&(ksfDataRkc->rkMaterial1), HKS_RKC_MATERIAL_LEN,
        ksfFromFile->data + *ksfBufOffset, HKS_RKC_MATERIAL_LEN) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_MATERIAL_LEN;

    /* Extract the second material */
    if (memcpy_s(&(ksfDataRkc->rkMaterial2), HKS_RKC_MATERIAL_LEN,
        ksfFromFile->data + *ksfBufOffset, HKS_RKC_MATERIAL_LEN) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_MATERIAL_LEN;

    /* Extract iterator number */
    if (memcpy_s(&(ksfDataRkc->rmkIter), sizeof(uint32_t), ksfFromFile->data + *ksfBufOffset, sizeof(uint32_t)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint32_t);

    /* Extract salt */
    if (memcpy_s(&(ksfDataRkc->rmkSalt), HKS_RKC_SALT_LEN, ksfFromFile->data + *ksfBufOffset, HKS_RKC_SALT_LEN) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_SALT_LEN;

    /* Extract hash algorithm */
    if (memcpy_s(&(ksfDataRkc->rmkHashAlg), sizeof(uint32_t),
        ksfFromFile->data + *ksfBufOffset, sizeof(uint32_t)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint32_t);

    /* Extract reserve field */
    if (memcpy_s(&(ksfDataRkc->rkRsv), HKS_RKC_KSF_DATA_RSV_LEN,
        ksfFromFile->data + *ksfBufOffset, HKS_RKC_KSF_DATA_RSV_LEN) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_KSF_DATA_RSV_LEN;

    return HKS_SUCCESS;
}

int32_t ExtractKsfDataMk(const struct HksBlob *ksfFromFile,
    uint32_t *ksfBufOffset, struct HksKsfDataMk *ksfDataMk)
{
    /* Extract mkCreatedTime */
    int32_t ret = RkcExtractTime(ksfFromFile, ksfBufOffset, &(ksfDataMk->mkCreatedTime));
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Extract mkCreatedTime failed!")

    /* Extract mkExpiredTime */
    ret = RkcExtractTime(ksfFromFile, ksfBufOffset, &(ksfDataMk->mkExpiredTime));
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Extract mkExpiredTime failed!")

    /* Fill encryption algorithm */
    if (memcpy_s(&(ksfDataMk->mkEncryptAlg), sizeof(uint32_t),
        ksfFromFile->data + *ksfBufOffset, sizeof(uint32_t)) != EOK) {
        HKS_LOG_E("Memcpy mkEncryptAlg failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint32_t);

    /* Fill IV */
    if (memcpy_s(&(ksfDataMk->mkIv), HKS_RKC_MK_IV_LEN, ksfFromFile->data + *ksfBufOffset, HKS_RKC_MK_IV_LEN) != EOK) {
        HKS_LOG_E("Memcpy mkIv failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_MK_IV_LEN;

    /* Fill ciphertext */
    if (memcpy_s(&(ksfDataMk->mkCiphertext), HKS_RKC_MK_CIPHER_TEXT_LEN,
        ksfFromFile->data + *ksfBufOffset, HKS_RKC_MK_CIPHER_TEXT_LEN) != EOK) {
        HKS_LOG_E("Memcpy mkCiphertext failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_MK_CIPHER_TEXT_LEN;

    /* Fill reserve field */
    if (memcpy_s(&(ksfDataMk->mkRsv), HKS_RKC_KSF_DATA_RSV_LEN,
        ksfFromFile->data + *ksfBufOffset, HKS_RKC_KSF_DATA_RSV_LEN) != EOK) {
        HKS_LOG_E("Memcpy mkRsv failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_KSF_DATA_RSV_LEN;

    return HKS_SUCCESS;
}

int32_t ExtractKsfRkcWithVer(const struct HksBlob *ksfFromFile,
    uint32_t *ksfBufOffset, struct HksKsfDataRkcWithVer *ksfDataRkcWithVer)
{
    /* Extract version */
    if (memcpy_s(&(ksfDataRkcWithVer->rkVersion), sizeof(uint16_t),
        ksfFromFile->data + *ksfBufOffset, sizeof(uint16_t)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint16_t);

    /* Extract fields of root key component */
    int32_t ret = ExtractKsfDataRkc(ksfFromFile, ksfBufOffset, &(ksfDataRkcWithVer->ksfDataRkc));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return HKS_SUCCESS;
}

static int32_t ExtractKsfMkWithVer(const struct HksBlob *ksfFromFile,
    uint32_t *ksfBufOffset, struct HksKsfDataMkWithVer *ksfDataMkWithVer)
{
    /* Extract version */
    if (memcpy_s(&(ksfDataMkWithVer->mkVersion), sizeof(uint16_t),
        ksfFromFile->data + *ksfBufOffset, sizeof(uint16_t)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint16_t);

    /* Extract fields of main key */
    int32_t ret = ExtractKsfDataMk(ksfFromFile, ksfBufOffset, &(ksfDataMkWithVer->ksfDataMk));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return HKS_SUCCESS;
}

int32_t RkcExtractKsfHash(const struct HksBlob *ksfFromFile, uint32_t *ksfBufOffset)
{
    /* calculate sha256, skip file flag, begin with version, end with reserve field. */
    uint8_t hashResult[HKS_RKC_HASH_LEN] = {0};
    struct HksBlob hashResultBlob = { HKS_RKC_HASH_LEN, hashResult };
    /* the upper layer ensures no overflow */
    const struct HksBlob hashSrc = { *ksfBufOffset - HKS_RKC_KSF_FLAG_LEN, ksfFromFile->data + HKS_RKC_KSF_FLAG_LEN };
    int32_t ret = HksCryptoHalHash(HKS_DIGEST_SHA256, &hashSrc, &hashResultBlob);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Hks hash failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* Extract hash from ksf buffer */
    uint8_t ksfHash[HKS_RKC_HASH_LEN] = {0};
    if (memcpy_s(&ksfHash, HKS_RKC_HASH_LEN, ksfFromFile->data + *ksfBufOffset, HKS_RKC_HASH_LEN) != EOK) {
        HKS_LOG_E("Memcpy ksfHash failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_HASH_LEN;

    /* Check hash result. */
    if (HksMemCmp(hashResult, ksfHash, HKS_RKC_HASH_LEN) != 0) {
        HKS_LOG_E("Ksf hash result is Invalid!");
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    return HKS_SUCCESS;
}

static int32_t ExtractKsfBufRkc(const struct HksBlob *ksfFromFile, struct HksKsfDataRkcWithVer *ksfDataRkcWithVer)
{
    uint32_t ksfBufOffset = 0;

    /* Extract file flag. */
    int32_t ret = RkcExtractKsfFileFlag(ksfFromFile, &ksfBufOffset);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract root key data */
    ret = ExtractKsfRkcWithVer(ksfFromFile, &ksfBufOffset, ksfDataRkcWithVer);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Extract ksf rkc with version failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* Extract hash */
    return RkcExtractKsfHash(ksfFromFile, &ksfBufOffset);
}

static int32_t ExtractKsfBufMk(const struct HksBlob *ksfFromFile, struct HksKsfDataMkWithVer *ksfDataMkWithVer)
{
    uint32_t ksfBufOffset = 0;

    /* Extract file flag. */
    int32_t ret = RkcExtractKsfFileFlag(ksfFromFile, &ksfBufOffset);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract main key data */
    ret = ExtractKsfMkWithVer(ksfFromFile, &ksfBufOffset, ksfDataMkWithVer);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Extract ksf mk with version failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* Extract hash */
    return RkcExtractKsfHash(ksfFromFile, &ksfBufOffset);
}

int32_t HksReadKsfRkc(const char *ksfName, struct HksKsfDataRkcWithVer *ksfDataRkc)
{
    struct HksBlob tmpKsf;
    int32_t ret = GetKeyBlobKsf(ksfName, &tmpKsf);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Get rkc ksf file failed! ret = 0x%" LOG_PUBLIC "X", ret)

    ret = ExtractKsfBufRkc(&tmpKsf, ksfDataRkc);

    /* the data of root key should be cleared after use */
    (void)memset_s(tmpKsf.data, tmpKsf.size, 0, tmpKsf.size);
    HKS_FREE_BLOB(tmpKsf);
    return ret;
}

int32_t HksReadKsfMk(const char *ksfName, struct HksKsfDataMkWithVer *ksfDataMk)
{
    struct HksBlob tmpKsf;
    int32_t ret = GetKeyBlobKsf(ksfName, &tmpKsf);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Get mk ksf file failed! ret = 0x%" LOG_PUBLIC "X", ret)

    ret = ExtractKsfBufMk(&tmpKsf, ksfDataMk);

    /* the data of main key should be cleared after use */
    (void)memset_s(tmpKsf.data, tmpKsf.size, 0, tmpKsf.size);
    HKS_FREE_BLOB(tmpKsf);
    return ret;
}

static int32_t RkcFillKsfTime(const struct HksTime *time, struct HksBlob *ksfBuf, uint32_t *ksfBufOffset)
{
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, sizeof(uint16_t), &(time->hksYear), sizeof(uint16_t)) != EOK) {
        HKS_LOG_E("Memcpy hksYear failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint16_t);

    if (memcpy_s(ksfBuf->data + *ksfBufOffset, sizeof(uint8_t), &(time->hksMon), sizeof(uint8_t)) != EOK) {
        HKS_LOG_E("Memcpy hksMon failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint8_t);

    if (memcpy_s(ksfBuf->data + *ksfBufOffset, sizeof(uint8_t), &(time->hksDay), sizeof(uint8_t)) != EOK) {
        HKS_LOG_E("Memcpy hksDay failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint8_t);

    if (memcpy_s(ksfBuf->data + *ksfBufOffset, sizeof(uint8_t), &(time->hksHour), sizeof(uint8_t)) != EOK) {
        HKS_LOG_E("Memcpy hksHour failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint8_t);

    if (memcpy_s(ksfBuf->data + *ksfBufOffset, sizeof(uint8_t), &(time->hksMin), sizeof(uint8_t)) != EOK) {
        HKS_LOG_E("Memcpy hksMin failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint8_t);

    if (memcpy_s(ksfBuf->data + *ksfBufOffset, sizeof(uint8_t), &(time->hksSec), sizeof(uint8_t)) != EOK) {
        HKS_LOG_E("Memcpy hksSec failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint8_t);

    return HKS_SUCCESS;
}

static int32_t FillKsfDataRkc(const struct HksKsfDataRkc *ksfDataRkc, struct HksBlob *ksfBuf, uint32_t *ksfBufOffset)
{
    /* Fill rkCreatedTime */
    int32_t ret = RkcFillKsfTime(&(ksfDataRkc->rkCreatedTime), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Fill rkExpiredTime */
    ret = RkcFillKsfTime(&(ksfDataRkc->rkExpiredTime), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Fill the first material */
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, HKS_RKC_MATERIAL_LEN,
        ksfDataRkc->rkMaterial1, HKS_RKC_MATERIAL_LEN) != EOK) {
        HKS_LOG_E("Memcpy first material to ksf buf failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_MATERIAL_LEN;

    /* Fill the second material */
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, HKS_RKC_MATERIAL_LEN,
        ksfDataRkc->rkMaterial2, HKS_RKC_MATERIAL_LEN) != EOK) {
        HKS_LOG_E("Memcpy second material to ksf buf failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_MATERIAL_LEN;

    /* Fill iterator number */
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, sizeof(uint32_t), &(ksfDataRkc->rmkIter), sizeof(uint32_t)) != EOK) {
        HKS_LOG_E("Memcpy iterator number to ksf buf failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint32_t);

    /* Fill salt */
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, HKS_RKC_SALT_LEN, ksfDataRkc->rmkSalt, HKS_RKC_SALT_LEN) != EOK) {
        HKS_LOG_E("Memcpy salt to ksf buf failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_SALT_LEN;

    /* Fill hash algorithm */
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, sizeof(uint32_t), &(ksfDataRkc->rmkHashAlg), sizeof(uint32_t)) != EOK) {
        HKS_LOG_E("Memcpy hash algorithm to ksf buf failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint32_t);

    /* Fill reserve field */
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, HKS_RKC_KSF_DATA_RSV_LEN,
        ksfDataRkc->rkRsv, HKS_RKC_KSF_DATA_RSV_LEN) != EOK) {
        HKS_LOG_E("Memcpy reserve field to ksf buf failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_KSF_DATA_RSV_LEN;

    return HKS_SUCCESS;
}

static int32_t FillKsfDataMk(const struct HksKsfDataMk *ksfDataMk, struct HksBlob *ksfBuf, uint32_t *ksfBufOffset)
{
    /* Fill mkCreatedTime */
    int32_t ret = RkcFillKsfTime(&(ksfDataMk->mkCreatedTime), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Fill mk created time to ksf buf failed!")

    /* Fill mkExpiredTime */
    ret = RkcFillKsfTime(&(ksfDataMk->mkExpiredTime), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Fill mk expired time to ksf buf failed!")

    /* Fill encryption algorithm */
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, sizeof(uint32_t), &(ksfDataMk->mkEncryptAlg), sizeof(uint32_t)) != EOK) {
        HKS_LOG_E("Memcpy encrption algorithm to ksf buf failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint32_t);

    /* Fill IV */
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, HKS_RKC_MK_IV_LEN, ksfDataMk->mkIv, HKS_RKC_MK_IV_LEN) != EOK) {
        HKS_LOG_E("Memcpy iv to ksf buf failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_MK_IV_LEN;

    /* Fill ciphertext */
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, HKS_RKC_MK_CIPHER_TEXT_LEN,
        ksfDataMk->mkCiphertext, HKS_RKC_MK_CIPHER_TEXT_LEN) != EOK) {
        HKS_LOG_E("Memcpy ciphertext to ksf buf failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_MK_CIPHER_TEXT_LEN;

    /* Fill reserve field */
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, HKS_RKC_KSF_DATA_RSV_LEN,
        ksfDataMk->mkRsv, HKS_RKC_KSF_DATA_RSV_LEN) != EOK) {
        HKS_LOG_E("Memcpy reserve field to ksf buf failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += HKS_RKC_KSF_DATA_RSV_LEN;

    return HKS_SUCCESS;
}

static int32_t FillKsfVerRkc(const struct HksKsfDataRkcWithVer *ksfataRkcWithVer,
    struct HksBlob *ksfBuf, uint32_t *ksfBufOffset)
{
    /* Fill version */
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, sizeof(uint16_t),
        &(ksfataRkcWithVer->rkVersion), sizeof(uint16_t)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint16_t);

    int32_t ret = FillKsfDataRkc(&(ksfataRkcWithVer->ksfDataRkc), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy rkc data to ksf buf failed! ret = 0x%" LOG_PUBLIC "X", ret)

    return HKS_SUCCESS;
}

static int32_t FillKsfVerMk(const struct HksKsfDataMkWithVer *ksfataMkWithVer,
    struct HksBlob *ksfBuf, uint32_t *ksfBufOffset)
{
    /* Fill version */
    if (memcpy_s(ksfBuf->data + *ksfBufOffset, sizeof(uint16_t),
        &(ksfataMkWithVer->mkVersion), sizeof(uint16_t)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    *ksfBufOffset += sizeof(uint16_t);

    int32_t ret = FillKsfDataMk(&(ksfataMkWithVer->ksfDataMk), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy mk data to ksf buf failed! ret = 0x%" LOG_PUBLIC "X", ret)

    return HKS_SUCCESS;
}

static int32_t RkcFillKsfHash(struct HksBlob *ksfBuf, uint32_t *ksfBufOffset)
{
    if ((ksfBuf->size < HKS_RKC_KSF_FLAG_LEN) || (*ksfBufOffset <= HKS_RKC_KSF_FLAG_LEN) ||
        (ksfBuf->size < *ksfBufOffset)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    /* calculate sha256, skip file flag, begin with version, end with reserve field. */
    const struct HksBlob hashSrc = { *ksfBufOffset - HKS_RKC_KSF_FLAG_LEN, ksfBuf->data + HKS_RKC_KSF_FLAG_LEN };
    struct HksBlob hash = { HKS_RKC_HASH_LEN, ksfBuf->data + *ksfBufOffset };
    int32_t ret = HksCryptoHalHash(HKS_DIGEST_SHA256, &hashSrc, &hash);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Hash failed! ret = 0x%" LOG_PUBLIC "X", ret)

    *ksfBufOffset += HKS_RKC_HASH_LEN;
    return HKS_SUCCESS;
}

static int32_t FillKsfBufRkc(const struct HksKsfDataRkcWithVer *ksfDataRkcWithVer, struct HksBlob *ksfBuf)
{
    uint32_t ksfBufOffset = 0;

    /* Fill file flag */
    if (memcpy_s(ksfBuf->data, HKS_RKC_KSF_FLAG_LEN, g_hksRkcKsfFlag, HKS_RKC_KSF_FLAG_LEN) != EOK) {
        HKS_LOG_E("Memcpy file flag to ksd buf failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    ksfBufOffset += HKS_RKC_KSF_FLAG_LEN;

    /* Fill root key */
    int32_t ret = FillKsfVerRkc(ksfDataRkcWithVer, ksfBuf, &ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Fill root key info to ksf buf failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* calculate and fill SHA256 result, skip file flag, begin with version, end with reserve field. */
    ret = RkcFillKsfHash(ksfBuf, &ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Fill hash to ksf buf failed! ret = 0x%" LOG_PUBLIC "X", ret)

    return HKS_SUCCESS;
}

static int32_t FillKsfBufMk(const struct HksKsfDataMkWithVer *ksfDataMkWithVer, struct HksBlob *ksfBuf)
{
    uint32_t ksfBufOffset = 0;

    /* Fill file flag */
    if (memcpy_s(ksfBuf->data, HKS_RKC_KSF_FLAG_LEN, g_hksRkcKsfFlag, HKS_RKC_KSF_FLAG_LEN) != EOK) {
        HKS_LOG_E("Memcpy file flag to ksd buf failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    ksfBufOffset += HKS_RKC_KSF_FLAG_LEN;

    /* Fill main key */
    int32_t ret = FillKsfVerMk(ksfDataMkWithVer, ksfBuf, &ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Fill main key info to ksf buf failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* calculate and fill SHA256 result, skip file flag, begin with version, end with reserve field. */
    ret = RkcFillKsfHash(ksfBuf, &ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Fill hash to ksf buf failed! ret = 0x%" LOG_PUBLIC "X", ret)

    return HKS_SUCCESS;
}

int32_t HksWriteKsfRkc(const char *ksfName, const struct HksKsfDataRkcWithVer *ksfDataRkc)
{
    struct HksBlob ksfBuf;
    ksfBuf.data = (uint8_t *)HksMalloc(HKS_KSF_BUF_LEN);
    HKS_IF_NULL_LOGE_RETURN(ksfBuf.data, HKS_ERROR_MALLOC_FAIL, "Malloc rkc ksf buffer failed!")

    ksfBuf.size = HKS_KSF_BUF_LEN;
    (void)memset_s(ksfBuf.data, ksfBuf.size, 0, ksfBuf.size);

    int32_t ret;
    do {
        /* Fill data into buffer */
        ret = FillKsfBufRkc(ksfDataRkc, &ksfBuf);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Fill rkc ksf buf failed! ret = 0x%" LOG_PUBLIC "X", ret)

        struct HksProcessInfo processInfo = {{0, NULL}, {0, NULL}, 0, 0};
        ret = GetProcessInfo(&processInfo);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INTERNAL_ERROR, "get process info failed")

        /* write buffer data into keystore file */
        const struct HksBlob fileNameBlob = { strlen(ksfName), (uint8_t *)ksfName };
        ret = HksStoreKeyBlob(&processInfo, &fileNameBlob, HKS_STORAGE_TYPE_ROOT_KEY, &ksfBuf);
        HKS_IF_NOT_SUCC_LOGE(ret, "Store rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    (void)memset_s(ksfBuf.data, ksfBuf.size, 0, ksfBuf.size);
    HKS_FREE_BLOB(ksfBuf);
    return ret;
}

int32_t HksWriteKsfMk(const char *ksfName, const struct HksKsfDataMkWithVer *ksfDataMk)
{
    struct HksBlob ksfBuf;
    ksfBuf.data = (uint8_t *)HksMalloc(HKS_KSF_BUF_LEN);
    HKS_IF_NULL_LOGE_RETURN(ksfBuf.data, HKS_ERROR_MALLOC_FAIL, "Malloc mk ksf buffer failed!")

    ksfBuf.size = HKS_KSF_BUF_LEN;
    (void)memset_s(ksfBuf.data, ksfBuf.size, 0, ksfBuf.size);

    int32_t ret;
    do {
        /* Fill data into buffer */
        ret = FillKsfBufMk(ksfDataMk, &ksfBuf);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Fill mk ksf buf failed! ret = 0x%" LOG_PUBLIC "X", ret)

        struct HksProcessInfo processInfo = {{0, NULL}, {0, NULL}, 0, 0};
        ret = GetProcessInfo(&processInfo);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INTERNAL_ERROR, "get process info failed")

        /* write buffer data into keystore file */
        const struct HksBlob fileNameBlob = { strlen(ksfName), (uint8_t *)ksfName };
        ret = HksStoreKeyBlob(&processInfo, &fileNameBlob, HKS_STORAGE_TYPE_ROOT_KEY, &ksfBuf);
        HKS_IF_NOT_SUCC_LOGE(ret, "Store mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    (void)memset_s(ksfBuf.data, ksfBuf.size, 0, ksfBuf.size);
    HKS_FREE_BLOB(ksfBuf);
    return ret;
}

bool KsfExist(uint8_t ksfType)
{
    struct HksProcessInfo processInfo = {{0, NULL}, {0, NULL}, 0, 0};
    int32_t ret = GetProcessInfo(&processInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INTERNAL_ERROR, "get process info failed")

    struct HksBlob fileNameBlob;
    int32_t checkRet[HKS_KSF_NUM] = { 0 };
    if (ksfType == HKS_KSF_TYPE_RKC) {
        struct HksKsfAttr *rkcFileName = GetGlobalKsfAttrRkc();
        for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
            fileNameBlob.size = strlen(rkcFileName->name[i]);
            fileNameBlob.data = (uint8_t *)(rkcFileName->name[i]);
            checkRet[i] = HksStoreIsKeyBlobExist(&processInfo, &fileNameBlob, HKS_STORAGE_TYPE_ROOT_KEY);
        }
    } else {
        struct HksKsfAttr *mkFileName = GetGlobalKsfAttrMk();
        for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
            fileNameBlob.size = strlen(mkFileName->name[i]);
            fileNameBlob.data = (uint8_t *)(mkFileName->name[i]);
            checkRet[i] = HksStoreIsKeyBlobExist(&processInfo, &fileNameBlob, HKS_STORAGE_TYPE_ROOT_KEY);
        }
    }

    uint32_t validIndex = 0;
    for (; validIndex < HKS_KSF_NUM; validIndex++) {
        if (checkRet[validIndex] == HKS_SUCCESS) {
            break;
        }
    }
    if (validIndex == HKS_KSF_NUM) {
        return false;
    }
    /* return true if one exists */
    return true;
}
#endif /* _CUT_AUTHENTICATE_ */
