/*
 * Copyright (c) 2020-2024 Huawei Device Co., Ltd.
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
#include "hks_param.h"
#include "hks_rkc.h"
#include "hks_storage_manager.h"
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
    if (ksfName == NULL || tmpKsf == NULL) {
        HKS_LOG_E("Input argument ksfName or tmpKsf is null");
        return HKS_ERROR_NULL_POINTER;
    }

    tmpKsf->data = (uint8_t *)HksMalloc(HKS_KSF_BUF_LEN);
    HKS_IF_NULL_RETURN(tmpKsf->data, HKS_ERROR_MALLOC_FAIL)

    tmpKsf->size = HKS_KSF_BUF_LEN;
    (void)memset_s(tmpKsf->data, tmpKsf->size, 0, tmpKsf->size);

    int32_t ret;
    struct HksParamSet *paramSet = NULL;
    do {
        struct HksProcessInfo processInfo = { {0, NULL}, {0, NULL}, 0, 0, 0 };
        ret = GetProcessInfo(&processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get process info failed")

        const struct HksBlob fileNameBlob = { strlen(ksfName), (uint8_t *)ksfName };

        ret = HksRkcBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "rkc build paramset failed")

        ret = HksManageStoreGetKeyBlob(&processInfo, paramSet, &fileNameBlob, tmpKsf, HKS_STORAGE_TYPE_ROOT_KEY);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Get ksf file failed! ret = 0x%" LOG_PUBLIC "X", ret)

        HksFreeParamSet(&paramSet);
        return HKS_SUCCESS;
    } while (0);

    /* the data of root or main key should be cleared after use */
    (void)memset_s(tmpKsf->data, tmpKsf->size, 0, tmpKsf->size);
    HKS_FREE_BLOB(*tmpKsf);
    HksFreeParamSet(&paramSet);
    return ret;
}

int32_t ExtractFieldFromBuffer(const struct HksBlob *srcBlob, uint32_t *srcOffset, void *dest, uint32_t destSize)
{
    if (CheckBlob(srcBlob) != HKS_SUCCESS || srcOffset == NULL || dest == NULL || destSize == 0) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (srcBlob->size < *srcOffset) {
        HKS_LOG_E("Offset is greater than size of source buffer");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    if (srcBlob->size - *srcOffset < destSize) {
        HKS_LOG_E("Source buffer is too small");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    (void)memcpy_s(dest, destSize, srcBlob->data + *srcOffset, destSize);
    *srcOffset += destSize;
    return HKS_SUCCESS;
}

int32_t FillFieldToBuffer(const void *src, uint32_t srcSize, struct HksBlob *destBlob, uint32_t *destOffset)
{
    if (src == NULL || srcSize == 0 || CheckBlob(destBlob) != HKS_SUCCESS || destOffset == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (destBlob->size < *destOffset) {
        HKS_LOG_E("Offset is greater than size of destination buffer");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    if (destBlob->size - *destOffset < srcSize) {
        HKS_LOG_E("Destination buffer is too small");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, src, srcSize) != EOK) {
        HKS_LOG_E("Memcpy failed");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }
    *destOffset += srcSize;
    return HKS_SUCCESS;
}

int32_t RkcExtractKsfFileFlag(const struct HksBlob *ksfFromFile, uint32_t *ksfBufOffset)
{
    /* Extract file flag. */
    uint8_t fileFlag[HKS_RKC_KSF_FLAG_LEN] = {0};
    int32_t ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, fileFlag, HKS_RKC_KSF_FLAG_LEN);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy file flag failed!")

    /* Check file flag. */
    if (HksMemCmp(fileFlag, g_hksRkcKsfFlag, HKS_RKC_KSF_FLAG_LEN) != 0) {
        HKS_LOG_E("Ksf file flag is invalid!");
        return HKS_ERROR_READ_FILE_FAIL;
    }

    return HKS_SUCCESS;
}

static int32_t RkcExtractTime(const struct HksBlob *ksfFromFile, uint32_t *ksfBufOffset, struct HksTime *time)
{
    int32_t ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, &(time->hksYear), sizeof(time->hksYear));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, &(time->hksMon), sizeof(time->hksMon));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, &(time->hksDay), sizeof(time->hksDay));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, &(time->hksHour), sizeof(time->hksHour));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, &(time->hksMin), sizeof(time->hksMin));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    return ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, &(time->hksSec), sizeof(time->hksSec));
}

int32_t ExtractKsfDataRkc(const struct HksBlob *ksfFromFile, uint32_t *ksfBufOffset, struct HksKsfDataRkc *ksfDataRkc)
{
    if (ksfDataRkc == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    /* Extract rkCreatedTime */
    int32_t ret = RkcExtractTime(ksfFromFile, ksfBufOffset, &(ksfDataRkc->rkCreatedTime));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract rkExpiredTime */
    ret = RkcExtractTime(ksfFromFile, ksfBufOffset, &(ksfDataRkc->rkExpiredTime));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract the first material */
    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, ksfDataRkc->rkMaterial1,
        sizeof(ksfDataRkc->rkMaterial1));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract the second material */
    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, ksfDataRkc->rkMaterial2,
        sizeof(ksfDataRkc->rkMaterial2));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract iterator number */
    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, &(ksfDataRkc->rmkIter), sizeof(ksfDataRkc->rmkIter));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract salt */
    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, ksfDataRkc->rmkSalt, sizeof(ksfDataRkc->rmkSalt));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract hash algorithm */
    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, &(ksfDataRkc->rmkHashAlg), sizeof(ksfDataRkc->rmkHashAlg));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract reserve field */
    return ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, ksfDataRkc->rkRsv, sizeof(ksfDataRkc->rkRsv));
}

int32_t ExtractKsfDataMk(const struct HksBlob *ksfFromFile, uint32_t *ksfBufOffset, struct HksKsfDataMk *ksfDataMk)
{
    if (ksfDataMk == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    /* Extract mkCreatedTime */
    int32_t ret = RkcExtractTime(ksfFromFile, ksfBufOffset, &(ksfDataMk->mkCreatedTime));
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Extract mkCreatedTime failed!")

    /* Extract mkExpiredTime */
    ret = RkcExtractTime(ksfFromFile, ksfBufOffset, &(ksfDataMk->mkExpiredTime));
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Extract mkExpiredTime failed!")

    /* Fill encryption algorithm */
    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, &(ksfDataMk->mkEncryptAlg),
        sizeof(ksfDataMk->mkEncryptAlg));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Fill IV */
    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, ksfDataMk->mkIv, sizeof(ksfDataMk->mkIv));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Fill ciphertext */
    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, ksfDataMk->mkCiphertext,
        sizeof(ksfDataMk->mkCiphertext));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Fill reserve field */
    return ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, ksfDataMk->mkRsv, sizeof(ksfDataMk->mkRsv));
}

int32_t RkcExtractKsfHash(const struct HksBlob *ksfFromFile, uint32_t *ksfBufOffset)
{
    if (ksfFromFile == NULL || ksfBufOffset == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    if (*ksfBufOffset < HKS_RKC_KSF_FLAG_LEN || ksfFromFile->size < HKS_RKC_KSF_FLAG_LEN ||
        (ksfFromFile->size - HKS_RKC_KSF_FLAG_LEN) < (*ksfBufOffset - HKS_RKC_KSF_FLAG_LEN)) {
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    /* calculate sha256, skip file flag, begin with version, end with reserve field. */
    uint8_t hashResult[HKS_RKC_HASH_LEN] = {0};
    struct HksBlob hashResultBlob = { HKS_RKC_HASH_LEN, hashResult };
    /* the upper layer ensures no overflow */
    const struct HksBlob hashSrc = { *ksfBufOffset - HKS_RKC_KSF_FLAG_LEN, ksfFromFile->data + HKS_RKC_KSF_FLAG_LEN };
    int32_t ret = HksCryptoHalHash(HKS_DIGEST_SHA256, &hashSrc, &hashResultBlob);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Hks hash failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* Extract hash from ksf buffer */
    uint8_t ksfHash[HKS_RKC_HASH_LEN] = {0};
    ret = ExtractFieldFromBuffer(ksfFromFile, ksfBufOffset, ksfHash, HKS_RKC_HASH_LEN);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

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

     /* Extract version */
    ret = ExtractFieldFromBuffer(ksfFromFile, &ksfBufOffset, &(ksfDataRkcWithVer->rkVersion),
        sizeof(ksfDataRkcWithVer->rkVersion));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract fields of root key component */
    ret = ExtractKsfDataRkc(ksfFromFile, &ksfBufOffset, &(ksfDataRkcWithVer->ksfDataRkc));
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Extract ksf rkc failed! ret = 0x%" LOG_PUBLIC "X", ret)

    /* Extract hash */
    return RkcExtractKsfHash(ksfFromFile, &ksfBufOffset);
}

static int32_t ExtractKsfBufMk(const struct HksBlob *ksfFromFile, struct HksKsfDataMkWithVer *ksfDataMkWithVer)
{
    uint32_t ksfBufOffset = 0;

    /* Extract file flag. */
    int32_t ret = RkcExtractKsfFileFlag(ksfFromFile, &ksfBufOffset);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract version */
    ret = ExtractFieldFromBuffer(ksfFromFile, &ksfBufOffset, &(ksfDataMkWithVer->mkVersion),
        sizeof(ksfDataMkWithVer->mkVersion));
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    /* Extract fields of main key */
    ret = ExtractKsfDataMk(ksfFromFile, &ksfBufOffset, &(ksfDataMkWithVer->ksfDataMk));
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Extract ksf mk failed! ret = 0x%" LOG_PUBLIC "X", ret)

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
    int32_t ret = FillFieldToBuffer(&(time->hksYear), sizeof(time->hksYear), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy hksYear failed!")

    ret = FillFieldToBuffer(&(time->hksMon), sizeof(time->hksMon), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy hksMon failed!")

    ret = FillFieldToBuffer(&(time->hksDay), sizeof(time->hksDay), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy hksDay failed!")

    ret = FillFieldToBuffer(&(time->hksHour), sizeof(time->hksHour), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy hksHour failed!")

    ret = FillFieldToBuffer(&(time->hksMin), sizeof(time->hksMin), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy hksMin failed!")

    ret = FillFieldToBuffer(&(time->hksSec), sizeof(time->hksSec), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy hksSec failed!")

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
    ret = FillFieldToBuffer(ksfDataRkc->rkMaterial1, sizeof(ksfDataRkc->rkMaterial1), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy first material to ksf buf failed!")

    /* Fill the second material */
    ret = FillFieldToBuffer(ksfDataRkc->rkMaterial2, sizeof(ksfDataRkc->rkMaterial2), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy second material to ksf buf failed!")

    /* Fill iterator number */
    ret = FillFieldToBuffer(&(ksfDataRkc->rmkIter), sizeof(ksfDataRkc->rmkIter), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy iterator number to ksf buf failed!")

    /* Fill salt */
    ret = FillFieldToBuffer(ksfDataRkc->rmkSalt, sizeof(ksfDataRkc->rmkSalt), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy salt to ksf buf failed!")

    /* Fill hash algorithm */
    ret = FillFieldToBuffer(&(ksfDataRkc->rmkHashAlg), sizeof(ksfDataRkc->rmkHashAlg), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy hash algorithm to ksf buf failed!")

    /* Fill reserve field */
    ret = FillFieldToBuffer(ksfDataRkc->rkRsv, sizeof(ksfDataRkc->rkRsv), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy reserve field to ksf buf failed!")

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
    ret = FillFieldToBuffer(&(ksfDataMk->mkEncryptAlg), sizeof(ksfDataMk->mkEncryptAlg), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy encrption algorithm to ksf buf failed!")

    /* Fill IV */
    ret = FillFieldToBuffer(ksfDataMk->mkIv, sizeof(ksfDataMk->mkIv), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy iv to ksf buf failed!")

    /* Fill ciphertext */
    ret = FillFieldToBuffer(ksfDataMk->mkCiphertext, sizeof(ksfDataMk->mkCiphertext), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy ciphertext to ksf buf failed!")

    /* Fill reserve field */
    ret = FillFieldToBuffer(ksfDataMk->mkRsv, sizeof(ksfDataMk->mkRsv), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy reserve field to ksf buf failed!")

    return HKS_SUCCESS;
}

static int32_t FillKsfVerRkc(const struct HksKsfDataRkcWithVer *ksfDataRkcWithVer,
    struct HksBlob *ksfBuf, uint32_t *ksfBufOffset)
{
    /* Fill version */
    int32_t ret = FillFieldToBuffer(&(ksfDataRkcWithVer->rkVersion), sizeof(ksfDataRkcWithVer->rkVersion),
        ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy rkc version to ksf buf failed!")

    ret = FillKsfDataRkc(&(ksfDataRkcWithVer->ksfDataRkc), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy rkc data to ksf buf failed! ret = 0x%" LOG_PUBLIC "X", ret)

    return HKS_SUCCESS;
}

static int32_t FillKsfVerMk(const struct HksKsfDataMkWithVer *ksfDataMkWithVer,
    struct HksBlob *ksfBuf, uint32_t *ksfBufOffset)
{
    /* Fill version */
    int32_t ret = FillFieldToBuffer(&(ksfDataMkWithVer->mkVersion), sizeof(ksfDataMkWithVer->mkVersion),
        ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy mk version to ksf buf failed!")

    ret = FillKsfDataMk(&(ksfDataMkWithVer->ksfDataMk), ksfBuf, ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy mk data to ksf buf failed! ret = 0x%" LOG_PUBLIC "X", ret)

    return HKS_SUCCESS;
}

static int32_t RkcFillKsfHash(struct HksBlob *ksfBuf, uint32_t *ksfBufOffset)
{
    if ((ksfBuf->size < HKS_RKC_KSF_FLAG_LEN) || (*ksfBufOffset < HKS_RKC_KSF_FLAG_LEN) ||
        (ksfBuf->size - HKS_RKC_KSF_FLAG_LEN) < (*ksfBufOffset - HKS_RKC_KSF_FLAG_LEN)) {
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    /* calculate sha256, skip file flag, begin with version, end with reserve field. */
    const struct HksBlob msgBlob = { *ksfBufOffset - HKS_RKC_KSF_FLAG_LEN, ksfBuf->data + HKS_RKC_KSF_FLAG_LEN };
    uint8_t digest[HKS_RKC_HASH_LEN] = { 0 };
    struct HksBlob digestBlob = { HKS_RKC_HASH_LEN, digest };
    int32_t ret = HksCryptoHalHash(HKS_DIGEST_SHA256, &msgBlob, &digestBlob);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Hash failed! ret = 0x%" LOG_PUBLIC "X", ret)

    return FillFieldToBuffer(digestBlob.data, digestBlob.size, ksfBuf, ksfBufOffset);
}

static int32_t FillKsfBufRkc(const struct HksKsfDataRkcWithVer *ksfDataRkcWithVer, struct HksBlob *ksfBuf)
{
    uint32_t ksfBufOffset = 0;

    /* Fill file flag */
    int32_t ret = FillFieldToBuffer(g_hksRkcKsfFlag, sizeof(g_hksRkcKsfFlag), ksfBuf, &ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy file flag to ksf buf failed!")

    /* Fill root key */
    ret = FillKsfVerRkc(ksfDataRkcWithVer, ksfBuf, &ksfBufOffset);
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
    int32_t ret = FillFieldToBuffer(g_hksRkcKsfFlag, sizeof(g_hksRkcKsfFlag), ksfBuf, &ksfBufOffset);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "Memcpy file flag to ksf buf failed!")

    /* Fill main key */
    ret = FillKsfVerMk(ksfDataMkWithVer, ksfBuf, &ksfBufOffset);
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
    struct HksParamSet *paramSet = NULL;
    do {
        /* Fill data into buffer */
        ret = FillKsfBufRkc(ksfDataRkc, &ksfBuf);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Fill rkc ksf buf failed! ret = 0x%" LOG_PUBLIC "X", ret)

        struct HksProcessInfo processInfo = { {0, NULL}, {0, NULL}, 0, 0, 0 };
        ret = GetProcessInfo(&processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get process info failed")

        /* write buffer data into keystore file */
        const struct HksBlob fileNameBlob = { strlen(ksfName), (uint8_t *)ksfName };

        ret = HksRkcBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "rkc build paramset failed")

        ret = HksManageStoreKeyBlob(&processInfo, paramSet, &fileNameBlob, &ksfBuf, HKS_STORAGE_TYPE_ROOT_KEY);
        HKS_IF_NOT_SUCC_LOGE(ret, "Store rkc ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    (void)memset_s(ksfBuf.data, ksfBuf.size, 0, ksfBuf.size);
    HKS_FREE_BLOB(ksfBuf);
    HksFreeParamSet(&paramSet);
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
    struct HksParamSet *paramSet = NULL;
    do {
        /* Fill data into buffer */
        ret = FillKsfBufMk(ksfDataMk, &ksfBuf);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "Fill mk ksf buf failed! ret = 0x%" LOG_PUBLIC "X", ret)

        struct HksProcessInfo processInfo = { {0, NULL}, {0, NULL}, 0, 0, 0 };
        ret = GetProcessInfo(&processInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get process info failed")

        /* write buffer data into keystore file */
        const struct HksBlob fileNameBlob = { strlen(ksfName), (uint8_t *)ksfName };

        ret = HksRkcBuildParamSet(&paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "rkc build paramset failed")

        ret = HksManageStoreKeyBlob(&processInfo, paramSet, &fileNameBlob, &ksfBuf, HKS_STORAGE_TYPE_ROOT_KEY);
        HKS_IF_NOT_SUCC_LOGE(ret, "Store mk ksf failed! ret = 0x%" LOG_PUBLIC "X", ret)
    } while (0);

    (void)memset_s(ksfBuf.data, ksfBuf.size, 0, ksfBuf.size);
    HKS_FREE_BLOB(ksfBuf);
    HksFreeParamSet(&paramSet);
    return ret;
}

bool KsfExist(uint8_t ksfType)
{
    struct HksProcessInfo processInfo = { {0, NULL}, {0, NULL}, 0, 0, 0 };
    int32_t ret = GetProcessInfo(&processInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INTERNAL_ERROR, "get process info failed")

    const struct HksKsfAttr *ksfFileName = NULL;
    if (ksfType == HKS_KSF_TYPE_RKC) {
        ksfFileName = GetGlobalKsfAttrRkc();
    } else {
        ksfFileName = GetGlobalKsfAttrMk();
    }

    struct HksParamSet *paramSet = NULL;
    ret = HksRkcBuildParamSet(&paramSet);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "rkc build paramset failed")

    for (uint32_t i = 0; i < HKS_KSF_NUM; ++i) {
        if (ksfFileName->name[i] == NULL) {
            continue;
        }
        struct HksBlob fileNameBlob = { strlen(ksfFileName->name[i]), (uint8_t *)(ksfFileName->name[i]) };
        if (HksManageStoreIsKeyBlobExist(&processInfo, paramSet, &fileNameBlob,
            HKS_STORAGE_TYPE_ROOT_KEY) == HKS_SUCCESS) {
            HksFreeParamSet(&paramSet);
            return true;
        }
    }
    HksFreeParamSet(&paramSet);
    return false;
}
#endif /* _CUT_AUTHENTICATE_ */
