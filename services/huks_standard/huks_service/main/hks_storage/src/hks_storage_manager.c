/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define HUKS_DISABLE_LOG_AT_FILE_TO_REDUCE_ROM_SIZE

#ifndef _CUT_AUTHENTICATE_

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_common_check.h"
#include "hks_storage.h"
#include "hks_storage_manager.h"
#include "hks_template.h"
#include "hks_type_inner.h"

#include "securec.h"

#ifdef L2_STANDARD
#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
#ifndef HKS_USE_RKC_IN_STANDARD
#include "hks_osaccount_check.h"
#include "hks_upgrade_lock.h"
#endif

static bool IsDe(const struct HksParamSet *paramSet)
{
    struct HksParam *storageLevelParam = NULL;
    return HksGetParam(paramSet, HKS_TAG_AUTH_STORAGE_LEVEL, &storageLevelParam) == HKS_SUCCESS &&
        storageLevelParam->uint32Param == HKS_AUTH_STORAGE_LEVEL_DE;
}
#endif

static int32_t GetStorageLevelAndStoreUserIdParam(const struct HksProcessInfo* processInfo,
    const struct HksParamSet *paramSet, uint32_t *storageLevel, int32_t *storeUserId)
{
    struct HksParam *specificUserIdParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_SPECIFIC_USER_ID, &specificUserIdParam);
    if (ret == HKS_SUCCESS) {
        *storeUserId = specificUserIdParam->int32Param;
    } else if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
        *storeUserId = processInfo->userIdInt;
        ret = HKS_SUCCESS;
    }
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get store user id failed, ret = %" LOG_PUBLIC "d.", ret)

    struct HksParam *storageLevelParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_AUTH_STORAGE_LEVEL, &storageLevelParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get storage level tag failed, ret = %" LOG_PUBLIC "d.", ret)

    *storageLevel = storageLevelParam->uint32Param;

#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
#ifndef HKS_USE_RKC_IN_STANDARD
    HksTransferFileIfNeed(*storageLevel, *storeUserId);
#endif
#endif
    return ret;
}
#endif

static void UnlockIfDe(__attribute__((unused)) const struct HksParamSet *paramSet)
{
#ifdef L2_STANDARD
#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    if (!IsDe(paramSet)) {
        return;
    }
#ifndef HKS_USE_RKC_IN_STANDARD
    HksUpgradeOrRequestUnlockRead();
#endif
#endif
#endif
}

#ifdef HKS_ENABLE_LITE_HAP
#define HKS_LITE_NATIVE_PROCESS_NAME "hks_client"
static bool CheckIsLiteHap(const struct HksBlob *processName)
{
    if (processName->size == strlen(HKS_LITE_NATIVE_PROCESS_NAME)
        && HksMemCmp(processName->data, HKS_LITE_NATIVE_PROCESS_NAME,
        strlen(HKS_LITE_NATIVE_PROCESS_NAME)) == HKS_SUCCESS) {
        return false;
    }
    return true;
}
#endif

static int32_t GetKeyAliasPath(const struct HksBlob *keyAlias, struct HksStoreMaterial *outMaterial)
{
    if (keyAlias == NULL) {
        return HKS_SUCCESS;
    }
    outMaterial->keyAliasPath = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
    HKS_IF_NULL_LOGE_RETURN(outMaterial->keyAliasPath, HKS_ERROR_MALLOC_FAIL, "malloc keyAliasPath failed.")
    return ConstructName(keyAlias, outMaterial->keyAliasPath, HKS_MAX_FILE_NAME_LEN);
}

static int32_t GetUserIdPath(int32_t userId, bool isPlain, struct HksStoreMaterial *outMaterial)
{
    outMaterial->userIdPath = (char *)HksMalloc(HKS_MAX_DIRENT_FILE_LEN);
    HKS_IF_NULL_LOGE_RETURN(outMaterial->userIdPath, HKS_ERROR_MALLOC_FAIL, "malloc userIdPath failed.")
    struct HksBlob userIdBlob = { .data = (uint8_t *)&userId, .size = sizeof(userId) };

    int32_t ret;
    if (isPlain) {
        ret = ConstructPlainName(&userIdBlob, outMaterial->userIdPath, HKS_MAX_DIRENT_FILE_LEN);
    } else {
        if (userId == 0) {
            HKS_LOG_D("skip user id path.");
            return HKS_SUCCESS;
        }
        ret = ConstructName(&userIdBlob, outMaterial->userIdPath, HKS_MAX_DIRENT_FILE_LEN);
    }

    return ret;
}

static int32_t GetUidPath(bool isPlain, const struct HksBlob *processName,
    struct HksStoreMaterial *outMaterial)
{
    outMaterial->uidPath = (char *)HksMalloc(HKS_MAX_DIRENT_FILE_LEN);
    HKS_IF_NULL_LOGE_RETURN(outMaterial->uidPath, HKS_ERROR_MALLOC_FAIL, "malloc uidPath failed.")
#ifdef HKS_ENABLE_LITE_HAP
    if (CheckIsLiteHap(processName)) {
        if (memcpy_s(outMaterial->uidPath, HKS_MAX_DIRENT_FILE_LEN, processName->data, processName->size) != EOK) {
            HKS_LOG_E("construct uidPath fail, uidPath buffer is too small.");
            return HKS_ERROR_BUFFER_TOO_SMALL;
        }
        return HKS_SUCCESS;
    }
#endif
    int32_t ret;
    if (isPlain) {
        ret = ConstructPlainName(processName, outMaterial->uidPath, HKS_MAX_DIRENT_FILE_LEN);
    } else {
        ret = ConstructName(processName, outMaterial->uidPath, HKS_MAX_DIRENT_FILE_LEN);
    }

    return ret;
}

static int32_t GetStorageTypePath(uint32_t storageType, struct HksStoreMaterial *outMaterial)
{
    switch (storageType) {
        case HKS_STORAGE_TYPE_KEY:
        case HKS_STORAGE_TYPE_BAK_KEY:
            outMaterial->storageTypePath = (char *)HksMalloc(sizeof(HKS_KEY_STORE_KEY_PATH) + 1);
            HKS_IF_NULL_RETURN(outMaterial->storageTypePath, HKS_ERROR_MALLOC_FAIL)
            (void)memcpy_s(outMaterial->storageTypePath, sizeof(HKS_KEY_STORE_KEY_PATH),
                HKS_KEY_STORE_KEY_PATH, sizeof(HKS_KEY_STORE_KEY_PATH));
            return HKS_SUCCESS;
        case HKS_STORAGE_TYPE_ROOT_KEY:
            outMaterial->storageTypePath = (char *)HksMalloc(sizeof(HKS_KEY_STORE_ROOT_KEY_PATH) + 1);
            HKS_IF_NULL_RETURN(outMaterial->storageTypePath, HKS_ERROR_MALLOC_FAIL)
            (void)memcpy_s(outMaterial->storageTypePath, sizeof(HKS_KEY_STORE_ROOT_KEY_PATH),
                HKS_KEY_STORE_ROOT_KEY_PATH, sizeof(HKS_KEY_STORE_ROOT_KEY_PATH));
            return HKS_SUCCESS;
        default:
            return HKS_ERROR_BAD_STATE;
    }
}

static bool GetIsPlainPath(uint32_t storageLevel)
{
    (void)storageLevel;
#ifdef L2_STANDARD
    switch (storageLevel) {
        case HKS_AUTH_STORAGE_LEVEL_DE:
            return true;
        case HKS_AUTH_STORAGE_LEVEL_CE:
            return true;
        case HKS_AUTH_STORAGE_LEVEL_ECE:
            return true;
#ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
        case HKS_AUTH_STORAGE_LEVEL_OLD_DE_TMP:
            return false;
#endif
    }
#endif
    return false;
}

static int32_t GetPathType(const struct HksProcessInfo *processInfo, uint32_t storageType,
    int32_t storageLevel, struct HksStoreMaterial *outMaterial)
{
    (void)processInfo;
    (void)storageType;
#ifdef HKS_ENABLE_LITE_HAP
    if (CheckIsLiteHap(&processInfo->processName)) {
        outMaterial->pathType = LITE_HAP_PATH;
        return HKS_SUCCESS;
    }
#endif
#ifdef HKS_USE_RKC_IN_STANDARD
    if (storageType == HKS_STORAGE_TYPE_ROOT_KEY) {
        outMaterial->pathType = RKC_IN_STANDARD_PATH;
        return HKS_SUCCESS;
    }
#endif
    switch (storageLevel) {
        case HKS_AUTH_STORAGE_LEVEL_DE:
            outMaterial->pathType = DE_PATH;
            break;
#ifdef L2_STANDARD
        case HKS_AUTH_STORAGE_LEVEL_CE:
            outMaterial->pathType = CE_PATH;
            break;
        case HKS_AUTH_STORAGE_LEVEL_ECE:
            outMaterial->pathType = ECE_PATH;
            break;
    #ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
        case HKS_AUTH_STORAGE_LEVEL_OLD_DE_TMP:
            outMaterial->pathType = TMP_PATH;
            break;
    #endif
#endif
        default:
            HKS_LOG_E("invalid storage level %" LOG_PUBLIC "d.", storageLevel);
    }
    return HKS_SUCCESS;
}

static void FreeStorageMaterial(struct HksStoreMaterial *material)
{
    HKS_FREE(material->userIdPath);
    HKS_FREE(material->uidPath);
    HKS_FREE(material->storageTypePath);
    HKS_FREE(material->keyAliasPath);
    HKS_FREE(material->assetAccessGroup);
    HKS_FREE(material->developerId);
}

#ifdef L2_STANDARD
#define HKS_MAX_ACCESS_GROUP_LEN 128
#define HKS_MAX_DEVELOPER_ID_LEN 64
static int32_t GetAssetAccessGroupPath(const struct HksParamSet *paramSet, struct HksStoreMaterial *outMaterial)
{
    struct HksParam *accessGroupParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_KEY_ACCESS_GROUP, &accessGroupParam);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    uint32_t blobSize = accessGroupParam->blob.size;
    HKS_IF_TRUE_LOGE_RETURN(blobSize > HKS_MAX_ACCESS_GROUP_LEN, HKS_FAILURE,
        "access group len %" LOG_PUBLIC "u is invalid", blobSize)

    outMaterial->assetAccessGroup = (char *)HksMalloc(blobSize + 1);
    HKS_IF_NULL_LOGE_RETURN(outMaterial->assetAccessGroup, HKS_ERROR_MALLOC_FAIL, "malloc access group failed")
    (void)memcpy_s(outMaterial->assetAccessGroup, blobSize + 1, accessGroupParam->blob.data, blobSize);
    outMaterial->assetAccessGroup[blobSize] = '\0';

    return HKS_SUCCESS;
}

static int32_t GetDeveloperIdPath(const struct HksParamSet *paramSet,  struct HksStoreMaterial *outMaterial)
{
    struct HksParam *developerParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_DEVELOPER_ID, &developerParam);
    HKS_IF_NOT_SUCC_RETURN(ret, ret);

    uint32_t blobSize = developerParam->blob.size;
    HKS_IF_TRUE_LOGE_RETURN(blobSize > HKS_MAX_DEVELOPER_ID_LEN, HKS_FAILURE,
        "developId len %" LOG_PUBLIC "u is invalid", blobSize)

    outMaterial->developerId = (char *)HksMalloc(blobSize + 1);
    HKS_IF_NULL_LOGE_RETURN(outMaterial->developerId, HKS_ERROR_MALLOC_FAIL, "malloc developerId failed")
    (void)memcpy_s(outMaterial->developerId, blobSize + 1, developerParam->blob.data, blobSize);
    outMaterial->developerId[blobSize] = '\0';

    return HKS_SUCCESS;
}
#endif

static int32_t InitStorageMaterial(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const struct HksBlob *keyAlias, uint32_t storageType,
    struct HksStoreMaterial *outMaterial)
{
    (void)paramSet;
    uint32_t storageLevel = HKS_AUTH_STORAGE_LEVEL_DE;
    int32_t storeUserId = processInfo->userIdInt;
    int32_t ret;
#ifdef L2_STANDARD
    ret = GetStorageLevelAndStoreUserIdParam(processInfo, paramSet, &storageLevel, &storeUserId);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get storage level and user id from param set failed.")
#endif
    bool isPlainPath = GetIsPlainPath(storageLevel);

    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0, 0, 0 };
    do {
        ret = GetPathType(processInfo, storageType, storageLevel, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get path type failed.")

        ret = GetUserIdPath(storeUserId, isPlainPath, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get user id path failed.")

        ret = GetUidPath(isPlainPath, &processInfo->processName, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get uid path failed.")
#ifdef L2_STANDARD
        ret = GetAssetAccessGroupPath(paramSet, &material);
        if (ret == HKS_SUCCESS) {
            ret = GetDeveloperIdPath(paramSet, &material);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get developerId failed.")
        }
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS && ret != HKS_ERROR_PARAM_NOT_EXIST, "get group failed.")
#endif
        ret = GetStorageTypePath(storageType, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get storage type path failed.")

        ret = GetKeyAliasPath(keyAlias, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get key alias path failed.")

        *outMaterial = material;
        return HKS_SUCCESS;
    } while (false);
    FreeStorageMaterial(&material);
    return ret;
}

static int32_t HksConstructStoreFileInfo(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksStoreMaterial *material, struct HksStoreFileInfo *fileInfo)
{
    int32_t ret;
    do {
        ret = CheckSpecificUserIdAndStorageLevel(processInfo, paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check storagelevel or specificuserid tag failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksGetFileInfo(material, fileInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks get plain file info failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);
    return ret;
}

int32_t HksManageStoreKeyBlob(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, const struct HksBlob *keyBlob, uint32_t storageType)
{
    (void)processInfo;
    UnlockIfDe(paramSet);
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0, 0, 0 };
    int32_t ret;
    do {
#ifdef _STORAGE_LITE_
        ret = HksStoreKeyBlob(NULL, keyAlias, storageType, keyBlob);
#else
        ret = InitStorageMaterial(processInfo, paramSet, keyAlias, storageType, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init storage material failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksConstructStoreFileInfo(processInfo, paramSet, &material, &fileInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)

        struct HksParam *isKeyOverride = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_KEY_OVERRIDE, &isKeyOverride);
        if (ret == HKS_SUCCESS) {
            ret = HksStoreKeyBlob(&fileInfo, &material, keyBlob, isKeyOverride->boolParam);
        } else {
            ret = HksStoreKeyBlob(&fileInfo, &material, keyBlob, true);
        }
        
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks store key blob failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    FreeStorageMaterial(&material);
    return ret;
}

int32_t HksManageStoreDeleteKeyBlob(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, uint32_t storageType)
{
    (void)processInfo;
    UnlockIfDe(paramSet);
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0, 0, 0 };
    int32_t ret;
    do {
#ifdef _STORAGE_LITE_
        ret = HksStoreDeleteKeyBlob(NULL, keyAlias, storageType);
#else
        ret = InitStorageMaterial(processInfo, paramSet, keyAlias, storageType, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init storage material failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksConstructStoreFileInfo(processInfo, paramSet, &material, &fileInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksStoreDeleteKeyBlob(&fileInfo, &material);
#endif
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "hks delete key blob failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    FreeStorageMaterial(&material);
    return ret;
}

int32_t HksManageStoreIsKeyBlobExist(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, uint32_t storageType)
{
    (void)processInfo;
    UnlockIfDe(paramSet);
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0, 0, 0 };
    int32_t ret;
    do {
#ifdef _STORAGE_LITE_
        ret = HksStoreIsKeyBlobExist(NULL, keyAlias, storageType);
#else
        ret = InitStorageMaterial(processInfo, paramSet, keyAlias, storageType, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init storage material failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksConstructStoreFileInfo(processInfo, paramSet, &material, &fileInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksStoreIsKeyBlobExist(&fileInfo);
#endif
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "hks key blob in old de not exist, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    FreeStorageMaterial(&material);
    return ret;
}

int32_t HksManageStoreGetKeyBlob(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, struct HksBlob *keyBlob, uint32_t storageType)
{
    (void)processInfo;
    UnlockIfDe(paramSet);
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0, 0, 0 };
    int32_t ret;
    do {
#ifdef _STORAGE_LITE_
        ret = HksStoreGetKeyBlob(NULL, keyAlias, storageType, keyBlob);
#else
        ret = InitStorageMaterial(processInfo, paramSet, keyAlias, storageType, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init storage material failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksConstructStoreFileInfo(processInfo, paramSet, &material, &fileInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)

        if (storageType != HKS_STORAGE_TYPE_BAK_KEY) {
            ret = HksStoreGetKeyBlob(&fileInfo.mainPath, &material, keyBlob);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        else {
            ret = HksStoreGetKeyBlob(&fileInfo.bakPath, &material, keyBlob);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks get key blob failed, ret = %" LOG_PUBLIC "d.", ret)

            HKS_IF_NOT_SUCC_LOGE(HksStorageWriteFile(fileInfo.mainPath.path, fileInfo.mainPath.fileName,
                keyBlob->data, keyBlob->size, true), "hks copy bak key to main key failed")
        }
#endif
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks get key blob failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    FreeStorageMaterial(&material);
    return ret;
}

int32_t HksManageStoreGetKeyBlobSize(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, uint32_t *keyBlobSize, uint32_t storageType)
{
    (void)processInfo;
    UnlockIfDe(paramSet);
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0, 0, 0 };
    int32_t ret;
    do {
#ifdef _STORAGE_LITE_
        ret = HksStoreGetKeyBlobSize(NULL, keyAlias, storageType, keyBlobSize);
#else
        ret = InitStorageMaterial(processInfo, paramSet, keyAlias, storageType, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init storage material failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksConstructStoreFileInfo(processInfo, paramSet, &material, &fileInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)

        if (storageType != HKS_STORAGE_TYPE_BAK_KEY) {
            ret = HksStoreGetKeyBlobSize(&fileInfo.mainPath, &material, keyBlobSize);
        }
#ifdef SUPPORT_STORAGE_BACKUP
        else {
            ret = HksStoreGetKeyBlobSize(&fileInfo.bakPath, &material, keyBlobSize);
        }
#endif
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks get key blob failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    FreeStorageMaterial(&material);
    return ret;
}

int32_t HksManageGetKeyAliasByProcessName(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount)
{
    UnlockIfDe(paramSet);
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0, 0, 0 };
    int32_t ret;
    do {
        ret = InitStorageMaterial(processInfo, paramSet, NULL, HKS_STORAGE_TYPE_KEY, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init storage material failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksConstructStoreFileInfo(processInfo, paramSet, &material, &fileInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksGetKeyAliasByProcessName(&fileInfo, keyInfoList, listCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks get key alias by processname failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    FreeStorageMaterial(&material);
    return ret;
}

int32_t HksManageGetKeyCountByProcessName(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    uint32_t *fileCount)
{
    (void)processInfo;
    UnlockIfDe(paramSet);
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0, 0, 0 };
    int32_t ret;
    do {
#ifdef _STORAGE_LITE_
        ret = HksGetKeyCountByProcessName(NULL, fileCount);
#else
        ret = InitStorageMaterial(processInfo, paramSet, NULL, HKS_STORAGE_TYPE_KEY, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init storage material failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksConstructStoreFileInfo(processInfo, paramSet, &material, &fileInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksGetKeyCountByProcessName(&fileInfo, fileCount);
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks get key count by processname failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    FreeStorageMaterial(&material);
    return ret;
}

int32_t HksManageListAliasesByProcessName(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksKeyAliasSet **outData)
{
    UnlockIfDe(paramSet);
#ifdef L2_STANDARD
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    struct HksStoreMaterial material = { DE_PATH, 0, 0, 0, 0, 0, 0 };
    int32_t ret;
    do {
        ret = InitStorageMaterial(processInfo, paramSet, NULL, HKS_STORAGE_TYPE_KEY, &material);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init storage material failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksConstructStoreFileInfo(processInfo, paramSet, &material, &fileInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksListAliasesByProcessName(&fileInfo, outData);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks list aliases by processname failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    FreeStorageMaterial(&material);
    return ret;
#else
    (void)processInfo;
    (void)paramSet;
    (void)outData;
    return HKS_SUCCESS;
#endif
}

int32_t HksManageStoreRenameKeyAlias(const struct HksProcessInfo *processInfo,
    const struct HksBlob *oldKeyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *newKeyAlias, uint32_t storageType)
{
    (void)processInfo;
    UnlockIfDe(paramSet);
    struct HksStoreFileInfo oldKeyFileInfo = { { 0 } };
    struct HksStoreFileInfo newKeyFileInfo = { { 0 } };
    struct HksStoreMaterial oldKeyMaterial = { DE_PATH, 0, 0, 0, 0, 0, 0 };
    struct HksStoreMaterial newKeyMaterial = { DE_PATH, 0, 0, 0, 0, 0, 0 };
    int32_t ret;
    do {
        ret = InitStorageMaterial(processInfo, paramSet, oldKeyAlias, storageType, &oldKeyMaterial);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init old key storage material failed, ret = %" LOG_PUBLIC "d.", ret);
        ret = InitStorageMaterial(processInfo, paramSet, newKeyAlias, storageType, &newKeyMaterial);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init new key storage material failed, ret = %" LOG_PUBLIC "d.", ret);

        ret = HksConstructStoreFileInfo(processInfo, paramSet, &oldKeyMaterial, &oldKeyFileInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct old store file info failed, ret = %" LOG_PUBLIC "d.", ret);
        ret = HksConstructStoreFileInfo(processInfo, paramSet, &newKeyMaterial, &newKeyFileInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct new store file info failed, ret = %" LOG_PUBLIC "d.", ret);

        ret = HksCheckParamSetValidity(paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check paramset invalid failed!");

        struct HksParam *isNeedCopy = NULL;
        ret = HksGetParam(paramSet, HKS_TAG_IS_COPY_NEW_KEY, &isNeedCopy);
        ret = HksStoreRenameKeyAlias(&oldKeyFileInfo, &newKeyFileInfo, &oldKeyMaterial, &newKeyMaterial,
            (ret == HKS_SUCCESS && isNeedCopy->boolParam == true) ? true : false);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks rename key blod failed, ret = %" LOG_PUBLIC "d.", ret);
    } while (0);
    FileInfoFree(&oldKeyFileInfo);
    FileInfoFree(&newKeyFileInfo);
    FreeStorageMaterial(&oldKeyMaterial);
    FreeStorageMaterial(&newKeyMaterial);
    return ret;
}

#endif