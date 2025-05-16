/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "hks_file_transfer.h"

#include "hks_cfi.h"
#include "hks_config_parser.h"
#include "hks_file_operator.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type_inner.h"
#include "hks_util.h"

#include "hks_storage_utils.h"
#include "hks_plugin_adapter.h"
#include "hks_plugin_def.h"
#include "hks_event_info.h"
#include "hisysevent_wrapper.h"

#include <errno.h>
#include <ftw.h>
#include <securec.h>
#include <stdio.h>
#include <string.h>

#define OPEN_FDS 64

uint32_t g_frontUserId = 100;

static int32_t GetStoreMaterial(const struct HksBlob *alias, const struct HksUpgradeFileTransferInfo *info,
    struct HksStoreMaterial *outMaterial)
{
    outMaterial->pathType = info->needDe ? DE_PATH : CE_PATH;
    outMaterial->keyAliasPath = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
    HKS_IF_NULL_RETURN(outMaterial->keyAliasPath, HKS_ERROR_MALLOC_FAIL)
    int32_t ret = ConstructName(alias, outMaterial->keyAliasPath, HKS_MAX_FILE_NAME_LEN);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "construct key alias name failed.")

    outMaterial->uidPath = (char *)HksMalloc(HKS_MAX_DIRENT_FILE_LEN);
    HKS_IF_NULL_RETURN(outMaterial->uidPath, HKS_ERROR_MALLOC_FAIL);

    struct HksBlob uidBlob = { .data = (uint8_t *)&info->uid, .size = sizeof(info->uid) };
    ret = ConstructPlainName(&uidBlob, outMaterial->uidPath, HKS_MAX_DIRENT_FILE_LEN);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "construct uid path failed.")

    outMaterial->userIdPath = (char *)HksMalloc(HKS_MAX_DIRENT_FILE_LEN);
    HKS_IF_NULL_RETURN(outMaterial->userIdPath, HKS_ERROR_MALLOC_FAIL);

    struct HksBlob userIdBlob = { 0 };

    userIdBlob.data = info->needFrontUser ? (uint8_t *)&g_frontUserId : (uint8_t *)&info->userId;
    userIdBlob.size = info->needFrontUser ? sizeof(g_frontUserId) : sizeof(info->userId);

    ret = ConstructPlainName(&userIdBlob, outMaterial->userIdPath, HKS_MAX_DIRENT_FILE_LEN);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "construct user id path failed.")

    outMaterial->storageTypePath = (char *)HksMalloc(sizeof(HKS_KEY_STORE_KEY_PATH) + 1);
    HKS_IF_NULL_RETURN(outMaterial->storageTypePath, HKS_ERROR_MALLOC_FAIL);

    (void)memcpy_s(outMaterial->storageTypePath, sizeof(HKS_KEY_STORE_KEY_PATH),
        HKS_KEY_STORE_KEY_PATH, sizeof(HKS_KEY_STORE_KEY_PATH));

    return ret;
}

static int32_t ConstructNewFilePath(const char *alias, const struct HksUpgradeFileTransferInfo *info,
    char **newPath)
{
    int32_t ret;
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreFileInfo fileInfo = { { 0 }, { 0 } };
#else
    struct HksStoreFileInfo fileInfo = { { 0 } };
#endif
    struct HksStoreMaterial storeMaterial = { DE_PATH, 0 };
    struct HksBlob aliasBlob = { .data = (uint8_t *)alias, .size = strlen(alias) };
    do {
        ret = GetStoreMaterial(&aliasBlob, info, &storeMaterial);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get store material failed.")

        ret = HksGetFileInfo(&storeMaterial, &fileInfo);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get file info failed.")
        *newPath = (char *)HksMalloc(strlen(fileInfo.mainPath.path) + 1);
        if (*newPath == NULL) {
            HKS_LOG_E("malloc newPath->data failed.");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        (void)memcpy_s(*newPath, strlen(fileInfo.mainPath.path),
            fileInfo.mainPath.path, strlen(fileInfo.mainPath.path));
    } while (false);
    FileInfoFree(&fileInfo);
    HKS_FREE(storeMaterial.userIdPath);
    HKS_FREE(storeMaterial.uidPath);
    HKS_FREE(storeMaterial.storageTypePath);
    HKS_FREE(storeMaterial.keyAliasPath);
    return ret;
}

static int32_t TransferFile(const char *alias, const char *anonymousKeyAlias, const char *oldPath,
    const struct HksBlob *fileContent, const struct HksUpgradeFileTransferInfo *info)
{
    int32_t ret;
    char *newPath = NULL;
    do {
        ret = ConstructNewFilePath(alias, info, &newPath);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "construct new file path failed.")

        // Check if the alias is of rdb key file. If it is, skip the checking of duplicate to overwrite key file.
        if (HksIsRdbDeKey(alias) && info->needDe) {
            HKS_LOG_I("Remove rbd key file in de path, to accept the old file.");
            ret = HksFileRemove(newPath, alias);
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "remove DE rdb file in %" LOG_PUBLIC "s write failed.", newPath)
        } else {
            ret = HksIsFileExist(newPath, alias);
            if (ret == HKS_SUCCESS) {
                HKS_LOG_E("file in %" LOG_PUBLIC "s already exists.", newPath);
                // try remove old key file, it is ok if fails.
                (void)HksFileRemove(oldPath, alias);
                break;
            }
        }

        ret = HksMakeFullDir(newPath);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "make dir %" LOG_PUBLIC "s writefailed.", newPath)

        // The result of the info record dose not need to take into consideration.
        HKS_LOG_I("transfer key, storage userid: %" LOG_PUBLIC "d, uid: %" LOG_PUBLIC "d, alias: %" LOG_PUBLIC "s",
            info->userId, info->uid, anonymousKeyAlias);

        ret = HksFileWrite(newPath, alias, 0, fileContent->data, fileContent->size);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "file %" LOG_PUBLIC "s write failed.", newPath)

        ret = HksFileRemove(oldPath, alias);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("file in %" LOG_PUBLIC "s remove failed.", oldPath);
            // remove new file in case of old file removing fails, for avoiding double backup problem
            if (HksFileRemove(newPath, alias) != HKS_SUCCESS) {
                HKS_LOG_E("try remove new file in %" LOG_PUBLIC "s failed.", newPath);
            } else {
                HKS_LOG_I("remove new file success.");
            }
        }
    } while (false);
    HKS_FREE(newPath);

    return ret;
}

static int32_t SplitPath(const char *filePath, const struct FTW *ftw, char **path, char **alias)
{
    *alias = (char *)HksMalloc(strlen(filePath) + 1 - ftw->base);
    HKS_IF_NULL_RETURN(*alias, HKS_ERROR_MALLOC_FAIL)
    (void)memcpy_s(*alias, strlen(filePath) - ftw->base, filePath + ftw->base, strlen(filePath) - ftw->base);

    *path = (char *)HksMalloc(ftw->base + 1);
    HKS_IF_NULL_RETURN(*path, HKS_ERROR_MALLOC_FAIL)
    (void)memcpy_s(*path, ftw->base, filePath, ftw->base);

    HKS_LOG_I("path is %" LOG_PUBLIC "s.", *path);

    return HKS_SUCCESS;
}

static int32_t GetFileContent(const char *path, const char *alias, struct HksBlob *fileContent)
{
    uint32_t size = HksFileSize(path, alias);
    HKS_IF_TRUE_RETURN(size == 0, HKS_ERROR_FILE_SIZE_FAIL)
    fileContent->data = (uint8_t *)HksMalloc(size);
    HKS_IF_NULL_RETURN(fileContent->data, HKS_ERROR_MALLOC_FAIL)

    fileContent->size = size;
    return HksFileRead(path, alias, 0, fileContent, &fileContent->size);
}

static int ProcessFileUpgrade(const char *filePath, const struct stat *st, int typeFlag, struct FTW *ftw)
{
    (void)st;
    if (typeFlag != FTW_F) {
        HKS_LOG_D("%" LOG_PUBLIC "s not a file", filePath);
        return 0;
    }
    char *alias = NULL;
    char *path = NULL;
    char *anonymousKeyAlias = NULL;
    struct HksBlob fileContent = { 0 };
    int32_t ret;
    do {
        ret = SplitPath(filePath, ftw, &path, &alias);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "split filePath failed.")

        ret = AnonymizeKeyAlias(alias, &anonymousKeyAlias);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get anonymous key alias failed.")

        ret = GetFileContent(path, alias, &fileContent);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get file content failed.")

        struct HksUpgradeFileTransferInfo info = { 0 };
        ret = HksParseConfig(alias, &fileContent, &info);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "HksParseConfig failed, userid: %" LOG_PUBLIC "d, uid: %" LOG_PUBLIC "d, "
            "alias: %" LOG_PUBLIC "s", info.userId, info.uid, anonymousKeyAlias)
        HKS_IF_TRUE_LOGI_BREAK(info.skipTransfer, "file should skip transfer, userid: %" LOG_PUBLIC "d, "
            "uid: %" LOG_PUBLIC "d, alias: %" LOG_PUBLIC "s", info.userId, info.uid, anonymousKeyAlias)
        HKS_IF_NOT_SUCC_LOGE(TransferFile(alias, anonymousKeyAlias, path, &fileContent, &info), "TransferFile failed!")
    } while (false);
    HKS_FREE(path);
    HKS_FREE(alias);
    HKS_FREE(anonymousKeyAlias);
    HKS_FREE_BLOB(fileContent);

    // continue to traverse files
    return 0;
}

ENABLE_CFI(int32_t UpgradeFileTransfer(void))
{
    // depth first and ignore soft link
    int nftwRet = nftw(HKS_KEY_STORE_TMP_PATH, ProcessFileUpgrade, OPEN_FDS, FTW_DEPTH | FTW_PHYS);
    HKS_LOG_I("call nftw result is %" LOG_PUBLIC "d.", nftwRet);

    return HKS_SUCCESS;
}

static int32_t CopyDeToTmpPathIfNeed(void)
{
    HKS_IF_TRUE_RETURN(HksIsDirExist(HKS_KEY_STORE_TMP_PATH) == HKS_SUCCESS, HKS_SUCCESS)
    int32_t ret = rename(HKS_KEY_STORE_PATH, HKS_KEY_STORE_TMP_PATH);
    HKS_IF_TRUE_LOGE_RETURN(ret != 0, HKS_ERROR_MAKE_DIR_FAIL,
        "move de file path to old file path failed, ret = %" LOG_PUBLIC "d.", ret);

    ret = HksMakeDir(HKS_KEY_STORE_PATH);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_MAKE_DIR_FAIL,
        "create de path failed, error code is %" LOG_PUBLIC "d.", ret)
    HKS_LOG_I("move de file path to old file path");
    return HKS_SUCCESS;
}

static int32_t ConstructHksEventCommonInfo(HksEventCommonInfo *commonInfo, uint64_t totalCostTime)
{
    HKS_IF_NULL_LOGE_RETURN(commonInfo, HKS_ERROR_NULL_POINTER, "commonInfo in ConstructHksEventCommonInfo is NULL");
    commonInfo->callerInfo.name = "KEY_LEVEL_CHANGE";
    commonInfo->result.code = HKS_FAILURE;
    commonInfo->result.errMsg = (char *)HksGetThreadErrorMsg();
    commonInfo->statInfo.totalCost = (uint32_t)totalCostTime;
    commonInfo->eventId = HKS_EVENT_KEY_LEVEL_CHANGE;
    commonInfo->count = 1;
    commonInfo->function = "HksUpgradeFileTransferOnPowerOn";
    return HKS_SUCCESS;
}

int32_t HksUpgradeFileTransferOnPowerOn(void)
{
    uint64_t startTime = 0;
    uint64_t endTime = 0;
    int32_t ret;
    
    (void)HksElapsedRealTime(&startTime);
    WritePerformanceEvent(HUKS_TRANSFER_KEY);
    CopyDeToTmpPathIfNeed();
    
    ret = UpgradeFileTransfer();
    
    (void)HksElapsedRealTime(&endTime);
    if (HksGetThreadErrorMsgLen() != 0) {
        uint64_t totalCostTime = endTime - startTime;
        HksEventCommonInfo commonInfo = {0};
        (void)ConstructHksEventCommonInfo(&commonInfo, totalCostTime);
        (void)HksPluginOnLocalRequest(CODE_FAULT_METRICS, &commonInfo, NULL);
    }
    return ret;
}

int32_t HksUpgradeFileTransferOnUserUnlock(uint32_t userId)
{
    g_frontUserId = userId;
    return HksUpgradeFileTransferOnPowerOn();
}
 