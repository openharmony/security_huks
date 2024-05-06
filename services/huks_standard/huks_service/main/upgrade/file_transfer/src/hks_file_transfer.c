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

#include "hks_storage_utils.h"

#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <string.h>

#define OPEN_FDS 64

uint32_t g_frontUserId = 100;

static int32_t GetStoreMaterial(const struct HksBlob *alias, const struct HksUpgradeFileTransferInfo *info,
    struct HksStoreMaterial *outMaterial)
{
    outMaterial->pathType = info->needDe ? DE_PATH : CE_PATH;
    outMaterial->keyAliasPath = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
    if (outMaterial->keyAliasPath == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
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

    if (info->needFrontUser) {
        userIdBlob.data = (uint8_t *)&g_frontUserId;
        userIdBlob.size = sizeof(g_frontUserId);
    } else {
        userIdBlob.data = (uint8_t *)&info->userId;
        userIdBlob.size = sizeof(info->userId);
    }

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
    struct HksStoreFileInfo fileInfo = { 0 };
    struct HksStoreMaterial storeMaterial = { DE_PATH, 0 };
    struct HksBlob aliasBlob = { .data = (uint8_t *)alias, .size = strlen(alias) };
    do {
        ret = GetStoreMaterial(&aliasBlob, info, &storeMaterial);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get store material failed.")

        ret = HksGetFileInfo(&storeMaterial, &fileInfo);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("get file info failed.");
            break;
        };
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

static int32_t TransferFile(const char *alias, const char *oldPath, const struct HksBlob *fileContent,
    const struct HksUpgradeFileTransferInfo *info)
{
    int32_t ret;
    char *newPath = NULL;
    do {
        ret = ConstructNewFilePath(alias, info, &newPath);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("construct new file path failed.");
            break;
        }

        ret = HksIsFileExist(newPath, alias);
        if (ret == HKS_SUCCESS) {
            HKS_LOG_E("file in %" LOG_PUBLIC "s already exists.", newPath);
            // try remove old key file, it is ok if fails.
            (void)HksFileRemove(oldPath, alias);
            break;
        }

        ret = HksMakeFullDir(newPath);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("make dir %" LOG_PUBLIC "s writefailed.", newPath);
            break;
        }

        // The result of the info record dose not need to take into consideration.
        (void)RecordKeyOperation(KEY_OPERATION_SAVE, newPath, alias);

        ret = HksFileWrite(newPath, alias, 0, fileContent->data, fileContent->size);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("file %" LOG_PUBLIC "s/%" LOG_PUBLIC "s write failed.", newPath, alias);
            break;
        }

        ret = HksFileRemove(oldPath, alias);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("file %" LOG_PUBLIC "s/%" LOG_PUBLIC "s remove failed.", oldPath, alias);
            // remove new file in case of old file removing fails, for avoiding double backup problem
            if (HksFileRemove(newPath, alias) != HKS_SUCCESS) {
                HKS_LOG_E("try remove new file %" LOG_PUBLIC "s/%" LOG_PUBLIC "s failed.", newPath, alias);
            } else {
                HKS_LOG_I("remove new file success.");
            }
        }
    } while (false);
    HKS_FREE(newPath);

    return ret;
}

static int32_t SplitPath(const char *fpath, const struct FTW *ftwbuf, char **path, char **alias)
{
    *alias = (char *)HksMalloc(strlen(fpath) + 1 - ftwbuf->base);
    if (*alias == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(*alias, strlen(fpath) - ftwbuf->base, fpath + ftwbuf->base, strlen(fpath) - ftwbuf->base);

    *path = (char *)HksMalloc(ftwbuf->base + 1);
    if (*path == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(*path, ftwbuf->base, fpath, ftwbuf->base);

    HKS_LOG_I("path is %" LOG_PUBLIC "s.", *path);

    return HKS_SUCCESS;
}

static int32_t GetFileContent(const char *path, const char *alias, struct HksBlob *fileContent)
{
    uint32_t size = HksFileSize(path, alias);
    if (size == 0) {
        return HKS_ERROR_FILE_SIZE_FAIL;
    }
    fileContent->data = (uint8_t *)HksMalloc(size);
    HKS_IF_NULL_RETURN(fileContent->data, HKS_ERROR_MALLOC_FAIL)

    fileContent->size = size;
    return HksFileRead(path, alias, 0, fileContent, &fileContent->size);
}

static int ProcessFileUpgrade(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    (void)ftwbuf;
    if (typeflag != FTW_F) {
        HKS_LOG_D("%" LOG_PUBLIC "s not a file", fpath);
        return 0;
    }
    char *alias = NULL;
    char *path = NULL;
    struct HksBlob fileContent = { 0 };
    int32_t ret;
    do {
        ret = SplitPath(fpath, ftwbuf, &path, &alias);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "split fpath failed.")

        ret = GetFileContent(path, alias, &fileContent);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "get file content failed.")

        struct HksUpgradeFileTransferInfo info = { 0 };
        ret = HksParseConfig(&fileContent, &info);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HksParseConfig failed, path is %" LOG_PUBLIC "s", fpath);
            break;
        }
        if (info.skipTransfer) {
            HKS_LOG_I("file %" LOG_PUBLIC "s should skip transfer.", fpath);
            break;
        }
        HKS_IF_NOT_SUCC_LOGE(TransferFile(alias, path, &fileContent, &info), "TransferFile failed!")
    } while (false);
    HKS_FREE(path);
    HKS_FREE(alias);
    HKS_FREE_BLOB(fileContent);

    // continue to traverse files
    return 0;
}

ENABLE_CFI(static int32_t UpgradeFileTransfer())
{
    // depth first and ignore soft link
    int nftwRet = nftw(HKS_KEY_STORE_TMP_PATH, ProcessFileUpgrade, OPEN_FDS, FTW_DEPTH | FTW_PHYS);
    HKS_LOG_I("call nftw result is %" LOG_PUBLIC "d.", nftwRet);

    return HKS_SUCCESS;
}

static int32_t CopyDeToTmpPathIfNeed()
{
    if (HksIsDirExist(HKS_KEY_STORE_TMP_PATH) == HKS_SUCCESS) {
        return HKS_SUCCESS;
    }
    int32_t ret = rename(HKS_KEY_STORE_PATH, HKS_KEY_STORE_TMP_PATH);
    if (ret != 0) {
        HKS_LOG_E("move de file path to old file path failed, error code is %" LOG_PUBLIC "d.", errno);
        return HKS_ERROR_MAKE_DIR_FAIL;
    }
    ret = HksMakeDir(HKS_KEY_STORE_PATH);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("create de path failed, error code is %" LOG_PUBLIC "d.", ret);
        return HKS_ERROR_MAKE_DIR_FAIL;
    }
    HKS_LOG_I("move de file path to old file path");
    return HKS_SUCCESS;
}

int32_t HksUpgradeFileTransferOnPowerOn()
{
    CopyDeToTmpPathIfNeed();
    return UpgradeFileTransfer();
}

int32_t HksUpgradeFileTransferOnUserUnlock(uint32_t userId)
{
    g_frontUserId = userId;
    return HksUpgradeFileTransferOnPowerOn();
}
