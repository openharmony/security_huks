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

#include "hks_type.h"
#include "hks_type_inner.h"
#ifndef _CUT_AUTHENTICATE_

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_storage_utils.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hks_file_operator.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_param.h"
#include "securec.h"

#define HKS_ENCODE_OFFSET_LEN         6
#define HKS_ENCODE_KEY_SALT_VALUE     0x3f
#define KEY_ALIAS_ANONYMOUS_LEN       4
#define KEY_ALIAS_SUFFIX_LEN          4
#define HKS_ROOT_USER_UPPERBOUND      100

#ifdef HKS_SUPPORT_POSIX
static void ConstructInvalidCharacter(const char input, char *output)
{
    switch (input) {
        case ':':
            *output = '#';
            return;
        case '<':
            *output = '$';
            return;
        case '>':
            *output = '%';
            return;
        case '?':
            *output = '&';
            return;
        case '\\':
            *output = '(';
            return;
        case '|':
            *output = ')';
            return;
        default:
            *output = input;
            return;
    }
}
#endif

static void ResumeInvalidCharacter(const char input, char *output)
{
    switch (input) {
        case '#':
            *output = ':';
            return;
        case '$':
            *output = '<';
            return;
        case '%':
            *output = '>';
            return;
        case '&':
            *output = '?';
            return;
        case '(':
            *output = '\\';
            return;
        case ')':
            *output = '|';
            return;
        default:
            *output = input;
            return;
    }
}

int32_t ConstructPlainName(const struct HksBlob *blob, char *targetName, uint32_t nameLen)
{
    if (blob->size == sizeof(int)) {
        int32_t offset = sprintf_s(targetName, nameLen, "%d", *(int *)blob->data);
        if (offset <= 0) {
            HKS_LOG_E("get plain name failed");
            return HKS_ERROR_INSUFFICIENT_MEMORY;
        }

        return HKS_SUCCESS;
    }

    uint32_t count = 0;
    for (uint32_t i = 0; i < blob->size; ++i) {
        if (count >= (nameLen - 1)) { /* nameLen can be guaranteed to be greater than 1 */
            return HKS_ERROR_INSUFFICIENT_DATA;
        }
        targetName[count++] = blob->data[i];

#ifdef HKS_SUPPORT_POSIX
        ConstructInvalidCharacter(targetName[count - 1], &targetName[count - 1]);
#endif
    }

    return HKS_SUCCESS;
}

/* Encode invisible content to visible */
int32_t ConstructName(const struct HksBlob *blob, char *targetName, uint32_t nameLen)
{
    uint32_t count = 0;

    for (uint32_t i = 0; i < blob->size; ++i) {
        if (count >= (nameLen - 1)) { /* nameLen can be guaranteed to be greater than 1 */
            return HKS_ERROR_INSUFFICIENT_DATA;
        }

        if ((blob->data[i] < '0') || (blob->data[i] > '~')) {
            targetName[count++] = '+' + (blob->data[i] >> HKS_ENCODE_OFFSET_LEN);
            targetName[count++] = '0' + (blob->data[i] & HKS_ENCODE_KEY_SALT_VALUE);
        } else {
            targetName[count++] = blob->data[i];
        }

#ifdef HKS_SUPPORT_POSIX
        ConstructInvalidCharacter(targetName[count - 1], &targetName[count - 1]);
#endif
    }

    return HKS_SUCCESS;
}

/* Decode encoded content to original content */
int32_t ConstructBlob(const char *src, struct HksBlob *blob)
{
    uint32_t size = strlen(src);
    uint8_t *outputBlob = (uint8_t *)HksMalloc(size);
    HKS_IF_NULL_LOGE_RETURN(outputBlob, HKS_ERROR_MALLOC_FAIL, "malloc failed")

    uint32_t count = 0;
    int32_t ret = HKS_SUCCESS;
    for (uint32_t i = 0; i < size; ++i) {
        if ((src[i] >= '+') && (src[i] <= '.')) {
            uint8_t c = (uint8_t)(src[i] - '+') << HKS_ENCODE_OFFSET_LEN;
            i++;
            if (i >= size) {
                ret = HKS_ERROR_INVALID_KEY_FILE; /* keyfile name invalid */
                break;
            }
            char tmp;
            ResumeInvalidCharacter(src[i], &tmp);
            c += tmp - '0';
            outputBlob[count++] = c;
        } else {
            char tmp;
            ResumeInvalidCharacter(src[i], &tmp);
            outputBlob[count++] = tmp;
        }
    }

    if (ret != HKS_SUCCESS) {
        HKS_FREE(outputBlob);
        return ret;
    }

    if (blob->size < count) {
        HKS_FREE(outputBlob);
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    (void)memcpy_s(blob->data, blob->size, outputBlob, count);

    blob->size = count;
    HKS_FREE(outputBlob);
    return ret;
}

int32_t GetPath(const char *path, const char *name, char *targetPath, uint32_t pathLen, uint32_t bakFlag)
{
    if (strncpy_s(targetPath, pathLen, path, strlen(path)) != EOK) {
        HKS_LOG_E("strncpy path failed");
        return HKS_ERROR_BAD_STATE;
    }

    if (targetPath[strlen(targetPath) - 1] != '/') {
        if (strncat_s(targetPath, pathLen, "/", strlen("/")) != EOK) {
            HKS_LOG_E("strncat slash failed");
            return HKS_ERROR_INTERNAL_ERROR;
        }
    }

    if (strncat_s(targetPath, pathLen, name, strlen(name)) != EOK) {
        HKS_LOG_E("strncat Name failed");
        return HKS_ERROR_BAD_STATE;
    }

    if (bakFlag == HKS_STORAGE_BAK_FLAG_TRUE) {
        if (strncat_s(targetPath, pathLen, ".bak", strlen(".bak")) != EOK) {
            HKS_LOG_E("strncat bak failed");
            return HKS_ERROR_BAD_STATE;
        }
    }

    return HKS_SUCCESS;
}

static int32_t DataInit(char **data, uint32_t size)
{
    *data = (char *)HksMalloc(size);
    HKS_IF_NULL_RETURN(*data, HKS_ERROR_MALLOC_FAIL)

    (void)memset_s(*data, size, 0, size);
    return HKS_SUCCESS;
}

static int32_t FileInfoInit(struct HksStoreFileInfo *fileInfo)
{
    fileInfo->mainPath.size = HKS_MAX_FILE_NAME_LEN;
    /* if one param init fail, others free by caller function */
    int32_t ret = DataInit(&fileInfo->mainPath.path, fileInfo->mainPath.size);
    ret += DataInit(&fileInfo->mainPath.fileName, fileInfo->mainPath.size);

#ifdef SUPPORT_STORAGE_BACKUP
    fileInfo->bakPath.size = HKS_MAX_FILE_NAME_LEN;
    ret += DataInit(&fileInfo->bakPath.path, fileInfo->bakPath.size);
    ret += DataInit(&fileInfo->bakPath.fileName, fileInfo->bakPath.size);
#endif

    return ret;
}

void FileInfoFree(struct HksStoreFileInfo *fileInfo)
{
    HKS_FREE(fileInfo->mainPath.path);
    HKS_FREE(fileInfo->mainPath.fileName);
    fileInfo->mainPath.size = 0;

#ifdef SUPPORT_STORAGE_BACKUP
    HKS_FREE(fileInfo->bakPath.path);
    HKS_FREE(fileInfo->bakPath.fileName);
    fileInfo->bakPath.size = 0;
#endif
}

/*
 * keyAlias: xxxxxxxxxxxxxxxxxxx********************xxxxxxxxxxxxxxxxxx
 *                              |<- anonymous len ->||<- suffix len ->|
 *           |<----------------- keyAlias len ----------------------->|
 */
int32_t RecordKeyOperation(uint32_t operation, const char *path, const char *keyAlias)
{
    (void)path;
    uint32_t bufSize = strlen(keyAlias) + 1;
    char *outKeyAlias = (char *)HksMalloc(bufSize);
    HKS_IF_NULL_RETURN(outKeyAlias, HKS_ERROR_MALLOC_FAIL)

    (void)memset_s(outKeyAlias, bufSize, 0, bufSize);

    uint32_t keyAliasLen = strlen(keyAlias);
    for (uint32_t i = 0; i < keyAliasLen; ++i) {
        if ((keyAliasLen < (i + 1 + KEY_ALIAS_ANONYMOUS_LEN + KEY_ALIAS_SUFFIX_LEN)) &&
            ((i + 1 + KEY_ALIAS_SUFFIX_LEN) <= keyAliasLen)) {
            outKeyAlias[i] = '*';
        } else {
            outKeyAlias[i] = keyAlias[i];
        }
    }
    outKeyAlias[keyAliasLen] = '\0';

    int32_t ret = HKS_SUCCESS;
    switch (operation) {
        case KEY_OPERATION_SAVE:
            HKS_LOG_I("generate key, storage path: %" LOG_PUBLIC "s, key alias: %" LOG_PUBLIC "s",
                path, outKeyAlias);
            break;
        case KEY_OPERATION_GET:
            HKS_LOG_I("use key, storage path: %" LOG_PUBLIC "s, key alias: %" LOG_PUBLIC "s", path, outKeyAlias);
            break;
        case KEY_OPERATION_DELETE:
            HKS_LOG_I("delete key, storage path: %" LOG_PUBLIC "s, key alias: %" LOG_PUBLIC "s",
                path, outKeyAlias);
            break;
        default:
            ret = HKS_ERROR_INVALID_ARGUMENT;
    }

    HKS_FREE(outKeyAlias);
    return ret;
}

void FileNameListFree(struct HksFileEntry **fileNameList, uint32_t keyCount)
{
    if (fileNameList != NULL && *fileNameList != NULL) {
        for (uint32_t i = 0; i < keyCount; ++i) {
            HKS_FREE((*fileNameList)[i].fileName);
        }
        HKS_FREE(*fileNameList);
    }
}

int32_t FileNameListInit(struct HksFileEntry **fileNameList, uint32_t keyCount)
{
    if (((keyCount > UINT32_MAX / (sizeof(struct HksFileEntry)))) || (keyCount == 0)) {
        HKS_LOG_E("keyCount too big or is zero.");
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    uint32_t totalSize = keyCount * sizeof(struct HksFileEntry);
    *fileNameList = (struct HksFileEntry *)HksMalloc(totalSize);
    HKS_IF_NULL_LOGE_RETURN(*fileNameList, HKS_ERROR_MALLOC_FAIL, "malloc file name list failed.")

    (void)memset_s(*fileNameList, totalSize, 0, totalSize);
    int32_t ret = HKS_SUCCESS;

    for (uint32_t i = 0; i < keyCount; ++i) {
        (*fileNameList)[i].fileNameLen = HKS_MAX_FILE_NAME_LEN;
        (*fileNameList)[i].fileName = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
        if ((*fileNameList)[i].fileName == NULL) {
            HKS_LOG_E("malloc failed.");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
    }

    if (ret != HKS_SUCCESS) {
        FileNameListFree(fileNameList, keyCount);
    }
    return ret;
}

#ifdef L2_STANDARD
static int32_t CheckIfBothTagExist(const struct HksParam *storageLevel,
    const struct HksParam *specificUserId)
{
    if (storageLevel->uint32Param == HKS_AUTH_STORAGE_LEVEL_DE) {
        if (specificUserId->int32Param < 0) {
            HKS_LOG_E("invalid specificUserId, specificUserId is %" LOG_PUBLIC "d.", specificUserId->int32Param);
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    } else {
        if (specificUserId->int32Param < HKS_ROOT_USER_UPPERBOUND) {
            HKS_LOG_E("invalid specificUserId when tag storage level is CE or ECE, specificUserId is %" LOG_PUBLIC "d",
                specificUserId->int32Param);
            return HKS_ERROR_INVALID_ARGUMENT;
        }
    }
    return HKS_SUCCESS;
}

static int32_t CheckIfOnlyStorageLevelTagExist(const struct HksProcessInfo *processInfo,
    const struct HksParam *storageLevel)
{
    if (storageLevel->uint32Param != HKS_AUTH_STORAGE_LEVEL_DE &&
#ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
        storageLevel->uint32Param != HKS_AUTH_STORAGE_LEVEL_OLD_DE_TMP &&
#endif
        processInfo->userIdInt < HKS_ROOT_USER_UPPERBOUND) {
        HKS_LOG_E("invalid userId when tag storage level is CE or ECE, userId is %" LOG_PUBLIC "d",
            processInfo->userIdInt);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    return HKS_SUCCESS;
}
#endif

int32_t CheckSpecificUserIdAndStorageLevel(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet)
{
#ifdef L2_STANDARD
    if (paramSet == NULL) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = HKS_SUCCESS;
    struct HksParam *storageLevel = NULL;
    struct HksParam *specificUserId = NULL;

    bool storageLevelExist = HksGetParam(paramSet, HKS_TAG_AUTH_STORAGE_LEVEL, &storageLevel) == HKS_SUCCESS;
    bool specificUserIdExist = HksGetParam(paramSet, HKS_TAG_SPECIFIC_USER_ID, &specificUserId) == HKS_SUCCESS;
    if (storageLevelExist && specificUserIdExist) {
        ret = CheckIfBothTagExist(storageLevel, specificUserId);
    } else if (storageLevelExist && !specificUserIdExist) {
        ret = CheckIfOnlyStorageLevelTagExist(processInfo, storageLevel);
    }
    HKS_IF_NOT_SUCC_RETURN(ret, ret)
#endif
    (void)processInfo;
    (void)paramSet;
    return HKS_SUCCESS;
}

int32_t HksMakeFullDir(const char *path)
{
    uint32_t pathLen = strlen(path);
    char *curPath = (char *)HksMalloc(pathLen + 1);
    if (curPath == NULL) {
        HKS_LOG_E("cur path malloc failed.");
        return HKS_ERROR_MALLOC_FAIL;
    }
    int32_t ret = HKS_SUCCESS;
    do {
        for (uint32_t i = 1; i < pathLen; ++i) {
            if (path[i] == '/') {
                (void)memcpy_s(curPath, pathLen, path, i);
                curPath[i] = '\0';
                if (HksIsDirExist(curPath) == HKS_SUCCESS) {
                    continue;
                }
                ret = HksMakeDir(curPath);
                if (ret != HKS_SUCCESS && ret != HKS_ERROR_ALREADY_EXISTS) {
                    HKS_LOG_E("mkdir %" LOG_PUBLIC "s failed.", curPath);
                    break;
                }
                ret = HKS_SUCCESS;
            }
        }
        if (ret != HKS_SUCCESS) {
            break;
        }
        ret = HksMakeDir(path);
        if (ret == HKS_ERROR_ALREADY_EXISTS) {
            ret = HKS_SUCCESS;
        }
    } while (false);

    HKS_FREE(curPath);
    return ret;
}

// remove duplicated '/'
static void StandardizePath(char *path)
{
    // the size must be more than 0
    uint32_t size = strlen(path);
    uint32_t index = 1;
    for (uint32_t i = 1; i < size; ++i) {
        if (path[i] != '/' || path[i - 1] != '/') {
            path[index] = path[i];
            ++index;
        }
    }
    // the index will be less than or equal to the size
    path[index] = '\0';
}

#ifdef L2_STANDARD
// Only ce and ece will access this check function.
static int32_t CheckUserPathExist(enum HksPathType pathType, const char *userIdPath)
{
    char userPath[HKS_MAX_DIRENT_FILE_LEN] = { 0 };
    int32_t offset = sprintf_s(userPath, HKS_MAX_DIRENT_FILE_LEN, "%s/%s",
        pathType == CE_PATH ? HKS_CE_ROOT_PATH : HKS_ECE_ROOT_PATH, userIdPath);
    if (offset <= 0) {
        HKS_LOG_E("get user path failed, path type is %" LOG_PUBLIC "d.", pathType);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    return HksIsDirExist(userPath) == HKS_SUCCESS ? HKS_SUCCESS : HKS_ERROR_NO_PERMISSION;
}
#endif

static int32_t ConstructPath(const struct HksStoreMaterial *material, struct HksStoreFileInfo *fileInfo)
{
    int32_t ret = HKS_SUCCESS;
    int32_t offset = 0;
    switch (material->pathType) {
        case DE_PATH:
            offset = sprintf_s(fileInfo->mainPath.path, HKS_MAX_DIRENT_FILE_LEN, "%s/%s/%s/%s",
                HKS_KEY_STORE_PATH, material->userIdPath,  material->uidPath, material->storageTypePath);
            break;
#ifdef L2_STANDARD
        case CE_PATH:
            ret = CheckUserPathExist(CE_PATH, material->userIdPath);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check user path exist failed.")
            offset = sprintf_s(fileInfo->mainPath.path, HKS_MAX_DIRENT_FILE_LEN, "%s/%s/%s/%s/%s",
                HKS_CE_ROOT_PATH, material->userIdPath,  HKS_STORE_SERVICE_PATH, material->uidPath,
                material->storageTypePath);
            break;
        case ECE_PATH:
            ret = CheckUserPathExist(ECE_PATH, material->userIdPath);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "check user path exist failed.")
            offset = sprintf_s(fileInfo->mainPath.path, HKS_MAX_DIRENT_FILE_LEN, "%s/%s/%s/%s/%s",
                HKS_ECE_ROOT_PATH, material->userIdPath,  HKS_STORE_SERVICE_PATH, material->uidPath,
                material->storageTypePath);
            break;
#ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
        case TMP_PATH:
            offset = sprintf_s(fileInfo->mainPath.path, HKS_MAX_DIRENT_FILE_LEN, "%s/%s/%s/%s",
                HKS_KEY_STORE_TMP_PATH, material->userIdPath,  material->uidPath, material->storageTypePath);
            break;
#endif
#ifdef HKS_USE_RKC_IN_STANDARD
        case RKC_IN_STANDARD_PATH:
            // there is no user id path in rkc of standard
            offset = sprintf_s(fileInfo->mainPath.path, HKS_MAX_DIRENT_FILE_LEN, "%s/%s/%s",
                HKS_KEY_RKC_PATH,  material->uidPath, material->storageTypePath);
            break;
#endif
#endif
#ifdef HKS_ENABLE_LITE_HAP
        case LITE_HAP_PATH:
            offset = sprintf_s(fileInfo->mainPath.path, HKS_MAX_DIRENT_FILE_LEN, "%s/%s/%s/%s",
                HKS_KEY_STORE_LITE_HAP, material->userIdPath,  material->uidPath, material->storageTypePath);
            break;
#endif
    }
    if (offset <= 0) {
        HKS_LOG_E("get main path failed, path type is %" LOG_PUBLIC "d.", material->pathType);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    return ret;
}

static int32_t GetMainPath(const struct HksStoreMaterial *material, struct HksStoreFileInfo *fileInfo)
{
    int32_t ret = HKS_SUCCESS;
#ifdef L2_STANDARD
    bool isUserPath = material->pathType == CE_PATH || material->pathType == ECE_PATH;
#else
    bool isUserPath = false;
#endif

    ret = ConstructPath(material, fileInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "construct path failed")

    StandardizePath(fileInfo->mainPath.path);
    ret = HksMakeFullDir(fileInfo->mainPath.path);
    if (isUserPath) {
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_NO_PERMISSION, "make full dir failed.")
    } else {
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "make full dir failed.")
    }
    if (material->keyAliasPath != NULL) {
        if (memcpy_s(fileInfo->mainPath.fileName, HKS_MAX_FILE_NAME_LEN,
            material->keyAliasPath, strlen(material->keyAliasPath)) != EOK) {
            ret = HKS_ERROR_INSUFFICIENT_MEMORY;
        }
    }
    return ret;
}

// for now only construct for mainPath, bakPath is not on the table
int32_t HksGetFileInfo(const struct HksStoreMaterial *material, struct HksStoreFileInfo *fileInfo)
{
    int32_t ret = FileInfoInit(fileInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "hks file info init failed, ret = %" LOG_PUBLIC "d.", ret)

    return GetMainPath(material, fileInfo);
}
#endif /* _CUT_AUTHENTICATE_ */
