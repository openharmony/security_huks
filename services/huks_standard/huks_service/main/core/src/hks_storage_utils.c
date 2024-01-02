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

#ifdef L2_STANDARD
#include "hks_response.h"
#endif

#define HKS_ENCODE_OFFSET_LEN         6
#define HKS_ENCODE_KEY_SALT_VALUE     0x3f
#define KEY_ALIAS_ANONYMOUS_LEN       4
#define KEY_ALIAS_SUFFIX_LEN          4
#define USER_ID_ROOT                  "0"
#define HKS_ROOT_USER_UPPERBOUND      100

static bool g_setRootMainPath = false;
static bool g_setRootBakPath = false;

#ifdef HKS_USE_RKC_IN_STANDARD
static bool g_setRootRkcPath = false;
#endif

#ifdef HKS_ENABLE_LITE_HAP
static bool g_setRootLiteHapPath = false;
#endif

static char g_keyStoreMainPath[HKS_MAX_FILE_NAME_LEN + 1] = {0};
static char g_keyStoreBakPath[HKS_MAX_FILE_NAME_LEN + 1] = {0};

#ifdef HKS_USE_RKC_IN_STANDARD
// This is rkc root key position, which is independent from normal keys storage.
static char g_rkcStoreMainPath[HKS_MAX_FILE_NAME_LEN + 1] = {0};
#endif

#ifdef HKS_ENABLE_LITE_HAP
static char g_keyStoreLiteHapPath[HKS_MAX_FILE_NAME_LEN + 1] = {0};
#endif

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

static int32_t GetFullPath(const char *path, const char *processName, const char *storeName,
    struct HksStoreFileInfo *fileInfo)
{
    int32_t ret = GetPath(path, processName, fileInfo->mainPath.processPath, fileInfo->mainPath.size,
        HKS_STORAGE_BAK_FLAG_FLASE);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get processPath failed, ret = %" LOG_PUBLIC "d.", ret)

    return GetPath(fileInfo->mainPath.processPath, storeName, fileInfo->mainPath.path, fileInfo->mainPath.size,
        HKS_STORAGE_BAK_FLAG_FLASE);
}

int32_t GetStoreRootPath(enum HksStoragePathType type, char **path)
{
    if (type == HKS_STORAGE_MAIN_PATH) {
        if (!g_setRootMainPath) {
            uint32_t len = sizeof(g_keyStoreMainPath);
            int32_t ret = HksGetStoragePath(HKS_STORAGE_MAIN_PATH, g_keyStoreMainPath, &len);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get mainStorage path fail")

            g_setRootMainPath = true;
        }
        *path = g_keyStoreMainPath;
        return HKS_SUCCESS;
    }

    if (type == HKS_STORAGE_BACKUP_PATH) {
        if (!g_setRootBakPath) {
            uint32_t len = sizeof(g_keyStoreBakPath);
            int32_t ret = HksGetStoragePath(HKS_STORAGE_BACKUP_PATH, g_keyStoreBakPath, &len);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get backup storage path fail")

            g_setRootBakPath = true;
        }
        *path = g_keyStoreBakPath;
        return HKS_SUCCESS;
    }

#ifdef HKS_ENABLE_LITE_HAP
    if (type == HKS_STORAGE_LITE_HAP_PATH) {
        if (!g_setRootLiteHapPath) {
            uint32_t len = sizeof(g_keyStoreLiteHapPath);
            int32_t ret = HksGetStoragePath(HKS_STORAGE_LITE_HAP_PATH, g_keyStoreLiteHapPath, &len);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get backup storage path fail")

            g_setRootLiteHapPath = true;
        }
        *path = g_keyStoreLiteHapPath;
        return HKS_SUCCESS;
    }
#endif

#ifdef HKS_USE_RKC_IN_STANDARD
    if (type == HKS_STORAGE_RKC_PATH) {
        if (!g_setRootRkcPath) {
            uint32_t len = sizeof(g_rkcStoreMainPath);
            int32_t ret = HksGetStoragePath(HKS_STORAGE_RKC_PATH, g_rkcStoreMainPath, &len);
            HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get rkc storage path fail")
            g_setRootRkcPath = true;
        }
        *path = g_rkcStoreMainPath;
        return HKS_SUCCESS;
    }
#endif

    return HKS_ERROR_INVALID_ARGUMENT;
}

int32_t MakeDirIfNotExist(const char *path)
{
    int32_t ret = HksIsDirExist(path);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_I("dir not exist, path = %" LOG_PUBLIC "s", path);
        ret = HksMakeDir(path);
        if (ret != HKS_SUCCESS) {
            if (ret == HKS_ERROR_ALREADY_EXISTS) {
                ret = HKS_SUCCESS;
            } else {
                HKS_LOG_E("make dir failed");
                ret = HKS_ERROR_MAKE_DIR_FAIL;
            }
        }
    }
    return ret;
}

#ifdef SUPPORT_STORAGE_BACKUP
static int32_t GetBakFullPath(const char *path, const char *processName, const char *storeName,
    struct HksStoreFileInfo *fileInfo)
{
    int32_t ret = GetPath(path, processName, fileInfo->bakPath.processPath, fileInfo->bakPath.size,
        HKS_STORAGE_BAK_FLAG_TRUE);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get bakProcessPath failed, ret = %" LOG_PUBLIC "d.", ret)

    return GetPath(fileInfo->bakPath.processPath, storeName, fileInfo->bakPath.path, fileInfo->bakPath.size,
        HKS_STORAGE_BAK_FLAG_TRUE);
}

static int32_t GetBakFileName(const char *fileName, char *bakFileName, uint32_t bakFileNameLen)
{
    if (strncpy_s(bakFileName, bakFileNameLen, fileName, strlen(fileName)) != EOK) {
        HKS_LOG_E("strncpy_s fileName failed");
        return HKS_ERROR_BAD_STATE;
    }
    if (strncat_s(bakFileName, bakFileNameLen, ".bak", strlen(".bak")) != EOK) {
        HKS_LOG_E("strncat_s bak failed");
        return HKS_ERROR_BAD_STATE;
    }

    return HKS_SUCCESS;
}
#endif

static int32_t DataInit(char **data, uint32_t size)
{
    *data = (char *)HksMalloc(size);
    HKS_IF_NULL_RETURN(*data, HKS_ERROR_MALLOC_FAIL)

    (void)memset_s(*data, size, 0, size);
    return HKS_SUCCESS;
}

int32_t FileInfoInit(struct HksStoreFileInfo *fileInfo)
{
    fileInfo->mainPath.size = HKS_MAX_FILE_NAME_LEN;
    /* if one param init fail, others free by caller function */
    int32_t ret = DataInit(&fileInfo->mainPath.processPath, fileInfo->mainPath.size);
    ret += DataInit(&fileInfo->mainPath.path, fileInfo->mainPath.size);
    ret += DataInit(&fileInfo->mainPath.fileName, fileInfo->mainPath.size);

#ifdef SUPPORT_STORAGE_BACKUP
    fileInfo->bakPath.size = HKS_MAX_FILE_NAME_LEN;
    ret += DataInit(&fileInfo->bakPath.processPath, fileInfo->bakPath.size);
    ret += DataInit(&fileInfo->bakPath.path, fileInfo->bakPath.size);
    ret += DataInit(&fileInfo->bakPath.fileName, fileInfo->bakPath.size);
#endif

    return ret;
}

void FileInfoFree(struct HksStoreFileInfo *fileInfo)
{
    HKS_FREE(fileInfo->mainPath.processPath);
    HKS_FREE(fileInfo->mainPath.path);
    HKS_FREE(fileInfo->mainPath.fileName);
    fileInfo->mainPath.size = 0;

#ifdef SUPPORT_STORAGE_BACKUP
    HKS_FREE(fileInfo->bakPath.processPath);
    HKS_FREE(fileInfo->bakPath.path);
    HKS_FREE(fileInfo->bakPath.fileName);
    fileInfo->bakPath.size = 0;
#endif
}

static int32_t DataStrCopy(char **data, uint32_t size, const char *cpyData)
{
    *data = (char *)HksMalloc(size);
    HKS_IF_NULL_RETURN(*data, HKS_ERROR_MALLOC_FAIL)

    (void)strcpy_s(*data, size, cpyData);
    return HKS_SUCCESS;
}

int32_t CopyFileInfo(const struct HksStoreFileInfo *fileInfoFrom, struct HksStoreFileInfo *fileInfoTo)
{
    fileInfoTo->mainPath.size = fileInfoFrom->mainPath.size;
    int32_t ret = DataStrCopy(&fileInfoTo->mainPath.processPath, fileInfoTo->mainPath.size, fileInfoFrom->mainPath.processPath);
    ret += DataStrCopy(&fileInfoTo->mainPath.path, fileInfoTo->mainPath.size, fileInfoFrom->mainPath.path);
    ret += DataStrCopy(&fileInfoTo->mainPath.fileName, fileInfoTo->mainPath.size, fileInfoFrom->mainPath.fileName);

#ifdef SUPPORT_STORAGE_BACKUP
    fileInfoTo->bakPath.size = fileInfoFrom->mainPath.size;
    ret += DataStrCopy(&fileInfoTo->bakPath.processPath, fileInfoTo->bakPath.size, fileInfoFrom->bakPath.processPath);
    ret += DataStrCopy(&fileInfoTo->bakPath.path, fileInfoTo->bakPath.size, fileInfoFrom->bakPath.path);
    ret += DataStrCopy(&fileInfoTo->bakPath.fileName, fileInfoTo->bakPath.size, fileInfoFrom->bakPath.fileName);
#endif

    return ret;
}

static int32_t MakeSubPath(const char *mainPath, const char *tmpPath, char *outPath, uint32_t outPathLen)
{
    if (strncpy_s(outPath, outPathLen, mainPath, strlen(mainPath)) != EOK) {
        return HKS_ERROR_INTERNAL_ERROR;
    }
    if (strncat_s(outPath, outPathLen, "/", strlen("/")) != EOK) {
        return HKS_ERROR_INTERNAL_ERROR;
    }
    if (strncat_s(outPath, outPathLen, tmpPath, strlen(tmpPath)) != EOK) {
        return HKS_ERROR_INTERNAL_ERROR;
    }
    return HKS_SUCCESS;
}

static int32_t MakeUserAndProcessNamePath(const char *mainRootPath, const struct HksProcessInfo *processInfo,
    const struct HksParam *storeUserId, char *userProcess, int32_t processLen)
{
    char workPath[HKS_MAX_DIRENT_FILE_LEN] = "";

    char *user = (char *)HksMalloc(HKS_PROCESS_INFO_LEN);
    HKS_IF_NULL_RETURN(user, HKS_ERROR_MALLOC_FAIL)

    (void)memset_s(user, HKS_PROCESS_INFO_LEN, 0, HKS_PROCESS_INFO_LEN);

    struct HksBlob specificUserId = { sizeof(storeUserId->int32Param),
        (uint8_t *)&storeUserId->int32Param };
    int32_t ret = ConstructName(&specificUserId, user, HKS_PROCESS_INFO_LEN);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("construct name failed, ret = %" LOG_PUBLIC "d.", ret);
        HKS_FREE(user);
        return ret;
    }

    if (memcpy_s(userProcess, processLen, user, strlen(user)) != EOK) {
        HKS_FREE(user);
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    HKS_FREE(user);

    ret = MakeSubPath(mainRootPath, userProcess, workPath, HKS_MAX_DIRENT_FILE_LEN);
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INTERNAL_ERROR)

    ret = MakeDirIfNotExist(workPath);
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_NO_PERMISSION)

    if (strncat_s(userProcess, HKS_PROCESS_INFO_LEN, "/", strlen("/")) != EOK) {
        return HKS_ERROR_INTERNAL_ERROR;
    }
    if (strncat_s(userProcess, HKS_PROCESS_INFO_LEN, (const char *)processInfo->processName.data,
        processInfo->processName.size) != EOK) {
        return HKS_ERROR_INTERNAL_ERROR;
    }

    ret = MakeSubPath(mainRootPath, userProcess, workPath, HKS_MAX_DIRENT_FILE_LEN);
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INTERNAL_ERROR)

    HKS_IF_NOT_SUCC_RETURN(MakeDirIfNotExist(workPath), HKS_ERROR_NO_PERMISSION)
    return HKS_SUCCESS;
}

#ifdef SUPPORT_STORAGE_BACKUP
static int32_t GetStoreBakPath(const struct HksProcessInfo *processInfo,
    const char *storageName, const struct HksParam *storeUserId, struct HksStoreFileInfo *fileInfo, char *userProcess)
{
    int32_t ret;
    char workPath[HKS_MAX_DIRENT_FILE_LEN] = "";
    char *bakRootPath = NULL;
    ret = GetStoreRootPath(HKS_STORAGE_BACKUP_PATH, &bakRootPath);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get root path failed")

    ret = MakeDirIfNotExist(bakRootPath);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_NO_PERMISSION, "makedir backup path failed")

    (void)memset_s(&workPath, HKS_MAX_DIRENT_FILE_LEN, 0, HKS_MAX_DIRENT_FILE_LEN);

    if (storeUserId->int32Param == 0) {
        if (memcpy_s(userProcess, HKS_PROCESS_INFO_LEN, processInfo->processName.data,
            processInfo->processName.size) != EOK) {
            return HKS_ERROR_INSUFFICIENT_MEMORY;
        }

        ret = MakeSubPath(bakRootPath, userProcess, &workPath, HKS_MAX_DIRENT_FILE_LEN);
        HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INTERNAL_ERROR)

        ret = MakeDirIfNotExist(&workPath);
        HKS_IF_NOT_SUCC_RETURN(ret, ret)
    } else {
        ret = MakeUserAndProcessNamePath(bakRootPath, processInfo, storeUserId, userProcess, HKS_PROCESS_INFO_LEN);
        HKS_IF_NOT_SUCC_RETURN(ret HKS_ERROR_INTERNAL_ERROR)
    }

    ret = GetBakFullPath(bakRootPath, userProcess, storageName, fileInfo);
    HKS_IF_NOT_SUCC_LOGE(ret, "get backup full path failed, ret = %" LOG_PUBLIC "d.", ret)
    return ret;
}
#endif

static int32_t GetStorageLevelAndStoreUserIdParam(const struct HksProcessInfo* processInfo,
    const struct HksParamSet *paramSet, struct HksParam *storageLevel, struct HksParam *storeUserId)
{
#ifdef L2_STANDARD
    struct HksParam *storeUserIdParam = NULL;
    int32_t ret = HksGetParam(paramSet, HKS_TAG_SPECIFIC_USER_ID, &storeUserIdParam);
    if (ret == HKS_SUCCESS) {
        storeUserId->tag = HKS_TAG_SPECIFIC_USER_ID;
        storeUserId->int32Param = storeUserIdParam->int32Param;
    } else if (ret == HKS_ERROR_PARAM_NOT_EXIST) {
        storeUserId->tag = HKS_TAG_USER_ID;
        storeUserId->int32Param = processInfo->userIdInt;
        ret = HKS_SUCCESS;
    }
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get store user id failed, ret = %" LOG_PUBLIC "d.", ret)

    struct HksParam *storageLevelParam = NULL;
    ret = HksGetParam(paramSet, HKS_TAG_AUTH_STORAGE_LEVEL, &storageLevelParam);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get storage level tag failed, ret = %" LOG_PUBLIC "d.", ret)
    storageLevel->tag = HKS_TAG_AUTH_STORAGE_LEVEL;
    storageLevel->uint32Param = storageLevelParam->uint32Param;
#else
    (void)paramSet;
    (void)storageLevel;
    storeUserId->tag = HKS_TAG_USER_ID;
    storeUserId->int32Param = processInfo->userIdInt;
    int32_t ret = HKS_SUCCESS;
#endif
    return ret;
}

static int32_t GetStoreOldDePath(const struct HksProcessInfo *processInfo,
    const char *storageName, const struct HksStoreMaterial *material, struct HksStoreFileInfo *fileInfo)
{
    struct HksParam storageLevel;
    struct HksParam storeUserId;
    int32_t ret = GetStorageLevelAndStoreUserIdParam(processInfo, material->paramSet, &storageLevel, &storeUserId);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get path params failed, ret = %" LOG_PUBLIC "d.", ret)

    char *mainRootPath = NULL;
    char userProcess[HKS_PROCESS_INFO_LEN] = "";
    char workPath[HKS_MAX_DIRENT_FILE_LEN] = "";

    enum HksStoragePathType pathType = HKS_STORAGE_MAIN_PATH;
#ifdef HKS_ENABLE_LITE_HAP
    if (CheckIsLiteHap(&processInfo->processName)) {
        pathType = HKS_STORAGE_LITE_HAP_PATH;
    }
#endif
    // The HKS_ENABLE_LITE_HAP is for lite device, while the HKS_USE_RKC_IN_STANDARD is for standard device.
#ifdef HKS_USE_RKC_IN_STANDARD
    if (strlen(storageName) == strlen(HKS_KEY_STORE_ROOT_KEY_PATH)
        && HksMemCmp(storageName, HKS_KEY_STORE_ROOT_KEY_PATH, strlen(storageName)) == 0) {
        pathType = HKS_STORAGE_RKC_PATH;
    }
#endif
    ret = GetStoreRootPath(pathType, &mainRootPath);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get root path failed")

    ret = MakeDirIfNotExist(mainRootPath);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "makedir main path failed")

    if (storeUserId.int32Param == 0) {
        if (memcpy_s(userProcess, HKS_PROCESS_INFO_LEN, processInfo->processName.data,
            processInfo->processName.size) != EOK) {
            return HKS_ERROR_INSUFFICIENT_MEMORY;
        }

        ret = MakeSubPath(mainRootPath, userProcess, workPath, HKS_MAX_DIRENT_FILE_LEN);
        HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INTERNAL_ERROR)

        ret = MakeDirIfNotExist(workPath);
        HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_NO_PERMISSION)
    } else {
        ret = MakeUserAndProcessNamePath(mainRootPath, processInfo, &storeUserId, userProcess, HKS_PROCESS_INFO_LEN);
        HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INTERNAL_ERROR)
    }

    ret = GetFullPath(mainRootPath, userProcess, storageName, fileInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get full path failed, ret = %" LOG_PUBLIC "d.", ret)

#ifdef SUPPORT_STORAGE_BACKUP
    ret = GetStoreBakPath(processInfo, storageName, storeUserId, fileInfo, userProcess);
#endif

    return ret;
}

static void SaveProcessInfo(uint8_t *processData, int32_t dataLen,
    const struct HksProcessInfo *originProcessInfo, struct HksProcessInfo *processInfo)
{
    processInfo->processName.data = processData;
    processInfo->processName.size = (uint32_t)dataLen;
    (void)memcpy_s(&processInfo->userId, sizeof(struct HksBlob), &originProcessInfo->userId, sizeof(struct HksBlob));
    processInfo->userIdInt = originProcessInfo->userIdInt;
    processInfo->accessTokenId = originProcessInfo->accessTokenId;
}

static int32_t GetStoreOldDePathByStorageType(const struct HksProcessInfo *info,
    const struct HksStoreMaterial *material, struct HksStoreFileInfo *fileInfo, bool supportRootKey)
{
    if (material->storageType == HKS_STORAGE_TYPE_KEY) {
        return GetStoreOldDePath(info, HKS_KEY_STORE_KEY_PATH, material, fileInfo);
    }
    if (material->storageType == HKS_STORAGE_TYPE_CERTCHAIN) {
        return GetStoreOldDePath(info, HKS_KEY_STORE_CERTCHAIN_PATH, material, fileInfo);
    }
    if (material->storageType == HKS_STORAGE_TYPE_ROOT_KEY) {
        if (supportRootKey) {
            return GetStoreOldDePath(info, HKS_KEY_STORE_ROOT_KEY_PATH, material, fileInfo);
        } else {
            return HKS_ERROR_NOT_SUPPORTED;
        }
    }
    return HKS_ERROR_NOT_SUPPORTED;
}

#ifdef L2_STANDARD
static int32_t GetStorePlainPath(const struct HksProcessInfo *processInfo, const char *storageName,
    const struct HksStoreMaterial *material, struct HksStoreFileInfo *fileInfo)
{
    struct HksParam storageLevel;
    struct HksParam storeUserId;
    int32_t ret = GetStorageLevelAndStoreUserIdParam(processInfo, material->paramSet, &storageLevel, &storeUserId);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get path params failed, ret = %" LOG_PUBLIC "d.", ret)

    char mainRootPath[HKS_MAX_DIRENT_FILE_LEN] = "";
    char userProcess[HKS_PROCESS_INFO_LEN] = "";
    char workPath[HKS_MAX_DIRENT_FILE_LEN] = "";

    if (memcpy_s(userProcess, HKS_PROCESS_INFO_LEN, processInfo->processName.data,
        processInfo->processName.size) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    int32_t offset = 0;
    if (storageLevel.uint32Param == HKS_AUTH_STORAGE_LEVEL_ECE) {
        offset = sprintf_s(mainRootPath, HKS_MAX_DIRENT_FILE_LEN, "%s/%d/%s",
            HKS_ECE_ROOT_PATH, storeUserId.int32Param, HKS_STORE_SERVICE_PATH);
    } else if (storageLevel.uint32Param == HKS_AUTH_STORAGE_LEVEL_CE) {
        offset = sprintf_s(mainRootPath, HKS_MAX_DIRENT_FILE_LEN, "%s/%d/%s",
            HKS_CE_ROOT_PATH, storeUserId.int32Param, HKS_STORE_SERVICE_PATH);
    } else if (storageLevel.uint32Param == HKS_AUTH_STORAGE_LEVEL_DE) {
        offset = sprintf_s(mainRootPath, HKS_MAX_DIRENT_FILE_LEN, "%s/%d",
            HKS_KEY_STORE_PATH, storeUserId.int32Param);
    } else {
        HKS_LOG_E("invalid tag storage level!");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    if (offset <= 0) {
        HKS_LOG_E("get main root path failed!");
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }
    ret = MakeDirIfNotExist(mainRootPath);
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_NO_PERMISSION)

    ret = MakeSubPath(mainRootPath, userProcess, workPath, HKS_MAX_DIRENT_FILE_LEN);
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_INTERNAL_ERROR)

    ret = MakeDirIfNotExist(workPath);
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_ERROR_NO_PERMISSION)

    ret = GetFullPath(mainRootPath, userProcess, storageName, fileInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get full path failed, ret = %" LOG_PUBLIC "d.", ret)

#ifdef SUPPORT_STORAGE_BACKUP
    ret = GetStoreBakPath(processInfo, storageName, &storeUserId, fileInfo, userProcess);
#endif

    return ret;
}
#endif

#ifdef L2_STANDARD
static int32_t GetStorePlainPathByStorageType(const struct HksProcessInfo *info,
    const struct HksStoreMaterial *material, struct HksStoreFileInfo *fileInfo, bool supportRootKey)
{
    if (material->storageType == HKS_STORAGE_TYPE_KEY) {
        return GetStorePlainPath(info, HKS_KEY_STORE_KEY_PATH, material, fileInfo);
    }
    if (material->storageType == HKS_STORAGE_TYPE_CERTCHAIN) {
        return GetStorePlainPath(info, HKS_KEY_STORE_CERTCHAIN_PATH, material, fileInfo);
    }
    if (material->storageType == HKS_STORAGE_TYPE_ROOT_KEY) {
        if (supportRootKey) {
            return GetStorePlainPath(info, HKS_KEY_STORE_ROOT_KEY_PATH, material, fileInfo);
        } else {
            return HKS_ERROR_NOT_SUPPORTED;
        }
    }
    return HKS_ERROR_NOT_SUPPORTED;
}
#endif

static int32_t GetStorePath(const struct HksProcessInfo *info, const struct HksStoreMaterial *material,
    struct HksStoreFileInfo *fileInfo, bool isPlainPath, bool supportRootKey)
{
    int32_t ret = HKS_ERROR_NOT_SUPPORTED;
    if (!isPlainPath) {
        return GetStoreOldDePathByStorageType(info, material, fileInfo, supportRootKey);
#ifdef L2_STANDARD
    } else {
        return GetStorePlainPathByStorageType(info, material, fileInfo, supportRootKey);
#endif
    }
    return ret;
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
            HKS_LOG_I("generate key or certchain, storage path: %" LOG_PUBLIC "s, key alias: %" LOG_PUBLIC "s",
                path, outKeyAlias);
            break;
        case KEY_OPERATION_GET:
            HKS_LOG_I("use key, storage path: %" LOG_PUBLIC "s, key alias: %" LOG_PUBLIC "s", path, outKeyAlias);
            break;
        case KEY_OPERATION_DELETE:
            HKS_LOG_I("delete key or certchain, storage path: %" LOG_PUBLIC "s, key alias: %" LOG_PUBLIC "s",
                path, outKeyAlias);
            break;
        default:
            ret = HKS_ERROR_INVALID_ARGUMENT;
    }

    HKS_FREE(outKeyAlias);
    return ret;
}

static int32_t IsPlainPath(const struct HksStoreMaterial *material, bool *isPlainPath)
{
#ifdef L2_STANDARD
    struct HksParam *storageLevel = NULL;
    int32_t ret = HksGetParam(material->paramSet, HKS_TAG_AUTH_STORAGE_LEVEL, &storageLevel);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_INVALID_ARGUMENT, "get storage level fail")

    if (storageLevel->uint32Param == HKS_AUTH_STORAGE_LEVEL_DE) {
        *isPlainPath = false;
    }
    return HKS_SUCCESS;
#else
    (void)material;
    *isPlainPath = false;
    return HKS_SUCCESS;
#endif
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

#ifdef HKS_ENABLE_EVENT_DELETE
int32_t ConstructUserIdPath(const char *userId, char *userIdPath, uint32_t pathLen)
{
    if (strncpy_s(userIdPath, pathLen, HKS_KEY_STORE_PATH, strlen(HKS_KEY_STORE_PATH)) != EOK) {
        HKS_LOG_E("copy key store path failed.");
        return HKS_ERROR_INTERNAL_ERROR;
    }

    if (strncat_s(userIdPath, pathLen, "/", strlen("/")) != EOK) {
        HKS_LOG_E("concatenate character / failed.");
        return HKS_ERROR_INTERNAL_ERROR;
    }

    if (strncat_s(userIdPath, pathLen, userId, strlen(userId)) != EOK) {
        HKS_LOG_E("concatenate userId failed.");
        return HKS_ERROR_INTERNAL_ERROR;
    }

    if (strncat_s(userIdPath, pathLen, "\0", strlen("\0")) != EOK) {
        HKS_LOG_E("concatenate character 0 at the end failed.");
        return HKS_ERROR_INTERNAL_ERROR;
    }

    return HKS_SUCCESS;
}

int32_t ConstructUidPath(const char *userId, const char *uid, char *uidPath, uint32_t pathLen)
{
    if (strncpy_s(uidPath, pathLen, HKS_KEY_STORE_PATH, strlen(HKS_KEY_STORE_PATH)) != EOK) {
        HKS_LOG_E("copy key store path failed.");
        return HKS_ERROR_INTERNAL_ERROR;
    }

    if (strncat_s(uidPath, pathLen, "/", strlen("/")) != EOK) {
        HKS_LOG_E("concatenate character / 1 failed.");
        return HKS_ERROR_INTERNAL_ERROR;
    }

    if (strncat_s(uidPath, pathLen, userId, strlen(userId)) != EOK) {
        HKS_LOG_E("concatenate userId failed.");
        return HKS_ERROR_INTERNAL_ERROR;
    }

    if (strncat_s(uidPath, pathLen, "/", strlen("/")) != EOK) {
        HKS_LOG_E("concatenate character / 2 failed.");
        return HKS_ERROR_INTERNAL_ERROR;
    }

    if (strncat_s(uidPath, pathLen, uid, strlen(uid)) != EOK) {
        HKS_LOG_E("concatenate uid failed.");
        return HKS_ERROR_INTERNAL_ERROR;
    }

    if (strncat_s(uidPath, pathLen, "\0", strlen("\0")) != EOK) {
        HKS_LOG_E("concatenate character 0 at the end failed.");
        return HKS_ERROR_INTERNAL_ERROR;
    }

    return HKS_SUCCESS;
}

bool HksIsUserIdRoot(const struct HksProcessInfo *processInfo)
{
    if (processInfo->userIdInt == 0) {
        HKS_LOG_I("is root user id");
        return true;
    }
    return false;
}
#endif

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

int32_t GetFileInfo(const struct HksProcessInfo *processInfo, const struct HksStoreMaterial *material,
    struct HksStoreFileInfo *fileInfo, bool supportRootKey)
{
    int32_t ret = FileInfoInit(fileInfo);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "hks file info init failed, ret = %" LOG_PUBLIC "d.", ret)

    char *name = (char *)HksMalloc(HKS_MAX_FILE_NAME_LEN);
    HKS_IF_NULL_RETURN(name, HKS_ERROR_MALLOC_FAIL)

    (void)memset_s(name, HKS_MAX_FILE_NAME_LEN, 0, HKS_MAX_FILE_NAME_LEN);

    bool isPlainPath = true;
    do {
        ret = IsPlainPath(material, &isPlainPath);
        HKS_IF_NOT_SUCC_BREAK(ret);
#ifdef HKS_ENABLE_LITE_HAP
        if (CheckIsLiteHap(&processInfo->processName)) {
            if (memcpy_s(name, HKS_MAX_FILE_NAME_LEN, processInfo->processName.data,
                processInfo->processName.size) != EOK) {
                HKS_IF_NOT_SUCC_LOGE_BREAK(HKS_ERROR_BUFFER_TOO_SMALL, "construct name fail, name buffer is too small.")
            }
        } else {
#endif
            if (isPlainPath) {
                ret = ConstructPlainName(&processInfo->processName, name, HKS_MAX_FILE_NAME_LEN);
            } else {
                ret = ConstructName(&processInfo->processName, name, HKS_MAX_FILE_NAME_LEN);
            }
            HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "construct name failed, ret = %" LOG_PUBLIC "d.", ret)
#ifdef HKS_ENABLE_LITE_HAP
        }
#endif
    } while (0);
    if (ret != HKS_SUCCESS) {
        HKS_FREE(name);
        return ret;
    }
    struct HksProcessInfo info;
    SaveProcessInfo((uint8_t *)name, strlen(name), processInfo, &info);

    ret = GetStorePath(&info, material, fileInfo, isPlainPath, supportRootKey);
    HKS_FREE(name);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "get store path failed, ret = %" LOG_PUBLIC "d.", ret)

    if (supportRootKey) {
        ret = ConstructName(material->keyAlias, fileInfo->mainPath.fileName, fileInfo->mainPath.size);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "construct name failed, ret = %" LOG_PUBLIC "d.", ret)

#ifdef SUPPORT_STORAGE_BACKUP
        ret = GetBakFileName(fileInfo->mainPath.fileName, fileInfo->bakPath.fileName, fileInfo->bakPath.size);
        HKS_IF_NOT_SUCC_LOGE(ret, "get backup file name failed, ret = %" LOG_PUBLIC "d.", ret)
#endif
    }

    return ret;
}

#endif /* _CUT_AUTHENTICATE_ */
