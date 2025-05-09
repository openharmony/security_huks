/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_file_operator.h"

#ifndef _STORAGE_LITE_
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* use product definitions temporarily */
#define DEFAULT_FILE_PERMISSION 0700
#else

#include <utils_file.h>

#endif /* _STORAGE_LITE_ */

#include "securec.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"

#ifdef HUKS_LOG_MINI_EXT_ENABLED
#include "log.h"
#endif


#ifndef _CUT_AUTHENTICATE_
static int32_t GetFileName(const char *path, const char *fileName, char *fullFileName, uint32_t fullFileNameLen)
{
    if (path != NULL) {
        if (strncpy_s(fullFileName, fullFileNameLen, path, strlen(path)) != EOK) {
            return HKS_ERROR_INTERNAL_ERROR;
        }

        if (path[strlen(path) - 1] != '/') {
            if (strncat_s(fullFileName, fullFileNameLen, "/", strlen("/")) != EOK) {
                return HKS_ERROR_INTERNAL_ERROR;
            }
        }

        if (strncat_s(fullFileName, fullFileNameLen, fileName, strlen(fileName)) != EOK) {
            return HKS_ERROR_INTERNAL_ERROR;
        }
    } else {
        if (strncpy_s(fullFileName, fullFileNameLen, fileName, strlen(fileName)) != EOK) {
            return HKS_ERROR_INTERNAL_ERROR;
        }
    }

    return HKS_SUCCESS;
}

static int32_t GetFullFileName(const char *path, const char *fileName, char **fullFileName)
{
    uint32_t nameLen = HKS_MAX_FILE_NAME_LEN;
    char *tmpFileName = (char *)HksMalloc(nameLen);
    HKS_IF_NULL_RETURN(tmpFileName, HKS_ERROR_MALLOC_FAIL)
    (void)memset_s(tmpFileName, nameLen, 0, nameLen);

    int32_t ret = GetFileName(path, fileName, tmpFileName, nameLen);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("get full fileName failed");
        HKS_FREE(tmpFileName);
        return ret;
    }

    *fullFileName = tmpFileName;
    return HKS_SUCCESS;
}

#ifndef _STORAGE_LITE_
static int32_t IsFileExist(const char *fileName)
{
    struct stat fileStat;
    int32_t ret = stat(fileName, &fileStat);
    if (ret == -1) {
        if (errno == ENOENT) {
            return HKS_ERROR_NOT_EXIST;
        } else {
            HKS_LOG_E("file stat failed, errno = 0x%" LOG_PUBLIC "x", errno);
            return HKS_ERROR_OPEN_FILE_FAIL;
        }
    }

    return HKS_SUCCESS;
}

static int32_t FileRead(const char *fileName, uint32_t offset, struct HksBlob *blob, uint32_t *size)
{
    (void)offset;
    int32_t fd = open(fileName, O_RDONLY);
    if (fd < 0) {
        HKS_LOG_E("failed to open file, errno = 0x%" LOG_PUBLIC "x", errno);
#ifdef HUKS_LOG_MINI_EXT_ENABLED
        HILOG_ERROR(HILOG_MODULE_SCY, "failed to open file, errno = 0x%{public}X", errno);
#endif
        return HKS_ERROR_OPEN_FILE_FAIL;
    }

    int32_t len = read(fd, blob->data, blob->size);
    close(fd);
    if (len < 0) {
        HKS_LOG_E("failed to read file, errno = 0x%" LOG_PUBLIC "x", errno);
#ifdef HUKS_LOG_MINI_EXT_ENABLED
        HILOG_ERROR(HILOG_MODULE_SCY, "failed to read file, errno = 0x%{public}X", errno);
#endif
        return HKS_ERROR_READ_FILE_FAIL;
    }
    *size = (uint32_t)len;
    return HKS_SUCCESS;
}

static uint32_t FileSize(const char *fileName)
{
    struct stat fileStat;
    (void)memset_s(&fileStat, sizeof(fileStat), 0, sizeof(fileStat));
    if (stat(fileName, &fileStat) != 0) {
        HKS_LOG_E("file stat failed, errno = 0x%" LOG_PUBLIC "x", errno);
        return 0;
    }

    return (uint32_t)fileStat.st_size;
}

static int32_t FileWrite(const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
    (void)offset;
    int32_t fd = open(fileName, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        HKS_LOG_E("open file failed, errno = 0x%" LOG_PUBLIC "x", errno);
#ifdef HUKS_LOG_MINI_EXT_ENABLED
        HILOG_ERROR(HILOG_MODULE_SCY, "open file failed, errno = 0x%{public}X", errno);
#endif
        return HKS_ERROR_OPEN_FILE_FAIL;
    }

    int32_t size = write(fd, buf, len);
    if (size < 0) {
        HKS_LOG_E("write file size failed, errno = 0x%" LOG_PUBLIC "x", errno);
#ifdef HUKS_LOG_MINI_EXT_ENABLED
        HILOG_ERROR(HILOG_MODULE_SCY, "write file size failed, errno = 0x%{public}X", errno);
#endif
        close(fd);
        return HKS_ERROR_WRITE_FILE_FAIL;
    }

    fsync(fd);
    close(fd);
    return HKS_SUCCESS;
}

static int32_t FileRemove(const char *fileName)
{
    struct stat fileStat;
    int32_t ret = stat(fileName, &fileStat);
    if (ret == -1) {
        if (errno == ENOENT) {
            return HKS_SUCCESS; /* if file not exist, return ok */
        } else {
            HKS_LOG_E("file stat failed, errno = 0x%" LOG_PUBLIC "x", errno);
            return HKS_ERROR_OPEN_FILE_FAIL;
        }
    }

    if (S_ISDIR(fileStat.st_mode)) {
        return HKS_ERROR_INVALID_ARGUMENT; /* FileRemove func only care about files. */
    }

    if (unlink(fileName) != 0) {
        HKS_LOG_E("remove file failed, errno = 0x%" LOG_PUBLIC "x", errno);
        return HKS_ERROR_REMOVE_FILE_FAIL;
    }

    return HKS_SUCCESS;
}

int32_t HksIsDirExist(const char *path)
{
    HKS_IF_NULL_RETURN(path, HKS_ERROR_NULL_POINTER)
    return IsFileExist(path);
}

int32_t HksMakeDir(const char *path)
{
    int result = mkdir(path, DEFAULT_FILE_PERMISSION);
    if (result == 0) {
        return HKS_SUCCESS;
    } else {
        switch (errno) {
            case EEXIST:
                return HKS_ERROR_ALREADY_EXISTS;
            default:
                HKS_LOG_E("mkdir failed, errno = 0x%" LOG_PUBLIC "x", errno);
#ifdef HUKS_LOG_MINI_EXT_ENABLED
                HILOG_ERROR(HILOG_MODULE_SCY, "mkdir failed, errno = 0x%{public}X", errno);
#endif
                return HKS_ERROR_MAKE_DIR_FAIL;
        }
    }
}

void *HksOpenDir(const char *path)
{
    return (void *)opendir(path);
}

int32_t HksCloseDir(void *dirp)
{
    return closedir((DIR *)dirp);
}

int32_t HksGetDirFile(void *dirp, struct HksFileDirentInfo *direntInfo)
{
    DIR *dir = (DIR *)dirp;
    struct dirent *dire = readdir(dir);

    while (dire != NULL) {
        if (dire->d_type != DT_REG) { /* only care about files. */
            dire = readdir(dir);
            continue;
        }

        uint32_t len = strlen(dire->d_name);
        if (memcpy_s(direntInfo->fileName, sizeof(direntInfo->fileName) - 1, dire->d_name, len) != EOK) {
            return HKS_ERROR_INSUFFICIENT_MEMORY;
        }
        direntInfo->fileName[len] = '\0';
        return HKS_SUCCESS;
    }

    return HKS_ERROR_NOT_EXIST;
}

int32_t HksRemoveDir(const char *dirPath)
{
    struct stat fileStat;
    int32_t ret = stat(dirPath, &fileStat);
    if (ret != 0) {
        HKS_LOG_E("file stat failed");
        return HKS_FAILURE;
    }

    if (!S_ISDIR(fileStat.st_mode)) {
        HKS_LOG_E("path is not dir");
        return HKS_FAILURE;
    }

    DIR *dir = opendir(dirPath);
    HKS_IF_NULL_LOGE_RETURN(dir, HKS_ERROR_OPEN_FILE_FAIL, "open dir failed")

    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        if (dire->d_type == DT_REG) { /* only care about files. */
            ret = HksFileRemove(dirPath, dire->d_name);
            /* Continue to delete remaining files */
            HKS_IF_NOT_SUCC_LOGE(ret, "remove file failed when remove dir files, ret = %" LOG_PUBLIC "d.", ret)
        }
        dire = readdir(dir);
    }

    closedir(dir);
    return HKS_SUCCESS;
}
#else
static int32_t IsFileExist(const char *fileName)
{
    unsigned int fileSize;
    int32_t ret = UtilsFileStat(fileName, &fileSize);
    if (ret < 0) {
        return HKS_ERROR_NOT_EXIST;
    }
    return HKS_SUCCESS;
}

static int32_t FileRead(const char *fileName, uint32_t offset, struct HksBlob *blob, uint32_t *size)
{
    /* now offset is 0, but we maybe extend hi1131 file interfaces in the future */
    if (offset != 0) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    unsigned int fileSize;
    int32_t ret = UtilsFileStat(fileName, &fileSize);
    if (ret < 0) {
        HKS_LOG_E("stat file failed, errno = 0x%" LOG_PUBLIC "x", ret);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (blob->size > fileSize) {
        HKS_LOG_E("read data over file size!\n, file size = %" LOG_PUBLIC "d\n, buf len = %" LOG_PUBLIC "d\n",
            fileSize, blob->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    int fd = UtilsFileOpen(fileName, O_RDONLY_FS, 0);
    if (fd < 0) {
        HKS_LOG_E("failed to open file, errno = 0x%" LOG_PUBLIC "x", fd);
        return HKS_ERROR_OPEN_FILE_FAIL;
    }

    ret = UtilsFileRead(fd, (char *)blob->data, blob->size);
    UtilsFileClose(fd);
    if (ret < 0) {
        HKS_LOG_E("failed to read file, errno = 0x%" LOG_PUBLIC "x", ret);
        return HKS_ERROR_READ_FILE_FAIL;
    }
    *size = blob->size;
    return HKS_SUCCESS;
}

static int32_t FileWrite(const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
    /* now offset is 0, but we may extend hi1131 file interfaces */
    if (offset != 0) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    int fd = UtilsFileOpen(fileName, O_CREAT_FS | O_TRUNC_FS | O_RDWR_FS, 0);
    if (fd < 0) {
        HKS_LOG_E("failed to open key file, errno = 0x%" LOG_PUBLIC "x\n", fd);
        return HKS_ERROR_OPEN_FILE_FAIL;
    }

    int32_t ret = UtilsFileWrite(fd, (const char*)buf, len);
    (void)UtilsFileClose(fd);
    if (ret < 0) {
        HKS_LOG_E("failed to write key file, errno = 0x%" LOG_PUBLIC "x\n", ret);
        return HKS_ERROR_WRITE_FILE_FAIL;
    }

    return HKS_SUCCESS;
}

static uint32_t FileSize(const char *fileName)
{
    unsigned int fileSize;
    int32_t ret = UtilsFileStat(fileName, &fileSize);
    if (ret < 0) {
        HKS_LOG_E("stat file failed, errno = 0x%" LOG_PUBLIC "x", ret);
        return 0;
    }
    return fileSize;
}

static int32_t FileRemove(const char *fileName)
{
    int32_t ret = UtilsFileDelete(fileName);
    if (ret < 0) {
        HKS_LOG_E("remove file failed");
        return HKS_ERROR_REMOVE_FILE_FAIL;
    }
    return HKS_SUCCESS;
}

#endif

int32_t HksFileRead(const char *path, const char *fileName, uint32_t offset, struct HksBlob *blob, uint32_t *size)
{
    if ((fileName == NULL) || (blob == NULL) || (blob->data == NULL) || (blob->size == 0) || (size == NULL)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = FileRead(fullFileName, offset, blob, size);
    HKS_FREE(fullFileName);
    return ret;
}

int32_t HksFileWrite(const char *path, const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
    if ((fileName == NULL) || (buf == NULL) || (len == 0)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = FileWrite(fullFileName, offset, buf, len);
    HKS_FREE(fullFileName);
    return ret;
}

uint32_t HksFileSize(const char *path, const char *fileName)
{
    HKS_IF_NULL_RETURN(fileName, 0)

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    HKS_IF_NOT_SUCC_RETURN(ret, 0)

    uint32_t size = FileSize(fullFileName);
    HKS_FREE(fullFileName);
    return size;
}

int32_t HksIsFileExist(const char *path, const char *fileName)
{
    HKS_IF_NULL_RETURN(fileName, HKS_ERROR_NULL_POINTER)

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = IsFileExist(fullFileName);
    HKS_FREE(fullFileName);
    return ret;
}

int32_t HksFileRemove(const char *path, const char *fileName)
{
    HKS_IF_NULL_RETURN(fileName, HKS_ERROR_INVALID_ARGUMENT)

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    HKS_IF_NOT_SUCC_RETURN(ret, ret)

    ret = FileRemove(fullFileName);
    HKS_FREE(fullFileName);
    return ret;
}

int32_t HksGetFileName(const char *path, const char *fileName, char *fullFileName, uint32_t fullFileNameLen)
{
    return GetFileName(path, fileName, fullFileName, fullFileNameLen);
}

#endif /* _CUT_AUTHENTICATE_ */
