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

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "securec.h"
#define REQUIRED_KEY_NOT_AVAILABLE 126

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

static int32_t IsFileExist(const char *fileName)
{
    if (access(fileName, F_OK) != 0) {
        return HKS_ERROR_NOT_EXIST;
    }

    return HKS_SUCCESS;
}

static int32_t FileRead(const char *fileName, uint32_t offset, struct HksBlob *blob, uint32_t *size)
{
    (void)offset;
    HKS_IF_NOT_SUCC_RETURN(IsFileExist(fileName), HKS_ERROR_NOT_EXIST)

    if (strstr(fileName, "../") != NULL) {
        HKS_LOG_E("invalid filePath, path %" LOG_PUBLIC "s", fileName);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    char filePath[PATH_MAX + 1] = {0};
    if (realpath(fileName, filePath) == NULL) {
        HKS_LOG_E("invalid filePath, path %" LOG_PUBLIC "s", fileName);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    FILE *fp = fopen(filePath, "rb");
    if (fp ==  NULL) {
        if (errno == REQUIRED_KEY_NOT_AVAILABLE) {
            HKS_LOG_E("Check Permission failed!");
            return HKS_ERROR_NO_PERMISSION;
        }
        HKS_LOG_E("open file fail, errno = 0x%" LOG_PUBLIC "x", errno);
        return HKS_ERROR_OPEN_FILE_FAIL;
    }

    uint32_t len = fread(blob->data, 1, blob->size, fp);
    if (fclose(fp) < 0) {
        HKS_LOG_E("failed to close file, errno = 0x%" LOG_PUBLIC "x", errno);
        return HKS_ERROR_CLOSE_FILE_FAIL;
    }
    *size = len;
    return HKS_SUCCESS;
}

static uint32_t FileSize(const char *fileName)
{
    HKS_IF_NOT_SUCC_RETURN(IsFileExist(fileName), 0)

    struct stat fileStat;
    (void)memset_s(&fileStat, sizeof(fileStat), 0, sizeof(fileStat));
    if (stat(fileName, &fileStat) != 0) {
        HKS_LOG_E("file stat fail, errno = 0x%" LOG_PUBLIC "x", errno);
        return 0;
    }

    return fileStat.st_size;
}

static int32_t GetRealPath(const char *fileName, char *filePath)
{
    if (memcpy_s(filePath, PATH_MAX, fileName, strlen(fileName)) != EOK) {
        return HKS_ERROR_INSUFFICIENT_MEMORY;
    }

    if (strstr(filePath, "../") != NULL) {
        HKS_LOG_E("invalid filePath!");
        return HKS_ERROR_INVALID_KEY_FILE;
    }
    return HKS_SUCCESS;
}

static int32_t FileWrite(const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
    (void)offset;
    char filePath[PATH_MAX + 1] = {0};
    int32_t ret = GetRealPath(fileName, filePath);
    HKS_IF_NOT_SUCC_LOGE(ret, "get real path faild")

    (void)realpath(fileName, filePath);

    /* caller function ensures that the folder exists */
    FILE *fp = fopen(filePath, "wb+");
    if (fp ==  NULL) {
        if (errno == REQUIRED_KEY_NOT_AVAILABLE) {
            HKS_LOG_E("Check Permission failed!");
            return HKS_ERROR_NO_PERMISSION;
        }
        HKS_LOG_E("open file fail, errno = 0x%" LOG_PUBLIC "x", errno);
        return HKS_ERROR_OPEN_FILE_FAIL;
    }

    if (chmod(filePath, S_IRUSR | S_IWUSR) < 0) {
        HKS_LOG_E("chmod file fail, errno = 0x%" LOG_PUBLIC "x", errno);
        fclose(fp);
        return HKS_ERROR_OPEN_FILE_FAIL;
    }

    uint32_t size = fwrite(buf, 1, len, fp);
    if (size != len) {
        HKS_LOG_E("write file size fail, errno = 0x%" LOG_PUBLIC "x", errno);
        fclose(fp);
        return HKS_ERROR_WRITE_FILE_FAIL;
    }

    if (fflush(fp) < 0) {
        HKS_LOG_E("fflush file fail, errno = 0x%" LOG_PUBLIC "x", errno);
        fclose(fp);
        return HKS_ERROR_WRITE_FILE_FAIL;
    }

    int fd = fileno(fp);
    if (fd < 0) {
        HKS_LOG_E("fileno fail, errno = 0x%" LOG_PUBLIC "x", errno);
        fclose(fp);
        return HKS_ERROR_WRITE_FILE_FAIL;
    }

    if (fsync(fd) < 0) {
        HKS_LOG_E("sync file fail, errno = 0x%" LOG_PUBLIC "x", errno);
        fclose(fp);
        return HKS_ERROR_WRITE_FILE_FAIL;
    }

    if (fclose(fp) < 0) {
        HKS_LOG_E("failed to close file, errno = 0x%" LOG_PUBLIC "x", errno);
        return HKS_ERROR_CLOSE_FILE_FAIL;
    }

    return HKS_SUCCESS;
}

static int32_t FileRemove(const char *fileName)
{
    int32_t ret = IsFileExist(fileName);
    HKS_IF_NOT_SUCC_RETURN(ret, HKS_SUCCESS) /* if file not exist, return ok */

    struct stat tmp;
    if (stat(fileName, &tmp) != 0) {
        return HKS_ERROR_INTERNAL_ERROR;
    }

    if (S_ISDIR(tmp.st_mode)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if ((unlink(fileName) != 0) && (errno != ENOENT)) {
        HKS_LOG_E("failed to remove file: errno = 0x%" LOG_PUBLIC "x", errno);
        return HKS_ERROR_REMOVE_FILE_FAIL;
    }

    return HKS_SUCCESS;
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

int32_t HksIsDirExist(const char *path)
{
    HKS_IF_NULL_RETURN(path, HKS_ERROR_NULL_POINTER)
    return IsFileExist(path);
}

int32_t HksMakeDir(const char *path)
{
    int result = mkdir(path, S_IRWXU);
    if (result == 0) {
        return HKS_SUCCESS;
    } else {
        switch (errno) {
            case EEXIST:
                return HKS_ERROR_ALREADY_EXISTS;
            default:
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
            HKS_IF_NOT_SUCC_LOGE(ret, "remove file failed when remove dir files, ret = %" LOG_PUBLIC "d.", ret)
        }
        dire = readdir(dir);
    }

    closedir(dir);
    return HKS_SUCCESS;
}

static int32_t HksDeletDirPartTwo(const char *path)
{
    int32_t ret;
    char deletePath[HKS_MAX_FILE_NAME_LEN] = {0};
    DIR *dir = opendir(path);
    HKS_IF_NULL_LOGE_RETURN(dir, HKS_ERROR_OPEN_FILE_FAIL, "open dir failed")
    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        if (strncpy_s(deletePath, sizeof(deletePath), path, strlen(path)) != EOK) {
            closedir(dir);
            return HKS_ERROR_INTERNAL_ERROR;
        }

        if (deletePath[strlen(deletePath) - 1] != '/') {
            if (strncat_s(deletePath, sizeof(deletePath), "/", strlen("/")) != EOK) {
                closedir(dir);
                return HKS_ERROR_INTERNAL_ERROR;
            }
        }

        if (strncat_s(deletePath, sizeof(deletePath), dire->d_name, strlen(dire->d_name)) != EOK) {
            closedir(dir);
            return HKS_ERROR_INTERNAL_ERROR;
        }

        if ((strcmp("..", dire->d_name) != 0) && (strcmp(".", dire->d_name) != 0)) {
            (void)remove(deletePath);
        }
        dire = readdir(dir);
    }
    closedir(dir);
    ret = remove(path);
    return ret;
}

static int32_t HksDeletDirPartOne(const char *path)
{
    int32_t ret;
    char deletePath[HKS_MAX_FILE_NAME_LEN] = {0};
    DIR *dir = opendir(path);
    HKS_IF_NULL_LOGE_RETURN(dir, HKS_ERROR_OPEN_FILE_FAIL, "open dir failed")
    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        if (strncpy_s(deletePath, sizeof(deletePath), path, strlen(path)) != EOK) {
            closedir(dir);
            return HKS_ERROR_INTERNAL_ERROR;
        }

        if (deletePath[strlen(deletePath) - 1] != '/') {
            if (strncat_s(deletePath, sizeof(deletePath), "/", strlen("/")) != EOK) {
                closedir(dir);
                return HKS_ERROR_INTERNAL_ERROR;
            }
        }

        if (strncat_s(deletePath, sizeof(deletePath), dire->d_name, strlen(dire->d_name)) != EOK) {
            closedir(dir);
            return HKS_ERROR_INTERNAL_ERROR;
        }

        if (dire->d_type == DT_DIR && (strcmp("..", dire->d_name) != 0) && (strcmp(".", dire->d_name) != 0)) {
            HksDeletDirPartTwo(deletePath);
        } else if (dire->d_type != DT_DIR) {
            (void)remove(deletePath);
        }
        dire = readdir(dir);
    }
    closedir(dir);
    ret = remove(path);
    return ret;
}

int32_t HksDeleteDir(const char *path)
{
    int32_t ret;
    char deletePath[HKS_MAX_FILE_NAME_LEN] = { 0 };

    DIR *dir = opendir(path);
    HKS_IF_NULL_LOGE_RETURN(dir, HKS_ERROR_OPEN_FILE_FAIL, "open dir failed")
    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        if (strncpy_s(deletePath, sizeof(deletePath), path, strlen(path)) != EOK) {
            closedir(dir);
            return HKS_ERROR_INTERNAL_ERROR;
        }

        if (deletePath[strlen(deletePath) - 1] != '/') {
            if (strncat_s(deletePath, sizeof(deletePath), "/", strlen("/")) != EOK) {
                closedir(dir);
                return HKS_ERROR_INTERNAL_ERROR;
            }
        }

        if (strncat_s(deletePath, sizeof(deletePath), dire->d_name, strlen(dire->d_name)) != EOK) {
            closedir(dir);
            return HKS_ERROR_INTERNAL_ERROR;
        }

        if (dire->d_type == DT_DIR && (strcmp("..", dire->d_name) != 0) && (strcmp(".", dire->d_name) != 0)) {
            HksDeletDirPartOne(deletePath);
        } else if (dire->d_type != DT_DIR) {
            (void)remove(deletePath);
        }
        dire = readdir(dir);
    }
    closedir(dir);
    ret = remove(path);
    return ret;
}

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

int32_t HksGetFileName(const char *path, const char *fileName, char *fullFileName, uint32_t fullFileNameLen)
{
    return GetFileName(path, fileName, fullFileName, fullFileNameLen);
}