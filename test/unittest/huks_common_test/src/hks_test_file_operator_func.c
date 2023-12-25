/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_test_file_operator_c.h"


int32_t GetFileName(const char *path, const char *fileName, char *fullFileName, uint32_t fullFileNameLen)
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

int32_t IsFileExist(const char *fileName)
{
    if (access(fileName, F_OK) != 0) {
        return HKS_ERROR_NOT_EXIST;
    }

    return HKS_SUCCESS;
}

int32_t FileRead(const char *fileName, uint32_t offset, struct HksBlob *blob, uint32_t *size)
{
    (void)offset;
    if (IsFileExist(fileName) != HKS_SUCCESS) {
        return HKS_ERROR_NOT_EXIST;
    }

    char filePath[PATH_MAX + 1] = {0};
    (void)realpath(fileName, filePath);
    if (strstr(filePath, "../") != NULL) {
        HKS_TEST_LOG_E("invalid filePath, path %s", filePath);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    FILE *fp = fopen(filePath, "rb");
    if (fp ==  NULL) {
        if (errno == REQUIRED_KEY_NOT_AVAILABLE) {
            HKS_TEST_LOG_E("Check Permission failed!");
            return HKS_ERROR_NO_PERMISSION;
        }
        HKS_TEST_LOG_E("open file fail, errno = 0x%x", errno);
        return HKS_ERROR_OPEN_FILE_FAIL;
    }

    uint32_t len = fread(blob->data, 1, blob->size, fp);
    if (fclose(fp) < 0) {
        HKS_TEST_LOG_E("failed to close file");
        return HKS_ERROR_CLOSE_FILE_FAIL;
    }
    *size = len;
    return HKS_SUCCESS;
}

uint32_t FileSize(const char *fileName)
{
    if (IsFileExist(fileName) != HKS_SUCCESS) {
        return 0;
    }

    struct stat fileStat;
    (void)memset_s(&fileStat, sizeof(fileStat), 0, sizeof(fileStat));
    if (stat(fileName, &fileStat) != 0) {
        HKS_TEST_LOG_E("file stat fail.");
        return 0;
    }

    return fileStat.st_size;
}

int32_t FileWrite(const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
    (void)offset;
    char filePath[PATH_MAX + 1] = {0};
    if (memcpy_s(filePath, sizeof(filePath) - 1, fileName, strlen(fileName)) != EOK) {
        return HKS_ERROR_BAD_STATE;
    }
    (void)realpath(fileName, filePath);
    if (strstr(filePath, "../") != NULL) {
        HKS_TEST_LOG_E("invalid filePath, path %s", filePath);
        return HKS_ERROR_INVALID_KEY_FILE;
    }

    /* caller function ensures that the folder exists */
    FILE *fp = fopen(filePath, "wb+");
    if (fp == NULL) {
        HKS_TEST_LOG_E("open file fail");
        return HKS_ERROR_OPEN_FILE_FAIL;
    }

    if (chmod(filePath, S_IRUSR | S_IWUSR) < 0) {
        HKS_TEST_LOG_E("chmod file fail.");
        fclose(fp);
        return HKS_ERROR_OPEN_FILE_FAIL;
    }

    uint32_t size = fwrite(buf, 1, len, fp);
    if (size != len) {
        HKS_TEST_LOG_E("write file size fail.");
        fclose(fp);
        return HKS_ERROR_WRITE_FILE_FAIL;
    }

    if (fclose(fp) < 0) {
        HKS_TEST_LOG_E("failed to close file");
        return HKS_ERROR_CLOSE_FILE_FAIL;
    }

    return HKS_SUCCESS;
}