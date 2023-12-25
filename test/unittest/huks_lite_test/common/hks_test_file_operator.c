/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef __LITEOS_M__

#include <fcntl.h>

/* use product definitions temporarily */
#define DEFAULT_FILE_PERMISSION 0666
#else

#include <utils_file.h>

#endif /* _STORAGE_LITE_ */

static int32_t GetFullFileName(const char *path, const char *fileName, char **fullFileName)
{
    uint32_t nameLen = HKS_MAX_FILE_NAME_LEN;
    char *tmpFileName = (char *)HksTestMalloc(nameLen);
    if (tmpFileName == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(tmpFileName, nameLen, 0, nameLen);

    int32_t ret = GetFileName(path, fileName, tmpFileName, nameLen);
    if (ret != HKS_SUCCESS) {
        HKS_TEST_LOG_E("get full fileName failed");
        HksTestFree(tmpFileName);
        return ret;
    }

    *fullFileName = tmpFileName;
    return HKS_SUCCESS;
}

#ifndef __LITEOS_M__

int32_t HksTestIsFileExist(const char *path, const char *fileName)
{
    if (fileName == NULL) {
        return HKS_ERROR_NULL_POINTER;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = IsFileExist(fullFileName);
    HksTestFree(fullFileName);
    return ret;
}
#else
static int32_t FileRead(const char *fileName, uint32_t offset, struct HksBlob *blob, uint32_t *size)
{
    /* now offset is 0, but we maybe extend hi1131 file interfaces in the future */
    if (offset != 0) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    unsigned int fileSize;
    int32_t ret = UtilsFileStat(fileName, &fileSize);
    if (ret < 0) {
        HKS_TEST_LOG_E("stat file failed, errno = 0x%x", ret);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    if (blob->size > fileSize) {
        HKS_TEST_LOG_E("read data over file size!\n, file size = %d\n, buf len = %d\n", fileSize, blob->size);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    int fd = UtilsFileOpen(fileName, O_RDONLY_FS, 0);
    if (fd < 0) {
        HKS_LOG_E("open file fail, errno = 0x%" LOG_PUBLIC "x", fd);
        return HKS_ERROR_OPEN_FILE_FAIL;
    }
    ret = UtilsFileRead(fd, blob->data, blob->size);
    UtilsFileClose(fd);
    if (ret < 0) {
        HKS_TEST_LOG_E("failed to read file, errno = 0x%x", ret);
        return HKS_ERROR_READ_FILE_FAIL;
    }
    *size = blob->size;
    return HKS_SUCCESS;
}

static int32_t FileWrite(const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
    /* now offset is 0, but we maybe extend hi1131 file interfaces in the future */
    if (offset != 0) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    int fd = UtilsFileOpen(fileName, O_CREAT_FS | O_TRUNC_FS | O_RDWR_FS, 0);
    if (fd < 0) {
        HKS_TEST_LOG_E("failed to open key file, errno = 0x%x\n", fd);
        return HKS_ERROR_OPEN_FILE_FAIL;
    }

    int32_t ret = UtilsFileWrite(fd, buf, len);
    if (ret < 0) {
        HKS_TEST_LOG_E("failed to write key file, errno = 0x%x\n", ret);
        ret = HKS_ERROR_WRITE_FILE_FAIL;
    }

    ret = UtilsFileClose(fd);
    if (ret < 0) {
        HKS_TEST_LOG_E("failed to close file, errno = 0x%x\n", ret);
        ret = HKS_ERROR_CLOSE_FILE_FAIL;
    }

    return ret;
}

static uint32_t FileSize(const char *fileName)
{
    unsigned int fileSize;
    int32_t ret = UtilsFileStat(fileName, &fileSize);
    if (ret < 0) {
        HKS_TEST_LOG_E("stat file failed, errno = 0x%x", ret);
        return 0;
    }
    return fileSize;
}

int32_t HksTestFileRemove(const char *path, const char *fileName)
{
    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != HKS_SUCCESS) {
        return 0;
    }

    return UtilsFileDelete(fullFileName);
}

#endif
int32_t HksTestFileRead(const char *path, const char *fileName, uint32_t offset, struct HksBlob *blob, uint32_t *size)
{
    if ((fileName == NULL) || (blob == NULL) || (blob->data == NULL) || (blob->size == 0) || (size == NULL)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = FileRead(fullFileName, offset, blob, size);
    HksTestFree(fullFileName);
    return ret;
}

int32_t HksTestFileWrite(const char *path, const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
    if ((fileName == NULL) || (buf == NULL) || (len == 0)) {
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != HKS_SUCCESS) {
        return ret;
    }

    ret = FileWrite(fullFileName, offset, buf, len);
    HksTestFree(fullFileName);
    return ret;
}

uint32_t HksTestFileSize(const char *path, const char *fileName)
{
    if (fileName == NULL) {
        return 0;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != HKS_SUCCESS) {
        return 0;
    }

    uint32_t size = FileSize(fullFileName);
    HksTestFree(fullFileName);
    return size;
}
