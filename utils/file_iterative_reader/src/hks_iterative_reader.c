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

#include "hks_iterative_reader.h"

#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>

#include "hks_file_operator.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_template.h"
#include "hks_type_inner.h"

#define DEFAULT_PATH_LEN 256

#define DEFAULT_FILE_INFO_NUM 64

#define DIR_TYPE 4

static void HksFreeFileInfo(struct HksReadFileInfo *info)
{
    HKS_FREE(info->path);
    HKS_FREE(info->fileName);
}

static void HksFreeFileInfoList(struct HksReadFileInfoList **infos)
{
    if (*infos == NULL) {
        return;
    }
    if ((*infos)->infos != NULL && (*infos)->occu > 0) {
        for (uint32_t i = 0; i < (*infos)->occu; ++i) {
            HksFreeFileInfo(&(*infos)->infos[i]);
        }
    }
    HKS_FREE((*infos)->infos);
    HKS_FREE(*infos);
}

static struct HksReadFileInfoList *HksInitFileInfoList()
{
    struct HksReadFileInfoList *infos;
    do {
        infos = (struct HksReadFileInfoList *)HksMalloc(sizeof(struct HksReadFileInfoList));
        if (infos == NULL) {
            HKS_LOG_E("malloc HksReadFileInfoList failed.");
            break;
        }
        infos->infos = (struct HksReadFileInfo *)HksMalloc(sizeof(struct HksReadFileInfo) * DEFAULT_FILE_INFO_NUM);
        if (infos->infos == NULL) {
            break;
        }
        infos->occu = 0;
        infos->cap = DEFAULT_FILE_INFO_NUM;
        return infos;
    } while (false);
    HksFreeFileInfoList(&infos);
    return NULL;
}

// each time for re-alloc, the capacity of OldFileInfoList will be added with DEFAULT_FILE_INFO_NUM.
static int32_t HksReAllocFileInfoList(struct HksReadFileInfoList *infos)
{
    struct HksReadFileInfo *newInfo =
        (struct HksReadFileInfo *)HksMalloc(sizeof(struct HksReadFileInfo) * (infos->cap + DEFAULT_FILE_INFO_NUM));
    if (newInfo == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(newInfo, (infos->cap + DEFAULT_FILE_INFO_NUM) * sizeof(struct HksReadFileInfo),
        infos->infos, infos->occu * sizeof(struct HksReadFileInfo));
    HKS_FREE(infos->infos);
    infos->infos = newInfo;
    infos->cap += DEFAULT_FILE_INFO_NUM;
    return HKS_SUCCESS;
}

static int32_t AppendFilePath(const char *path, const char *fileName, struct HksReadFileInfoList *infos)
{
    int32_t ret;
    if (infos->occu == infos->cap) {
        ret = HksReAllocFileInfoList(infos);
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "re-alloc old file info list failed.")
    }
    struct HksReadFileInfo *info = &infos->infos[infos->occu]; // the (infos->occu + 1)th info
    do {
        info->path = (char *)HksMalloc(strlen(path) + 1);
        HKS_IF_NULL_BREAK(info->path)
        info->fileName = (char *)HksMalloc(strlen(fileName) + 1);
        HKS_IF_NULL_BREAK(info->fileName)
        (void)memcpy_s(info->path, strlen(path), path, strlen(path));
        (void)memcpy_s(info->fileName, strlen(fileName), fileName, strlen(fileName));
        infos->occu += 1;

        return HKS_SUCCESS;
    } while (false);
    HksFreeFileInfo(info);
    return ret;
}

static int ConstructSubPath(const struct dirent *ptr, const char *curPath, char *subPath)
{
    int ret = strcpy_s(subPath, DEFAULT_PATH_LEN, curPath);
    if (ret != EOK) {
        return ret;
    }
    ret = strcat_s(subPath, DEFAULT_PATH_LEN, "/");
    if (ret != EOK) {
        return ret;
    }

    ret = strcat_s(subPath, DEFAULT_PATH_LEN, ptr->d_name);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static int32_t HksGetOldStoreFileInfo(const char *path, struct HksReadFileInfoList *infos)
{
    DIR *dir = opendir(path);
    if (dir == NULL) {
        HKS_LOG_E("open dir %" LOG_PUBLIC "s failed.", path);
        return HKS_ERROR_MAKE_DIR_FAIL;
    }
    struct dirent *ptr;
    int ret = EOK;
    while ((ptr = readdir(dir)) != NULL) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }
        if (ptr->d_type == DIR_TYPE) {
            char subPath[DEFAULT_PATH_LEN] = { 0 };

            ret = ConstructSubPath(ptr, path, subPath);
            if (ret != EOK) {
                HKS_LOG_E("construct src and target path failed!");
                break;
            }
            HKS_IF_NOT_SUCC_LOGE_BREAK(HksGetOldStoreFileInfo(subPath, infos),
                "HksGetOldStoreFileInfo failed, path is %" LOG_PUBLIC "s", subPath)
        } else {
            AppendFilePath(path, ptr->d_name, infos);
        }
    }
    closedir(dir);
    return HKS_SUCCESS;
}

int32_t HksInitFileIterativeReader(struct HksIterativeReader *reader, char *path)
{
    reader->fileLists = HksInitFileInfoList();
    if (reader->fileLists == NULL) {
        return HKS_ERROR_MALLOC_FAIL;
    }
    reader->curIndex = 0;
    int32_t ret = HksGetOldStoreFileInfo(path, reader->fileLists);
    if (ret != HKS_SUCCESS) {
        HksFreeFileInfoList(&reader->fileLists);
    }
    return ret;
}

void HksDestroyFileIterativeReader(struct HksIterativeReader *reader)
{
    HksFreeFileInfoList(&reader->fileLists);
}

int32_t HksReadFileWithIterativeReader(struct HksIterativeReader *reader, struct HksBlob *fileContent,
    struct HksBlob *alias, struct HksBlob *path)
{
    if (reader->curIndex == reader->fileLists->occu) {
        return HKS_ERROR_BUFFER_TOO_SMALL;
    }

    int32_t ret = HKS_SUCCESS;
    do {
        uint32_t size = HksFileSize(reader->fileLists->infos[reader->curIndex].path,
            reader->fileLists->infos[reader->curIndex].fileName);
        if (size == 0) {
            ret = HKS_ERROR_FILE_SIZE_FAIL;
            break;
        }
        fileContent->data = (uint8_t *)HksMalloc(size);
        if (fileContent->data == NULL) {
            HKS_LOG_E("malloc fileContent->data failed.");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        fileContent->size = size;
        alias->data = (uint8_t *)HksMalloc(strlen(reader->fileLists->infos[reader->curIndex].fileName) + 1);
        if (alias->data == NULL) {
            HKS_LOG_E("malloc alias->data failed.");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        alias->size = strlen(reader->fileLists->infos[reader->curIndex].fileName) + 1;
        (void)memcpy_s(alias->data, strlen(reader->fileLists->infos[reader->curIndex].fileName),
            reader->fileLists->infos[reader->curIndex].fileName,
            strlen(reader->fileLists->infos[reader->curIndex].fileName));
        path->data = (uint8_t *)HksMalloc(strlen(reader->fileLists->infos[reader->curIndex].path) + 1);
        if (path->data == NULL) {
            HKS_LOG_E("malloc path->data failed.");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }
        path->size = strlen(reader->fileLists->infos[reader->curIndex].path) + 1;
        (void)memcpy_s(path->data, strlen(reader->fileLists->infos[reader->curIndex].path),
            reader->fileLists->infos[reader->curIndex].path, strlen(reader->fileLists->infos[reader->curIndex].path));
        ret = HksFileRead(reader->fileLists->infos[reader->curIndex].path,
            reader->fileLists->infos[reader->curIndex].fileName, 0, fileContent, &fileContent->size);
        reader->curIndex++;
        return ret;
    } while (false);
    HKS_FREE_BLOB(*fileContent);
    HKS_FREE_BLOB(*alias);
    HKS_FREE_BLOB(*path);
    return ret;
}