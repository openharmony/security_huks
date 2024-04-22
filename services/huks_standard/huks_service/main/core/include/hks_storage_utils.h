/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef HKS_STORAGE_UTILS_H
#define HKS_STORAGE_UTILS_H

#include <stdint.h>

#include "hks_type_inner.h"
#include "hks_file_operator.h"

enum HksStorageType {
    HKS_STORAGE_TYPE_KEY = 0,
    HKS_STORAGE_TYPE_ROOT_KEY,
};

#ifdef __cplusplus
extern "C" {
#endif

#define HKS_STORAGE_BAK_FLAG_TRUE     1
#define HKS_STORAGE_BAK_FLAG_FLASE    0

struct HksStoreInfo {
    char *path; /* file path include process/key(or certchain) */
    char *fileName; /* file name that can be recognized by the file system */
    uint32_t size;
};

struct HksStoreFileInfo {
    struct HksStoreInfo mainPath;
#ifdef SUPPORT_STORAGE_BACKUP
    struct HksStoreInfo bakPath;
#endif
};

enum HksPathType {
    DE_PATH,
#ifdef L2_STANDARD
    CE_PATH,
    ECE_PATH,

    #ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    TMP_PATH,
    #endif

    #ifdef HKS_USE_RKC_IN_STANDARD
    RKC_IN_STANDARD_PATH,
    #endif
#endif
#ifdef HKS_ENABLE_LITE_HAP
    LITE_HAP_PATH,
#endif
};

struct HksStoreMaterial {
    enum HksPathType pathType;
    char *userIdPath;
    char *uidPath;
    /**
     * Storage type, including key and root key materials
     */
    char *storageTypePath;

    char *keyAliasPath;
};

struct HksFileEntry {
    char *fileName;
    uint32_t fileNameLen;
};

enum KeyOperation {
    KEY_OPERATION_SAVE = 0,
    KEY_OPERATION_GET = 1,
    KEY_OPERATION_DELETE = 2,
};

int32_t ConstructPlainName(const struct HksBlob *blob, char *targetName, uint32_t nameLen);

int32_t ConstructName(const struct HksBlob *blob, char *targetName, uint32_t nameLen);

int32_t ConstructBlob(const char *src, struct HksBlob *blob);

int32_t GetPath(const char *path, const char *name, char *targetPath, uint32_t pathLen, uint32_t bakFlag);

int32_t HksFileInfoInit(struct HksStoreFileInfo *fileInfo);

void FileInfoFree(struct HksStoreFileInfo *fileInfo);

int32_t RecordKeyOperation(uint32_t operation, const char *path, const char *keyAlias);

void FileNameListFree(struct HksFileEntry **fileNameList, uint32_t keyCount);

int32_t FileNameListInit(struct HksFileEntry **fileNameList, uint32_t keyCount);

int32_t HksMakeFullDir(const char *path);

int32_t HksGetFileInfo(const struct HksStoreMaterial *material, struct HksStoreFileInfo *fileInfo);

int32_t CheckSpecificUserIdAndStorageLevel(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet);

#ifdef __cplusplus
}
#endif

#endif /* HUKS_STORAGE_UTILS_H */