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

#ifndef HKS_FILE_OPERATOR_H
#define HKS_FILE_OPERATOR_H

#include "hks_type.h"

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#define HKS_MAX_FILE_NAME_LEN 512

#ifdef L2_STANDARD
    #define HKS_KEY_STORE_PATH            HKS_CONFIG_KEY_STORE_PATH "/maindata"
    #define HKS_KEY_STORE_BAK_PATH        HKS_CONFIG_KEY_STORE_PATH "/bakdata"
    #ifdef HUKS_ENABLE_SKIP_UPGRADE_KEY_STORAGE_SECURE_LEVEL
        #define HKS_KEY_STORE_TMP_PATH        HKS_CONFIG_KEY_STORE_PATH "/tmp"
    #endif
    #define HKS_CE_ROOT_PATH              "/data/service/el2"
    #define HKS_ECE_ROOT_PATH             "/data/service/el4"
    #define HKS_STORE_SERVICE_PATH        "huks_service/maindata"
    #ifdef HKS_USE_RKC_IN_STANDARD
        #define HKS_KEY_RKC_PATH HKS_CONFIG_RKC_STORE_PATH "/maindata"
    #endif
#else
    #ifdef HKS_L1_SMALL
        #define HKS_KEY_STORE_PATH            "/storage/data/service/el1/public/huks_service/maindata"
        #define HKS_KEY_STORE_BAK_PATH        "/storage/data/service/el1/public/huks_service/bakdata"
    #else
        #ifdef _STORAGE_LITE_
            #define HKS_KEY_STORE_PATH                HKS_CONFIG_KEY_STORE_PATH
        #else
            #ifdef HKS_ENABLE_LITE_HAP
                #define HKS_KEY_STORE_LITE_HAP        HKS_CONFIG_LITE_HAP_STORE_PATH
            #endif
            #ifdef HKS_CONFIG_KEY_STORE_PATH
                #define HKS_KEY_STORE_PATH            HKS_CONFIG_KEY_STORE_PATH "/maindata"
                #define HKS_KEY_STORE_BAK_PATH        HKS_CONFIG_KEY_STORE_PATH "/bakdata"
            #else
                #define HKS_KEY_STORE_PATH            "/storage/maindata"
                #define HKS_KEY_STORE_BAK_PATH        "/storage/bakdata"
            #endif
        #endif
    #endif
#endif
#define HKS_KEY_STORE_KEY_PATH        "key"
#define HKS_KEY_STORE_ROOT_KEY_PATH   "info"

#define HKS_PROCESS_INFO_LEN    128
#define HKS_MAX_DIRENT_FILE_LEN 128
struct HksFileDirentInfo {
    char fileName[HKS_MAX_DIRENT_FILE_LEN]; /* point to dirent->d_name */
};

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksFileRead(const char *path, const char *fileName, uint32_t offset, struct HksBlob *blob, uint32_t *size);

int32_t HksFileWrite(const char *path, const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len);

int32_t HksFileRemove(const char *path, const char *fileName);

uint32_t HksFileSize(const char *path, const char *fileName);

int32_t HksIsFileExist(const char *path, const char *fileName);

int32_t HksIsDirExist(const char *path);

int32_t HksMakeDir(const char *path);

void *HksOpenDir(const char *path);

int32_t HksCloseDir(void *dirp);

int32_t HksGetDirFile(void *dirp, struct HksFileDirentInfo *direntInfo);

int32_t HksRemoveDir(const char *dirPath);

int32_t HksDeleteDir(const char *path);

int32_t HksGetFileName(const char *path, const char *fileName, char *fullFileName, uint32_t fullFileNameLen);

#ifdef __cplusplus
}
#endif

#endif /* HKS_FILE_OPERATOR_H */
