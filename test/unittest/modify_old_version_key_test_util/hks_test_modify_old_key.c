/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "hks_test_modify_old_key.h"

#include "hks_client_service.h"
#include "hks_type_inner.h"
#include "hks_core_service.h"
#include "hks_storage.h"
#include "hks_param.h"
#include "hks_log.h"
#include "hks_storage_manager.h"

#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>

#define KEY_MAX_SIZE 4096
#define DIR_TYPE 4
#define DEFAULT_PATH_LEN 1024

int32_t HksTestGenerateOldKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    const struct HksProcessInfo *processInfo)
{
    HKS_LOG_I("enter HksTestGenerateOldKey");

    struct HksParamSet *newParamSet = NULL;
    (void)HksInitParamSet(&newParamSet);

    (void)HksAddParams(newParamSet, paramSet->params, paramSet->paramsCnt);

    struct HksParam tmpParam;
    tmpParam.tag = HKS_TAG_PROCESS_NAME;
    tmpParam.blob = processInfo->processName;

    (void)HksAddParams(newParamSet, &tmpParam, 1);

    (void)HksBuildParamSet(&newParamSet);

    uint8_t keyData[KEY_MAX_SIZE] = { 0 };
    struct HksBlob keyBlob = { .size = KEY_MAX_SIZE, .data = keyData };

    (void)HksCoreGenerateKey(keyAlias, newParamSet, NULL, &keyBlob);

    (void)HksManageStoreKeyBlob(processInfo, newParamSet, keyAlias, &keyBlob, HKS_STORAGE_TYPE_KEY);

    HksFreeParamSet(&newParamSet);
    return HKS_SUCCESS;
}

int32_t HksTestDeleteOldKey(const struct HksBlob *keyAlias, const struct HksProcessInfo *processInfo)
{
    return HksServiceDeleteKey(processInfo, keyAlias, NULL);
}

int32_t HksTestOldKeyExist(const struct HksBlob *keyAlias)
{
    const char *userId = "0";
    const char *processName = "hks_client";
    struct HksProcessInfo processInfo = {
        { strlen(userId), (uint8_t *)userId },
        { strlen(processName), (uint8_t *)processName },
        0,
        0,
        0
    };
    return HksServiceKeyExist(&processInfo, keyAlias, NULL);
}

int32_t HksTestInitialize(void)
{
    int32_t ret = HksCoreModuleInit();
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    ret = HksServiceInitialize();
    return ret;
}

void ChangeDirAndFiles(const char *path, uint32_t uid)
{
    DIR *dir;
    struct dirent *ptr;
    dir = opendir(path);
    if (dir == NULL) {
        return;
    }
    int ret = EOK;
    while ((ptr = readdir(dir)) != NULL) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
            continue;
        }
        char curPath[DEFAULT_PATH_LEN] = { 0 };

        ret = strcpy_s(curPath, DEFAULT_PATH_LEN, path);
        if (ret != EOK) {
            break;
        }
        ret = strcat_s(curPath, DEFAULT_PATH_LEN, "/");
        if (ret != EOK) {
            break;
        }
        ret = strcat_s(curPath, DEFAULT_PATH_LEN, ptr->d_name);
        if (ret != EOK) {
            break;
        }

        ret = chown(curPath, uid, uid);
        if (ret != EOK) {
            break;
        }
        if (ptr->d_type == DIR_TYPE) {
            ChangeDirAndFiles(curPath, uid);
        }
    }
    if (ret != EOK) {
        printf("chmod dir and file failed! errno = 0x%x \n", errno);
    }
    (void)closedir(dir);
}

void HksChangeOldKeyOwner(const char *path, uint32_t uid)
{
    ChangeDirAndFiles(path, uid);
}