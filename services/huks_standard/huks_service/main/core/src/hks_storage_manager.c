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

#ifndef _CUT_AUTHENTICATE_

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hks_log.h"
#include "hks_template.h"
#include "hks_param.h"

#include "hks_storage.h"
#include "hks_storage_manager.h"

static int32_t HksConstructStoreFileInfo(const struct HksProcessInfo *processInfo,
    const struct HksStoreMaterial *material, struct HksStoreFileInfo *fileInfo, bool supportRootKey)
{
    int32_t ret;
    do {
        ret = CheckSpecificUserIdAndStorageLevel(processInfo, material->paramSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "check storagelevel or specificuserid tag failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = GetFileInfo(processInfo, material, fileInfo, supportRootKey);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks get plain file info failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);
    return ret;
}

int32_t HksManageStoreKeyBlob(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, const struct HksBlob *keyBlob, uint32_t storageType)
{
    struct HksStoreFileInfo fileInfo = { 0 };
    struct HksStoreMaterial material = { .paramSet = paramSet, .keyAlias = keyAlias, .storageType = storageType };
    int32_t ret;
    do {
#ifdef _STORAGE_LITE_
        (void)processInfo;
        (void)material;
        ret = HksStoreKeyBlob(&fileInfo, keyAlias, storageType, keyBlob);
#else
        ret = HksConstructStoreFileInfo(processInfo, &material, &fileInfo, true);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)
        ret = HksStoreKeyBlob(&fileInfo, keyBlob);
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks store key blob failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    return ret;
}

int32_t HksManageStoreDeleteKeyBlob(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, uint32_t storageType)
{
    struct HksStoreFileInfo fileInfo = { 0 };
    struct HksStoreMaterial material = { .paramSet = paramSet, .keyAlias = keyAlias, .storageType = storageType };
    int32_t ret;
    do {
#ifdef _STORAGE_LITE_
        (void)processInfo;
        (void)material;
        ret = HksStoreDeleteKeyBlob(&fileInfo, keyAlias, storageType);
#else
        ret = HksConstructStoreFileInfo(processInfo, &material, &fileInfo, true);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)
        ret = HksStoreDeleteKeyBlob(&fileInfo);
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks delete key blob failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    return ret;
}

int32_t HksManageStoreIsKeyBlobExist(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, uint32_t storageType)
{
    struct HksStoreFileInfo fileInfo = { 0 };
    struct HksStoreMaterial material = { .paramSet = paramSet, .keyAlias = keyAlias, .storageType = storageType };
    int32_t ret;
    do {
#ifdef _STORAGE_LITE_
        (void)processInfo;
        (void)material;
        ret = HksStoreIsKeyBlobExist(&fileInfo, keyAlias, storageType);
#else
        ret = HksConstructStoreFileInfo(processInfo, &material, &fileInfo, true);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)
        ret = HksStoreIsKeyBlobExist(&fileInfo);
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks key blob in old de not exist, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    return ret;
}

int32_t HksManageStoreGetKeyBlob(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, struct HksBlob *keyBlob, uint32_t storageType)
{
    struct HksStoreFileInfo fileInfo = { 0 };
    struct HksStoreMaterial material = { .paramSet = paramSet, .keyAlias = keyAlias, .storageType = storageType };
    int32_t ret;
    do {
#ifdef _STORAGE_LITE_
        (void)processInfo;
        (void)material;
        ret = HksStoreGetKeyBlob(&fileInfo, keyAlias, storageType, keyBlob);
#else
        ret = HksConstructStoreFileInfo(processInfo, &material, &fileInfo, true);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)
        ret = HksStoreGetKeyBlob(&fileInfo, keyBlob);
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks get key blob failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    return ret;
}

int32_t HksManageStoreGetKeyBlobSize(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, uint32_t *keyBlobSize, uint32_t storageType)
{
    struct HksStoreFileInfo fileInfo = { 0 };
    struct HksStoreMaterial material = { .paramSet = paramSet, .keyAlias = keyAlias, .storageType = storageType };
    int32_t ret;
    do {
#ifdef _STORAGE_LITE_
        (void)processInfo;
        (void)material;
        ret = HksStoreGetKeyBlobSize(NULL, keyAlias, storageType, keyBlobSize);
#else
        ret = HksConstructStoreFileInfo(processInfo, &material, &fileInfo, true);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)
        ret = HksStoreGetKeyBlobSize(&fileInfo, keyBlobSize);
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks get key blob failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    return ret;
}

int32_t HksManageGetKeyAliasByProcessName(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount)
{
    struct HksStoreFileInfo fileInfo = { 0 };
    struct HksStoreMaterial material = { .paramSet = paramSet, .keyAlias = NULL, .storageType = HKS_STORAGE_TYPE_KEY };
    int32_t ret;
    do {
        ret = HksConstructStoreFileInfo(processInfo, &material, &fileInfo, false);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)

        ret = HksGetKeyAliasByProcessName(&fileInfo, keyInfoList, listCount);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks get key alias by processname failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    return ret;
}

int32_t HksManageGetKeyCountByProcessName(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    uint32_t *fileCount)
{
    struct HksStoreFileInfo fileInfo = { 0 };
    struct HksStoreMaterial material = { .paramSet = paramSet, .keyAlias = NULL, .storageType = HKS_STORAGE_TYPE_KEY };
    int32_t ret;
    do {
#ifdef _STORAGE_LITE_
        (void)processInfo;
        (void)material;
        ret = HksGetKeyCountByProcessName(NULL, fileCount);
#else
        ret = HksConstructStoreFileInfo(processInfo, &material, &fileInfo, false);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks construct store file info failed, ret = %" LOG_PUBLIC "d.", ret)
        ret = HksGetKeyCountByProcessName(&fileInfo, fileCount);
#endif
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "hks get key count by processname failed, ret = %" LOG_PUBLIC "d.", ret)
    } while (0);

    FileInfoFree(&fileInfo);
    return ret;
}

#endif