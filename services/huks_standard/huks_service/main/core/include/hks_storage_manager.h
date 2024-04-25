/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef HUKS_STORAGE_MANAGER_H
#define HUKS_STORAGE_MANAGER_H

#include "hks_storage_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksManageStoreKeyBlob(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, const struct HksBlob *keyBlob, uint32_t storageType);

int32_t HksManageStoreDeleteKeyBlob(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, uint32_t storageType);

int32_t HksManageStoreIsKeyBlobExist(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, uint32_t storageType);

int32_t HksManageStoreGetKeyBlob(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, struct HksBlob *keyBlob, uint32_t storageType);

int32_t HksManageStoreGetKeyBlobSize(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, uint32_t *keyBlobSize, uint32_t storageType);

int32_t HksManageGetKeyAliasByProcessName(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount);

int32_t HksManageGetKeyCountByProcessName(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    uint32_t *fileCount);

int32_t HksManageListAliasesByProcessName(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    struct HksKeyAliasSet **outData);

#ifdef __cplusplus
}
#endif

#endif /* HUKS_STORAGE_MANAGER_H */
