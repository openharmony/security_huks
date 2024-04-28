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

#ifndef HKS_STORAGE_H
#define HKS_STORAGE_H

#include "hks_storage_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _CUT_AUTHENTICATE_
#ifdef _STORAGE_LITE_
int32_t HksStoreKeyBlob(const struct HksStoreFileInfo *fileInfo, const struct HksBlob *keyAlias,
    uint32_t storageType, const struct HksBlob *keyBlob);

int32_t HksStoreDeleteKeyBlob(const struct HksStoreFileInfo *fileInfo,
    const struct HksBlob *keyAlias, uint32_t storageType);

int32_t HksStoreIsKeyBlobExist(const struct HksStoreFileInfo *fileInfo,
    const struct HksBlob *keyAlias, uint32_t storageType);

int32_t HksStoreGetKeyBlob(const struct HksStoreFileInfo *fileInfo,
    const struct HksBlob *keyAlias, uint32_t storageType, struct HksBlob *keyBlob);

int32_t HksStoreGetKeyBlobSize(const struct HksBlob *processName,
    const struct HksBlob *keyAlias, uint32_t storageType, uint32_t *keyBlobSize);

int32_t HksGetKeyCountByProcessName(const struct HksBlob *processName, uint32_t *fileCount);
#else // _STORAGE_LITE_

int32_t HksStoreKeyBlob(const struct HksStoreFileInfo *fileInfo, const struct HksBlob *keyBlob);

int32_t HksStoreDeleteKeyBlob(const struct HksStoreFileInfo *fileInfo);

int32_t HksStoreIsKeyBlobExist(const struct HksStoreFileInfo *fileInfo);

int32_t HksStoreGetKeyBlob(const struct HksStoreFileInfo *fileInfo, struct HksBlob *keyBlob);

int32_t HksStoreGetKeyBlobSize(const struct HksStoreFileInfo *fileInfo, uint32_t *keyBlobSize);

int32_t HksGetKeyCountByProcessName(const struct HksStoreFileInfo *fileInfo, uint32_t *fileCount);
#endif // _STORAGE_LITE_
#endif // _CUT_AUTHENTICATE_

int32_t HksGetKeyAliasByProcessName(const struct HksStoreFileInfo *fileInfo, struct HksKeyInfo *keyInfoList,
    uint32_t *listCount);

int32_t HksStoreDestroy(const struct HksBlob *processName);

void HksServiceDeleteUserIDKeyAliasFile(const struct HksBlob *userId);

void HksServiceDeleteUIDKeyAliasFile(const struct HksProcessInfo *processInfo);

int32_t HksListAliasesByProcessName(const struct HksStoreFileInfo *fileInfo, struct HksKeyAliasSet **outData);

#ifdef HKS_ENABLE_SMALL_TO_SERVICE
int32_t HksIsOldKeyPathCleared(uint32_t *keyCount);
#endif

#ifdef _STORAGE_LITE_

#define HKS_KEY_STORE_FILE_NAME "hks_keystore"

int32_t HksLoadFileToBuffer(void);

int32_t HksFileBufferRefresh(void);

int32_t HksStoreGetToatalSize(uint32_t *size);

int32_t HksStoreGetKeyInfoList(struct HksKeyInfo *keyInfoList, uint32_t *listCount);

#endif /* _STORAGE_LITE_ */

#ifdef __cplusplus
}
#endif

#endif /* HKS_STORAGE_H */