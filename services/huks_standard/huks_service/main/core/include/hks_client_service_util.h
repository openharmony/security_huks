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

#ifndef HKS_CLIENT_SERVICE_UTIL_H
#define HKS_CLIENT_SERVICE_UTIL_H

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_type.h"
#include "hks_session_manager.h"
#include "hks_storage_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

void IfNotSuccAppendHdiErrorInfo(int32_t hdiRet);

int32_t GetKeyParamSet(const struct HksBlob *key, struct HksParamSet *paramSet);

#ifndef _STORAGE_LITE_
int32_t GetKeyFileData(const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksBlob *keyAlias, struct HksBlob *key, enum HksStorageType mode);

#ifdef HKS_ENABLE_UPGRADE_KEY
int32_t ConstructUpgradeKeyParamSet(const struct HksProcessInfo *processInfo, const struct HksParamSet *srcParamSet,
    struct HksParamSet **outParamSet);
#endif /* HKS_ENABLE_UPGRADE_KEY */

#endif /* _STORAGE_LITE_ */

int32_t AppendStorageLevelIfNotExistInner(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksParamSet **outParamSet);

bool CheckProcessNameTagExist(const struct HksParamSet *paramSet);

int32_t AppendProcessInfoAndDefault(const struct HksParamSet *paramSet, const struct HksProcessInfo *processInfo,
    const struct HksOperation *operation, struct HksParamSet **outParamSet, bool checkGroup);

// callback
int32_t AppendNewInfoForGenKeyInService(const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, struct HksParamSet **outParamSet);

int32_t AppendNewInfoForUseKeyInService(const struct HksParamSet *paramSet,
    const struct HksProcessInfo *processInfo, struct HksParamSet **outParamSet);

int32_t AppendStorageLevelIfNotExist(const struct HksParamSet *paramSet, struct HksParamSet **outParamSet);

int32_t GetKeyData(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key, enum HksStorageType mode);

int32_t CheckKeyCondition(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet);

int32_t AppendKeyBlobToParamSet(const struct HksParamSet *paramSet, const struct HksBlob *keyBlob,
    struct HksParamSet **outParamSet);

int32_t HksGetScreenLockStatus(int32_t userId);

// Shared helpers migrated from hks_client_service.c
#ifdef HKS_UKEY_EXTENSION_CRYPTO
int32_t HksCheckMultiSetTag(const struct HksParamSet *paramSet);
#endif

#ifndef _CUT_AUTHENTICATE_
int32_t DksAppendKeyAliasAndNewParamSet(struct HksParamSet *paramSet, const struct HksBlob *keyAlias,
    struct HksParamSet **outParamSet);

int32_t GetKeyAndNewParamSet(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key, struct HksParamSet **outParamSet);

#if defined(L2_STANDARD) && defined(HKS_SUPPORT_GET_BUNDLE_INFO)
int32_t CheckExistingDeveloperId(const struct HksParamSet *paramSet, const struct HksBlob *developerId,
    bool *needAdd);

int32_t AppendGroupKeyInfo(const struct HksProcessInfo *processInfo, struct HksParamSet **outParamSet);
#endif

int32_t StoreOrCopyKeyBlob(const struct HksParamSet *paramSet, const struct HksProcessInfo *processInfo,
    struct HksBlob *output, struct HksBlob *outData, bool isNeedStorage);
#endif /* _CUT_AUTHENTICATE_ */

#ifdef __cplusplus
}
#endif

#endif
