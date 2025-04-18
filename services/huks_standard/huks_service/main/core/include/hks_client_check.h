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

#ifndef HKS_CLIENT_CHECK_H
#define HKS_CLIENT_CHECK_H

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include <stdint.h>

#include "hks_type.h"
#include "hks_type_inner.h"
#ifdef __cplusplus
extern "C" {
#endif

int32_t HksCheckProcessNameAndKeyAlias(const struct HksBlob *processName, const struct HksBlob *keyAlias);

int32_t HksCheckGenAndImportKeyParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, const struct HksBlob *key);

int32_t HksCheckImportWrappedKeyParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksBlob *wrappingKeyAlias, const struct HksParamSet *paramSetIn, const struct HksBlob *wrappedKeyData);

int32_t HksCheckAllParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *data1, const struct HksBlob *data2);

int32_t HksCheckGetKeyParamSetParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet);

int32_t HksCheckGenerateRandomParams(const struct HksBlob *processName, const struct HksBlob *random);

int32_t HksCheckExportPublicKeyParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksBlob *key);

int32_t HksCheckDeriveKeyParams(const struct HksBlob *processName, const struct HksParamSet *paramSet,
    const struct HksBlob *mainKey, const struct HksBlob *derivedKey);

int32_t HksCheckGetKeyInfoListParams(const struct HksBlob *processName, const struct HksKeyInfo *keyInfoList,
    const uint32_t *listCount);

#ifdef HKS_SUPPORT_API_ATTEST_KEY
int32_t HksCheckAttestKeyParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *certChain);
#endif

int32_t HksCheckServiceInitParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet);

int32_t HksCheckAndGetUserAuthInfo(const struct HksParamSet *paramSet, uint32_t *userAuthType,
    uint32_t *authAccessType);

int32_t HksCheckUserAuthKeyPurposeValidity(const struct HksParamSet *paramSet);

int32_t HksCheckListAliasesParam(const struct HksBlob *processName);

bool HksCheckIsAllowedWrap(const struct HksParamSet *paramSet);

int32_t HKsCheckOldKeyAliasDiffNewKeyAlias(const struct HksBlob *oldKeyAlias,
    const struct HksBlob *newKeyAlias);

int32_t HksCheckOldKeyExist(const struct HksProcessInfo *processInfo, const struct HksBlob *oldKeyAlias,
    const struct HksParamSet *paramSet);

int32_t HksCheckNewKeyNotExist(const struct HksProcessInfo *processInfo, const struct HksBlob *newKeyAlias,
    const struct HksParamSet *paramSet);

int32_t HksCheckProcessInConfigList(const struct HksBlob *processName);

int32_t HksCheckChangeStorageLevelParams(const struct HksBlob *processName, const struct HksBlob *keyAlias,
    const struct HksParamSet *srcParamSet, const struct HksParamSet *destParamSet);

#ifdef __cplusplus
}
#endif

#endif
