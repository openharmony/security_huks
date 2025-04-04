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

#ifndef HKS_CORE_SERVICE_KEY_OPERATE_ONE_STAGE_H
#define HKS_CORE_SERVICE_KEY_OPERATE_ONE_STAGE_H

#include <stdint.h>

#include "hks_type.h"

#define MAX_HASH_SIZE 64

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksCoreSign(const struct HksBlob *key, const struct HksParamSet *paramSet, const struct HksBlob *srcData,
    struct HksBlob *signature);

int32_t HksCoreVerify(const struct HksBlob *key, const struct HksParamSet *paramSet, const struct HksBlob *srcData,
    const struct HksBlob *signature);

int32_t HksCoreEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet, const struct HksBlob *plainText,
    struct HksBlob *cipherText);

int32_t HksCoreDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet, const struct HksBlob *cipherText,
    struct HksBlob *plainText);

int32_t HksCoreGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key);

int32_t HksCoreExportPublicKey(const struct HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *keyOut);

int32_t HksCoreAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey);

int32_t HksCoreDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *mainKey, struct HksBlob *derivedKey);

int32_t HksCoreMac(const struct HksBlob *key, const struct HksParamSet *paramSet, const struct HksBlob *srcData,
    struct HksBlob *mac);

int32_t HksCoreUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet,
    struct HksBlob *newKey);

#ifdef __cplusplus
}
#endif

#endif /* HKS_CORE_SERVICE_KEY_OPERATE_ONE_STAGE_H */