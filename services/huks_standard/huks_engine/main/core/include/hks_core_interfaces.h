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

#ifndef HUKS_CORE_INTERFACES
#define HUKS_CORE_INTERFACES

#include <stdint.h>
#include <stdio.h>
#include "hks_access.h"
#include "hks_config.h"
#include "hks_log.h"

struct HksCoreIfDevice {
    int32_t (*ModuleInit)(void);

    int32_t (*Refresh)(void);

    int32_t (*GenerateKey)(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
            const struct HksBlob *keyIn, struct HksBlob *keyOut);

    int32_t (*ImportKey)(const struct HksBlob *keyAlias, const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *keyOut);

    int32_t (*ImportWrappedKey)(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
            const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut);

    int32_t (*ExportPublicKey)(const struct HksBlob *key,  const struct HksParamSet *paramSet, struct HksBlob *keyOut);

    int32_t (*Init)(const struct  HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *handle);

    int32_t (*Update)(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData);

    int32_t (*Finish)(const struct HksBlob *handle, const struct HksParamSet *paramSet, const struct HksBlob *inData,
    struct HksBlob *outData);

    int32_t (*Abort)(const struct HksBlob *handle, const struct HksParamSet *paramSet);

    int32_t (*GetKeyProperties)(const struct HksParamSet *paramSet, const struct HksBlob *key);

    int32_t (*AttestKey)(const struct HksBlob *key, const  struct HksParamSet *paramSet, struct HksBlob *certChain);

    int32_t (*GetAbility)(int funcType);

    int32_t (*GetHardwareInfo)(void);

    int32_t (*CalcMacHeader)(const struct HksParamSet *paramSet, const struct HksBlob *salt,
            const struct HksBlob *srcData, struct HksBlob *mac);

    int32_t (*UpgradeKeyInfo)(const struct HksBlob *keyAlias, const struct HksBlob *keyInfo,
    struct HksBlob *keyOut);

    int32_t (*GenerateRandom)(const struct HksParamSet *paramSet, struct HksBlob *random);
};

struct HksCoreIfDevice* HksCreateCoreIfDevicePtr(void);

void HksDestoryCoreIfDevicePtr(void);

#endif
