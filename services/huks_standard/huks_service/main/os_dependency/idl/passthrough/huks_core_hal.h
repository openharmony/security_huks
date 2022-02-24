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

#ifndef HUKS_CORE_HAL_H
#define HUKS_CORE_HAL_H

#include "hks_param.h"
#include "hks_type_inner.h"

struct HksHalDevice {
    int32_t (*ModuleInit)(void);

    int32_t (*Refresh)(void);

    int32_t (*GenerateKey)(const struct HksBlob *, const struct HksParamSet *,
        const struct HksBlob *, struct HksBlob *);

    int32_t (*ImportKey)(const struct HksBlob *, const struct HksBlob *, const struct HksParamSet *, struct HksBlob *);

    int32_t (*ImportWrappedKey)(const struct HksBlob *, const struct HksBlob *,
        const struct HksBlob *, const struct HksParamSet *, struct HksBlob *);

    int32_t (*ExportPublicKey)(const struct HksBlob *, const struct HksParamSet *, struct HksBlob *);

    int32_t (*Init)(const struct HksBlob *, const struct HksParamSet *, struct HksBlob *);

    int32_t (*Update)(const struct HksBlob *, const struct HksParamSet *, const struct HksBlob *, struct HksBlob *);

    int32_t (*Finish)(const struct HksBlob *, const struct HksParamSet *, const struct HksBlob *, struct HksBlob *);

    int32_t (*Abort)(const struct HksBlob *, const struct HksParamSet *);

    int32_t (*GetKeyProperties)(const struct HksParamSet *, const struct HksBlob *);

    int32_t (*AttestKey)(const struct HksBlob *, const struct HksParamSet *, struct HksBlob *);

    int32_t (*GetAbility)(int);

    int32_t (*GetHardwareInfo)(void);

    int32_t (*CalcMacHeader)(const struct HksParamSet *, const struct HksBlob *,
        const struct HksBlob *, struct HksBlob *);

    int32_t (*UpgradeKeyInfo)(const struct HksBlob *, const struct HksBlob *, struct HksBlob *);

    int32_t (*GenerateRandom)(const struct HksParamSet *, struct HksBlob *);

    int32_t (*Sign)(const struct HksBlob *, const struct HksParamSet *, const struct HksBlob *, struct HksBlob *);

    int32_t (*Verify)(const struct HksBlob *, const struct HksParamSet *, const struct HksBlob *,
        const struct HksBlob *);

    int32_t (*Encrypt)(const struct HksBlob *, const struct HksParamSet *, const struct HksBlob *, struct HksBlob *);

    int32_t (*Decrypt)(const struct HksBlob *, const struct HksParamSet *, const struct HksBlob *, struct HksBlob *);

    int32_t (*AgreeKey)(const struct HksParamSet *, const struct HksBlob *, const struct HksBlob *, struct HksBlob *);

    int32_t (*DeriveKey)(const struct HksParamSet *, const struct HksBlob *, struct HksBlob *);

    int32_t (*Mac)(const struct HksBlob *, const struct HksParamSet *, const struct HksBlob *, struct HksBlob *);
};

int32_t HksCreateHuksHdiDevice(struct HksHalDevice **halDevice);

int32_t HksDestroyHuksHdiDevice(struct HksHalDevice **halDevice);

#endif
