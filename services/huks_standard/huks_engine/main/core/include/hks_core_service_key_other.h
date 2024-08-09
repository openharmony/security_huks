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

#ifndef HKS_CORE_SERVICE_KEY_OTHER_H
#define HKS_CORE_SERVICE_KEY_OTHER_H

#include <stdint.h>

#include "hks_keynode.h"
#include "hks_mutex.h"
#include "hks_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksCoreRefreshKeyInfo(void);

int32_t HksCoreCalcMacHeader(const struct HksParamSet *paramSet, const struct HksBlob *salt,
    const struct HksBlob *srcData, struct HksBlob *mac);

int32_t HksCoreModuleInit(void);

int32_t HksCoreModuleDestroy(void);

int32_t HksCoreRefresh(void);

int32_t HksCoreGetAbility(int32_t funcType);

int32_t HksCoreGetHardwareInfo(void);

HksMutex *HksCoreGetHuksMutex(void);

int32_t HksCoreUpgradeKeyInfo(const struct HksBlob *keyAlias, const struct HksBlob *keyInfo, struct HksBlob *keyOut);

#ifdef __cplusplus
}
#endif

#endif /* HKS_CORE_SERVICE_KEY_OTHER_H */