/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef HKS_CORE_GET_MAIN_KEY_H
#define HKS_CORE_GET_MAIN_KEY_H

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_crypto_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksCoreGetMainKey(const struct HksBlob *message, struct HksBlob *mainKey);

void RegisterAbilityGetMainKey(void);

#ifdef __cplusplus
}
#endif

#endif /* HKS_CORE_GET_MAIN_KEY_H */
