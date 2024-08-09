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

#ifndef HKS_CORE_SERVICE_KEY_CHIPSET_PLATFORM_DERIVE_H
#define HKS_CORE_SERVICE_KEY_CHIPSET_PLATFORM_DERIVE_H

#include <stdint.h>

#include "hks_keynode.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksCoreExportChipsetPlatformPublicKey(const struct HksBlob *salt,
    enum HksChipsetPlatformDecryptScene scene, struct HksBlob *publicKey);

int32_t HksCoreChipsetPlatformDecrypt(const struct HksParamSet *paramSet,
    enum HksChipsetPlatformDecryptScene scene, struct HksBlob *plainText);

#ifdef __cplusplus
}
#endif

#endif /* HKS_CORE_SERVICE_KEY_CHIPSET_PLATFORM_DERIVE_H */