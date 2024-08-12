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

#ifdef HKS_CONFIG_FILE
#include HKS_CONFIG_FILE
#else
#include "hks_config.h"
#endif

#include "hks_core_service_key_chipset_platform_derive.h"

#include <stdbool.h>
#include <stddef.h>

#include "hks_chipset_platform_decrypt.h"

#ifndef _HARDWARE_ROOT_KEY_
#include "hks_rkc.h"
#endif

#ifdef HKS_SUPPORT_CHIPSET_PLATFORM_DECRYPT
int32_t HksCoreChipsetPlatformDecrypt(const struct HksParamSet *paramSet,
    enum HksChipsetPlatformDecryptScene scene, struct HksBlob *plainText)
{
    return HuksCoreChipsetPlatformDecrypt(paramSet, scene, plainText);
}

int32_t HksCoreExportChipsetPlatformPublicKey(const struct HksBlob *salt,
    enum HksChipsetPlatformDecryptScene scene, struct HksBlob *publicKey)
{
    return HuksCoreExportChipsetPlatformPublicKey(salt, scene, publicKey);
}
#endif