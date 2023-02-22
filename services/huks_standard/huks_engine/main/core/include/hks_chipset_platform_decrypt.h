/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#ifndef HKS_CHIPSET_PLATFORM_DECRYPT_H
#define HKS_CHIPSET_PLATFORM_DECRYPT_H

#include <stddef.h>
#include <stdint.h>

#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

// Key protection scheme based on chipset platform key
enum {
    PLATFORM_KEY_INPUT_PARAMS_COUNT = 7,
    // The user must pass 16 bytes of salt, although only first 15 bytes will be used,
    // the last byte of salt from user is ignored and will be replaced by huks
    PLATFORM_KEY_SALT_SIZE = 16,
    PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE = 32,
    PLATFORM_KEY_PLATFORM_PUB_KEY_SIZE = PLATFORM_KEY_PLATFORM_PRI_KEY_SIZE * 2,
    PLATFORM_KEY_BUSINESS_ID_SIZE = 16,
    PLATFORM_KEY_CUSTOM_INFO_SIZE = 16,
    PLATFORM_KEY_HMAC_MESSAGE_SIZE = PLATFORM_KEY_BUSINESS_ID_SIZE + PLATFORM_KEY_CUSTOM_INFO_SIZE,
    PLATFORM_KEY_IV_SIZE = 12,
    PLATFORM_KEY_AAD_SIZE = 16,
    PLATFORM_KEY_TAG_SIZE = 16,
    PLATFORM_KEY_TEXT_MIN_LEN = 1,
    PLATFORM_KEY_TEXT_MAX_LEN = 512,

    PLATFORM_KEY_SALT_PADDING_BYTE_TA_TO_TA = 0xFF,
    PLATFORM_KEY_SHARED_KEY_SIZE = 32,
    PLATFORM_KEY_WRAPPED_KEY_SIZE = 32,
};

int32_t HuksCoreChipsetPlatformDecrypt(const struct HksParamSet *paramSet,
    enum HksChipsetPlatformDecryptScene scene, struct HksBlob *plainText);

int32_t HuksCoreExportChipsetPlatformPublicKey(const struct HksBlob *salt,
    enum HksChipsetPlatformDecryptScene scene, struct HksBlob *publicKey);

#ifdef __cplusplus
}
#endif

#endif /* HKS_CHIPSET_PLATFORM_DECRYPT_H */