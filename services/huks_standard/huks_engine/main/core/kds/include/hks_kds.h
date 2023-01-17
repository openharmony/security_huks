/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef HKS_KDS_H
#define HKS_KDS_H

#include <stddef.h>
#include <stdint.h>

#include "hks_crypto_hal.h"
#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

// 入参规格
#define KDS_INPUT_PARAMS_NUMBER 7
#define KDS_SALT_SIZE 16
#define KDS_TMP_PK_SIZE 64
#define KDS_CUSTOM_INFO_SIZE 16
#define KDS_IV_SIZE 12
#define KDS_AAD_SIZE 16
#define KDS_MAC_SIZE 16
#define KDS_TEXT_MIN_LEN 16
#define KDS_TEXT_MAX_LEN 512
#define KDS_TEXT_LEN_FACTOR 16

// 中间参数规格
#define KDS_PROCESS_INFO_MAX_SIZE 512
#define KDS_SHARED_KEY_SIZE 32
#define KDS_WRAPED_KEY_SIZE 32

int32_t HuksCoreChipsetPlatformDecrypt(const struct HksParamSet *paramSet, struct HksBlob *plainText);

#ifdef __cplusplus
}
#endif

#endif /* HKS_KDS_H */