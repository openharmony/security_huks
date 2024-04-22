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

#ifndef HKS_AT_API_WRAP_H
#define HKS_AT_API_WRAP_H

#include "hks_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

enum HksAtType {
    HKS_TOKEN_HAP,
    HKS_TOKEN_NATIVE,
    HKS_TOKEN_SHELL
};

int32_t HksGetAtType(uint64_t accessTokenId, enum HksAtType *atType);

#define HAP_NAME_LEN_MAX 128
int32_t HksGetHapNameFromAccessToken(int32_t tokenId, char *hapName, int32_t hapNameSize);

#ifdef __cplusplus
}
#endif

#endif // HKS_AT_API_WRAP_H