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

#ifndef HKS_CLIENT_SERVICE_ADAPTER_COMMON_H
#define HKS_CLIENT_SERVICE_ADAPTER_COMMON_H

#include <stdint.h>

#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CopyToInnerKey(const struct HksBlob *key, struct HksBlob *outKey);

int32_t GetHksPubKeyInnerFormat(const struct HksParamSet *paramSet, const struct HksBlob *key, struct HksBlob *outKey);

#ifdef __cplusplus
}
#endif

#endif /* HKS_CLIENT_SERVICE_ADAPTER_COMMON_H */
