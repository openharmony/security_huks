/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef HKS_UKEY_THREE_STAGE_ADAPTER_H
#define HKS_UKEY_THREE_STAGE_ADAPTER_H

#include <stdint.h>
#include <stdbool.h>
#include "hks_type.h"
#include "hks_plugin_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksCheckIsUkeyOperation(const struct HksParamSet *paramSet);

int32_t HksServiceOnUkeyInitSession(const struct HksProcessInfo *processInfo, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *handle);

int32_t HksServiceOnUkeyUpdateSession(const struct HksProcessInfo *processInfo, const struct HksBlob *handle,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData);

int32_t HksServiceOnUkeyFinishSession(const struct HksProcessInfo *processInfo, const struct HksBlob *handle,
    const struct HksParamSet *paramSet, const struct HksBlob *inData, struct HksBlob *outData);

#ifdef __cplusplus
}
#endif

#endif