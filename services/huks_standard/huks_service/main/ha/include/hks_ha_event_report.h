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

#ifndef HKS_HA_EVENT_REPORT_H
#define HKS_HA_EVENT_REPORT_H

#include "hks_plugin_def.h"
#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

void HksEventReport(const char *funcName, const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct HksParamSet *reportParamSet, int32_t errorCode);

#ifdef __cplusplus
}
#endif
#endif