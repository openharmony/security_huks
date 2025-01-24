/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef HKS_REPORT_RENAME_KEY_H
#define HKS_REPORT_RENAME_KEY_H

#include "hks_type.h"
#include "hks_type_inner.h"
#include "hks_event_info.h"
#include "hks_type_enum.h"
#include <stdint.h>

#ifdef __cplusplus
#include <vector>
#include <unordered_map>
#include <string>
#endif

#ifdef __cplusplus
extern "C" {
#endif

int32_t PreConstructRenameReportParamSet(const struct HksBlob *keyAlias, const struct HksBlob *dstKeyAlias,
    const struct HksParamSet *paramSetIn, uint64_t startTime, struct HksParamSet **paramSetOut);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

int32_t HksParamSetToEventInfoForRename(const struct HksParamSet *paramSetIn, struct HksEventInfo* eventInfo);

bool HksEventInfoIsNeedReportForRename(const struct HksEventInfo *eventInfo);

bool HksEventInfoIsEqualForRename(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2);

void HksEventInfoAddForRename(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo);

int32_t HksEventInfoToMapForRename(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData);

#endif

#endif  // HKS_REPORT_RENAME_KEY_H
