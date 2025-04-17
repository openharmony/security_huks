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

#ifndef HKS_REPORT_THREE_STAGE_GET_H
#define HKS_REPORT_THREE_STAGE_GET_H

#include <stdint.h>

#include "hks_event_info.h"
#include "hks_plugin_def.h"
#include "hks_session_manager.h"
#include "hks_type.h"

typedef struct HksThreeStageReportInfo {
    int32_t errCode;
    uint32_t inDataSize;
    enum HksReportStage stage;
    uint64_t startTime;
    const struct HksBlob *handle;
} HksThreeStageReportInfo;

typedef struct HksOneStageReportInfo {
    int32_t errCode;
    uint64_t startTime;
    const char *funcName;
    enum HksReportStage stage;
} HksOneStageReportInfo;

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksOneStageEventReport(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, const struct HksProcessInfo *processInfo, HksOneStageReportInfo *info);

int32_t HksGetInitEventInfo(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, const struct HksProcessInfo *processInfo, HksEventInfo *eventInfo);

int32_t HksServiceInitReport(const char *funcName, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const HksThreeStageReportInfo *info, HksEventInfo *eventInfo);

int32_t HksThreeStageReport(const char *funcName, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const HksThreeStageReportInfo *info, struct HksOperation *operation);

#ifdef __cplusplus
}
#endif

#endif  // HKS_REPORT_THREE_STAGE_GET_H
