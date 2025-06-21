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

#ifndef HKS_REPORT_COMMON_H
#define HKS_REPORT_COMMON_H

#include "hks_plugin_def.h"
#include "hks_report.h"
#include "hks_template.h"
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

#define HASH_SHA256_SIZE 256
#define KEYALIAS_HASH_SHA256_SIZE 1
#define KEY_HASH_SHA256_SIZE 2

int32_t AddKeyHash(struct HksParamSet *paramSetOut, const struct HksBlob *keyIn);

int32_t AddKeyAliasHash(struct HksParamSet *paramSetOut, const struct HksBlob *keyAlias, enum HksInnerTag paramTag);

int32_t AddTimeCost(struct HksParamSet *paramSetOut, uint64_t startTime);

int32_t PreAddCommonInfo(struct HksParamSet *paramSetOut, const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, uint64_t startTime);

int32_t ConstructReportParamSet(const char *funcName, const struct HksProcessInfo *processInfo,
    int32_t errorCode, struct HksParamSet **reportParamSet);

void DeConstructReportParamSet(struct HksParamSet **paramSet);

void FreeEventInfoSpecificPtr(struct HksEventInfo *eventInfo);

bool CheckEventCommon(const struct HksEventInfo *info1, const struct HksEventInfo *info2);

bool CheckEventCommonAndKey(const struct HksEventInfo *info1, const struct HksEventInfo *info2);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

static inline uint32_t HksGetHash(const struct HksBlob *blob)
{
    if (CheckBlob(blob) != HKS_SUCCESS) {
        return 0;
    }
    std::hash<std::string> hasher;
    std::string data(reinterpret_cast<char *>(blob->data), blob->size);
    return static_cast<uint32_t>(hasher(data));
}

int32_t ReportGetCallerName(std::string &callerName);

int32_t GetCommonEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo);

int32_t GetEventKeyInfo(const struct HksParamSet *paramSetIn, struct HksEventKeyInfo *keyInfo);

int32_t GetEventKeyAccessInfo(const struct HksParamSet *paramSetIn, struct HksEventKeyAccessInfo *keyAccessInfo);

std::pair<std::unordered_map<std::string, std::string>::iterator, bool> EventInfoToMapKeyInfo(
    const struct HksEventKeyInfo *eventKeyInfo, std::unordered_map<std::string, std::string> &reportData);

std::pair<std::unordered_map<std::string, std::string>::iterator, bool> EventInfoToMapKeyAccessInfo(
    const struct HksEventKeyAccessInfo *eventKeyAccessInfo, std::unordered_map<std::string, std::string> &reportData);

void CopyParamBlobData(char **dst, const struct HksParam *param);

#endif

#endif  // HKS_REPORT_COMMON_H
