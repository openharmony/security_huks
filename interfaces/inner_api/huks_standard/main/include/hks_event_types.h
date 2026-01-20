/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

/**
 * @file hks_event_types.h
 *
 * @brief Declares Huks event types.
 *
 * @since 22
 */
#ifndef HKS_EVENT_TYPES_H
#define HKS_EVENT_TYPES_H


#ifdef __cplusplus
#ifdef L2_STANDARD

#include <unordered_map>

#include <stdint.h>
#include "hks_type.h"

struct HksEventInfo;


typedef int32_t (*HksParamSetToEventInfo)(const struct HksParamSet *paramSet, struct HksEventInfo *eventInfo);

typedef bool (*HksEventInfoNeedReport)(const struct HksEventInfo *eventInfo);

typedef bool (*HksEventInfoIsEqual)(const struct HksEventInfo *info1, const struct HksEventInfo *info2);

typedef void (*HksEventInfoAdd)(struct HksEventInfo *dst, const struct HksEventInfo *src);

typedef int32_t (*HksEventInfoToMap)(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &eventMap);

struct HksEventProcMap {
    uint32_t eventId;
    HksParamSetToEventInfo eventInfoCreate;
    HksEventInfoNeedReport needReport;
    HksEventInfoIsEqual eventInfoEqual;
    HksEventInfoAdd eventInfoAdd;
    HksEventInfoToMap eventInfoToMap;
};

extern "C" {

int32_t HksRegisterEventProcWrapper(const void *ProcMap);

int32_t HksRegisterEventProcs(const void *procMaps, uint32_t count);

int32_t HksUnregisterEventProcWrapper(uint32_t eventId);

int32_t HksEnqueueEventWrapper(uint32_t eventId, struct HksParamSet *paramSet);
}

#endif // L2_STANDARD
#endif // __cplusplus

#endif // HKS_EVENT_TYPES_H
