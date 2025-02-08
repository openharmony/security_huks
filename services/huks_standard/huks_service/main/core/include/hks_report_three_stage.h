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

#ifndef HKS_REPORT_THREE_STAGE_H
#define HKS_REPORT_THREE_STAGE_H

#include <stdint.h>
#include <string>
#include <unordered_map>

#include "hks_event_info.h"
#include "hks_type.h"

// crypto
int32_t HksParamSetToEventInfoCrypto(const struct HksParamSet *paramSet, HksEventInfo *eventInfo);

bool HksEventInfoNeedReportCrypto(const HksEventInfo *eventInfo);

bool HksEventInfoIsEqualCrypto(const HksEventInfo *info1, const HksEventInfo *info2);

void HksEventInfoAddCrypto(HksEventInfo *info1, const HksEventInfo *info2);

int32_t HksEventInfoToMapCrypto(const HksEventInfo *info, std::unordered_map<std::string, std::string>& map);

// agree derive
int32_t HksParamSetToEventInfoAgreeDerive(const struct HksParamSet *paramSet, HksEventInfo *eventInfo);

bool HksEventInfoNeedReportAgreeDerive(const HksEventInfo *eventInfo);

bool HksEventInfoIsEqualAgreeDerive(const HksEventInfo *info1, const HksEventInfo *info2);

void HksEventInfoAddAgreeDerive(HksEventInfo *info1, const HksEventInfo *info2);

int32_t HksEventInfoToMapAgreeDerive(const HksEventInfo *info, std::unordered_map<std::string, std::string>& map);

// MAC
int32_t HksParamSetToEventInfoMac(const struct HksParamSet *paramSet, HksEventInfo *eventInfo);

bool HksEventInfoNeedReportMac(const HksEventInfo *eventInfo);

bool HksEventInfoIsEqualMac(const HksEventInfo *info1, const HksEventInfo *info2);

void HksEventInfoAddMac(HksEventInfo *info1, const HksEventInfo *info2);

int32_t HksEventInfoToMapMac(const HksEventInfo *info, std::unordered_map<std::string, std::string>& map);

// attest
int32_t HksParamSetToEventInfoAttest(const struct HksParamSet *paramSet, HksEventInfo *eventInfo);

bool HksEventInfoNeedReportAttest(const HksEventInfo *eventInfo);

bool HksEventInfoIsEqualAttest(const HksEventInfo *info1, const HksEventInfo *info2);

void HksEventInfoAddAttest(HksEventInfo *info1, const HksEventInfo *info2);

int32_t HksEventInfoToMapAttest(const HksEventInfo *info, std::unordered_map<std::string, std::string>& map);

#endif  // HKS_REPORT_THREE_STAGE_H
