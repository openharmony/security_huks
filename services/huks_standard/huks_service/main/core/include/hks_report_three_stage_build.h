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

#ifndef HKS_REPORT_THREE_STAGE_BUILD_H
#define HKS_REPORT_THREE_STAGE_BUILD_H

#include <stdint.h>
#include <string>
#include <unordered_map>

#include "hks_event_info.h"
#include "hks_type.h"

int32_t BuildCommonInfo(const struct HksParamSet *paramSet, struct HksEventInfo *eventInfo);

// check uid, operation, userId
bool CheckEventCommon(const struct HksEventInfo *info1, const struct HksEventInfo *info2);

// add count, dataLen, totalCost
void AddEventInfoCommon(HksEventInfo *info1, const HksEventInfo *info2);

void KeyInfoToMap(const HksEventKeyInfo *keyInfo, std::unordered_map<std::string, std::string>& map);

void KeyAccessInfoToMap(const HksEventKeyAccessInfo *accessInfo, std::unordered_map<std::string, std::string>& map);

void CryptoInfoToMap(const HksEventCryptoInfo *cryptoInfo, std::unordered_map<std::string, std::string>& map);

void AgreeDeriveInfoToMap(const HksEventAgreeDeriveInfo *info, std::unordered_map<std::string, std::string>& map);

void AttestInfoToMap(const HksEventAttestInfo *attestInfo, std::unordered_map<std::string, std::string>& map);

#endif  // HKS_REPORT_THREE_STAGE_BUILD_H
