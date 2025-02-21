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

#include "hks_report_three_stage.h"

#include <cstdint>
#include <string>
#include <unordered_map>

#include "hks_event_info.h"
#include "hks_report_common.h"
#include "hks_report_three_stage_build.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"

static bool NeedReportCommon(const HksEventInfo *eventInfo)
{
    if (eventInfo == nullptr) {
        HKS_LOG_I("paramset or eventInfo is null");
        return false;
    }
    return eventInfo->common.result.code != HKS_SUCCESS;
}

static bool CryptoInfoIsEqual(const HksEventInfo *info1, const HksEventInfo *info2)
{
    if (CheckEventCommon(info1, info2) == false) {
        return false;
    }
    return (info1->cryptoInfo.keyInfo.alg == info2->cryptoInfo.keyInfo.alg) &&
        (info1->common.operation == info2->common.operation);
}

// crypto
int32_t HksParamSetToEventInfoCrypto(const struct HksParamSet *paramSet, HksEventInfo *eventInfo)
{
    return BuildCommonInfo(paramSet, eventInfo);
}

bool HksEventInfoNeedReportCrypto(const HksEventInfo *eventInfo)
{
    return NeedReportCommon(eventInfo);
}

bool HksEventInfoIsEqualCrypto(const HksEventInfo *info1, const HksEventInfo *info2)
{
    return CryptoInfoIsEqual(info1, info2);
}

void HksEventInfoAddCrypto(HksEventInfo *info1, const HksEventInfo *info2)
{
    AddEventInfoCommon(info1, info2);
}

int32_t HksEventInfoToMapCrypto(const HksEventInfo *info, std::unordered_map<std::string, std::string>& map)
{
    HKS_IF_NULL_LOGI_RETURN(info, HKS_ERROR_NULL_POINTER, "eventinfo is null")
    KeyInfoToMap(&(info->cryptoInfo.keyInfo), map);
    KeyAccessInfoToMap(&(info->cryptoInfo.accessCtlInfo), map);
    CryptoInfoToMap(&(info->cryptoInfo), map);
    return HKS_SUCCESS;
}

// agree derive
int32_t HksParamSetToEventInfoAgreeDerive(const struct HksParamSet *paramSet, HksEventInfo *eventInfo)
{
    return BuildCommonInfo(paramSet, eventInfo);
}

bool HksEventInfoNeedReportAgreeDerive(const HksEventInfo *eventInfo)
{
    return NeedReportCommon(eventInfo);
}

bool HksEventInfoIsEqualAgreeDerive(const HksEventInfo *info1, const HksEventInfo *info2)
{
    return CheckEventCommonAndKey(info1, info2);
}

void HksEventInfoAddAgreeDerive(HksEventInfo *info1, const HksEventInfo *info2)
{
    AddEventInfoCommon(info1, info2);
}

int32_t HksEventInfoToMapAgreeDerive(const HksEventInfo *info, std::unordered_map<std::string, std::string>& map)
{
    HKS_IF_NULL_LOGI_RETURN(info, HKS_ERROR_NULL_POINTER, "eventinfo is null")
    KeyInfoToMap(&(info->agreeDeriveInfo.keyInfo), map);
    KeyAccessInfoToMap(&(info->agreeDeriveInfo.accessCtlInfo), map);
    AgreeDeriveInfoToMap(&(info->agreeDeriveInfo), map);
    return HKS_SUCCESS;
}

// MAC
int32_t HksParamSetToEventInfoMac(const struct HksParamSet *paramSet, HksEventInfo *eventInfo)
{
    return BuildCommonInfo(paramSet, eventInfo);
}

bool HksEventInfoNeedReportMac(const HksEventInfo *eventInfo)
{
    return NeedReportCommon(eventInfo);
}

bool HksEventInfoIsEqualMac(const HksEventInfo *info1, const HksEventInfo *info2)
{
    return CryptoInfoIsEqual(info1, info2);
}

void HksEventInfoAddMac(HksEventInfo *info1, const HksEventInfo *info2)
{
    AddEventInfoCommon(info1, info2);
}

int32_t HksEventInfoToMapMac(const HksEventInfo *info, std::unordered_map<std::string, std::string>& map)
{
    HKS_IF_NULL_LOGI_RETURN(info, HKS_ERROR_NULL_POINTER, "eventinfo is null")
    KeyInfoToMap(&(info->macInfo.keyInfo), map);
    KeyAccessInfoToMap(&(info->macInfo.accessCtlInfo), map);
    return HKS_SUCCESS;
}

// attest
int32_t HksParamSetToEventInfoAttest(const struct HksParamSet *paramSet, HksEventInfo *eventInfo)
{
    return BuildCommonInfo(paramSet, eventInfo);
}

bool HksEventInfoNeedReportAttest(const HksEventInfo *eventInfo)
{
    return NeedReportCommon(eventInfo);
}

bool HksEventInfoIsEqualAttest(const HksEventInfo *info1, const HksEventInfo *info2)
{
    if (CheckEventCommon(info1, info2) == false) {
        return false;
    }
    return (info1->attestInfo.keyInfo.alg == info2->attestInfo.keyInfo.alg) &&
        (info1->attestInfo.isAnonymous == info2->attestInfo.isAnonymous);
}

void HksEventInfoAddAttest(HksEventInfo *info1, const HksEventInfo *info2)
{
    AddEventInfoCommon(info1, info2);
}

int32_t HksEventInfoToMapAttest(const HksEventInfo *info, std::unordered_map<std::string, std::string>& map)
{
    HKS_IF_NULL_LOGI_RETURN(info, HKS_ERROR_NULL_POINTER, "eventinfo is null")
    KeyInfoToMap(&(info->attestInfo.keyInfo), map);
    AttestInfoToMap(&(info->attestInfo), map);
    return HKS_SUCCESS;
}
