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

#include "hks_error_code.h"
#include "hks_event_info.h"
#include "hks_report_common.h"
#include "hks_report_three_stage_build.h"
#include "hks_template.h"
#include "hks_type.h"
#include "hks_type_enum.h"

static bool NeedReportCommon(const HksEventInfo *eventInfo)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, false, "paramset or eventInfo is null")
    int32_t code = eventInfo->common.result.code;
    if (code == HKS_ERROR_NOT_EXIST || code == HKS_ERROR_INVALID_ARGUMENT) {
        return false;
    }
    return code != HKS_SUCCESS;
}

static bool CryptoInfoIsEqual(const HksEventInfo *info1, const HksEventInfo *info2)
{
    HKS_IF_TRUE_RETURN(info1 == nullptr || info2 == nullptr, false)
    HKS_IF_TRUE_RETURN(info1->common.eventId != info2->common.eventId, false)
    HKS_IF_TRUE_RETURN(info1->common.result.code != info2->common.result.code, false)

    int32_t code = info1->common.result.code;
    if (code == HKS_ERROR_NOT_EXIST) {
        // -13: key not exist, aggregate by alg + operation (no callerInfo, no aliasHash)
        return (info1->cryptoInfo.keyInfo.alg == info2->cryptoInfo.keyInfo.alg) &&
            (info1->common.operation == info2->common.operation);
    }
    if (code == HKS_ERROR_INVALID_ARGUMENT) {
        // -3: aggregate by same caller + same key (callerInfo + aliasHash + alg)
        HKS_IF_TRUE_RETURN(info1->common.callerInfo.name == nullptr ||
            info2->common.callerInfo.name == nullptr, false)
        HKS_IF_TRUE_RETURN(strcmp(info1->common.callerInfo.name, info2->common.callerInfo.name) != 0, false)
        return (info1->cryptoInfo.keyInfo.alg == info2->cryptoInfo.keyInfo.alg) &&
            (info1->cryptoInfo.keyInfo.aliasHash == info2->cryptoInfo.keyInfo.aliasHash);
    }
    // Other errors: keep callerInfo + alg + operation
    HKS_IF_TRUE_RETURN(info1->common.callerInfo.name == nullptr ||
        info2->common.callerInfo.name == nullptr, false)
    HKS_IF_TRUE_RETURN(strcmp(info1->common.callerInfo.name, info2->common.callerInfo.name) != 0, false)
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
    HKS_IF_NULL_LOGI_RETURN(eventInfo, false, "eventInfo is null")
    if (eventInfo->common.result.code == HUKS_ERR_CODE_EXTERNAL_ERROR) {
        return false;
    }
    return NeedReportCommon(eventInfo);
}

bool HksEventInfoIsEqualAttest(const HksEventInfo *info1, const HksEventInfo *info2)
{
    HKS_IF_NOT_TRUE_RETURN(CheckEventCommon(info1, info2), false);
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
