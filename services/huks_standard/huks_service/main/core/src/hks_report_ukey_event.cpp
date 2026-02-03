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

#include "hks_report_ukey_event.h"

#include <memory>
#include <string>
#include "hks_error_code.h"
#include "hks_event_info.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type.h"
#include "hks_tag.h"
#include "hks_template.h"
#include "hks_ha_event_report.h"
#include "hks_report_common.h"
#include "hks_type_inner.h"
#include "hks_ha_plugin.h"

using UkeyAddParamFunc = int32_t(*)(const struct UKeyInfo*, const struct HksParamSet *, struct HksParamSet *);

/* register/ungister provider */
static int32_t AddUKeyRegProviderParamSet(const struct UKeyInfo* ukeyInfo, const struct HksParamSet *paramSet,
    struct HksParamSet *reportParamSet)
{
    struct HksParam *abilityParam = nullptr;
    int32_t ret = HksGetParam(paramSet, HKS_EXT_CRYPTO_TAG_ABILITY_NAME, &abilityParam);
    if (ret == HKS_SUCCESS) {
        const struct HksParam paramsAbilityName[] = {
            {
                .tag = HKS_TAG_PARAM5_BUFFER,
                .blob = abilityParam->blob
            }
        };
        ret = HksAddParams(reportParamSet, paramsAbilityName, HKS_ARRAY_SIZE(paramsAbilityName));
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "add params failed");
    };
    const struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM0_UINT32,
            .uint32Param = HKS_EVENT_UKEY_REGISTER_PROVIDER
        }, {
            .tag = HKS_TAG_PARAM4_BUFFER,
            .blob = ukeyInfo->providerName
        }, {
            .tag = HKS_TAG_PARAM1_UINT32,
            .uint32Param = ukeyInfo->operation
        }
    };
    return HksAddParams(reportParamSet, params, HKS_ARRAY_SIZE(params));
}

int32_t HksRegProviderParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER,
        "HksRegProviderParamSetToEventInfo params is null")

    std::unique_ptr<HksEventInfo, decltype(&FreeCommonEventInfo)> tmpEventInfo(eventInfo, FreeCommonEventInfo);
    int32_t ret = GetCommonEventInfo(paramSetIn, eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);

    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM4_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        CopyParamBlobData(&eventInfo->ukeyInfo.providerName, paramToEventInfo);
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM5_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        CopyParamBlobData(&eventInfo->ukeyInfo.abilityName, paramToEventInfo);
    }

    (void)tmpEventInfo.release();
    return HKS_SUCCESS;
}

bool HksRegProviderNeedReport([[maybe_unused]] const struct HksEventInfo *eventInfo)
{
    return true;
}

bool HksRegProviderEventInfoEqual([[maybe_unused]] const struct HksEventInfo *eventInfo1,
    [[maybe_unused]]const struct HksEventInfo *eventInfo2)
{
    return false;
}

void HksEventInfoAddForRegProvider([[maybe_unused]] struct HksEventInfo *dstEventInfo,
    [[maybe_unused]] const struct HksEventInfo *srcEventInfo)
{
    return ;
}

int32_t HksRegProviderEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "eventInfo is null")

    const char *providerName = (eventInfo->ukeyInfo.providerName != nullptr) ?
        eventInfo->ukeyInfo.providerName : EVENT_PROPERTY_UNKNOWN;
    auto ret = reportData.insert_or_assign("provider_name", std::string(providerName));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert providerName failed!");

    const char *abilityName = (eventInfo->ukeyInfo.abilityName != nullptr) ?
        eventInfo->ukeyInfo.abilityName : EVENT_PROPERTY_UNKNOWN;
    ret = reportData.insert_or_assign("ability_name", std::string(abilityName));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert abilityName failed!");

    return HKS_SUCCESS;
}

/* get auth pin state */
static int32_t AddUKeyGetAuthPinStateParamSet(const struct UKeyInfo* ukeyInfo, const struct HksParamSet *paramSet,
    struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    const struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM0_UINT32,
            .uint32Param = HKS_EVENT_UKEY_GET_AUTH_PIN_STATE
        }, {
            .tag = HKS_TAG_PARAM4_BUFFER,
            .blob = ukeyInfo->resourceId
        }, {
            .tag = HKS_TAG_PARAM0_INT32,
            .int32Param = ukeyInfo->state
        }
    };
    return HksAddParams(reportParamSet, params, HKS_ARRAY_SIZE(params));
}

int32_t HksGetAuthPinStateParamSetToEventInfo(const struct HksParamSet *paramSetIn,
    struct HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER,
        "HksGetAuthPinStateParamSetToEventInfo params is null")
    
    std::unique_ptr<HksEventInfo, decltype(&FreeCommonEventInfo)> tmpEventInfo(eventInfo, FreeCommonEventInfo);
    int32_t ret = GetCommonEventInfo(paramSetIn, eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);

    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM4_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        CopyParamBlobData(&eventInfo->ukeyInfo.resourceId, paramToEventInfo);
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM0_INT32, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->ukeyInfo.state = paramToEventInfo->int32Param;
    }

    (void)tmpEventInfo.release();
    return HKS_SUCCESS;
}

bool HksGetAuthPinStateNeedReport(const struct HksEventInfo *eventInfo)
{
    return ((eventInfo != nullptr) && (eventInfo->common.result.code != HKS_SUCCESS));
}

bool HksGetAuthPinStateEventInfoEqual(const struct HksEventInfo *eventInfo1,
    const struct HksEventInfo *eventInfo2)
{
    HKS_IF_TRUE_RETURN(eventInfo1 == nullptr || eventInfo2 == nullptr, false)
    HKS_IF_TRUE_RETURN(eventInfo1->common.eventId != eventInfo2->common.eventId, false);
    HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.resourceId == nullptr || eventInfo2->ukeyInfo.resourceId == nullptr, false)
    return strcmp(eventInfo1->ukeyInfo.resourceId, eventInfo2->ukeyInfo.resourceId) == 0;
}

void HksEventInfoAddForGetAuthPinState(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    if (HksGetAuthPinStateEventInfoEqual(dstEventInfo, srcEventInfo)) {
        dstEventInfo->common.count++;
    }
}

int32_t HksGetAuthPinStateEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "eventInfo is null")

    const char *resourceId = (eventInfo->ukeyInfo.resourceId != nullptr) ?
        eventInfo->ukeyInfo.resourceId : EVENT_PROPERTY_UNKNOWN;
    auto ret = reportData.insert_or_assign("resource_id", std::string(resourceId));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert resourceId failed!");

    ret = reportData.insert_or_assign("state", std::to_string(eventInfo->ukeyInfo.state));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert state failed!");

    return HKS_SUCCESS;
}

/* auth pin */
static int32_t AddUKeyAuthPinParamSet(const struct UKeyInfo* ukeyInfo, const struct HksParamSet *paramSet,
    struct HksParamSet *reportParamSet)
{
    struct HksParam *authPinUidParam = nullptr;
    int32_t ret = HksGetParam(paramSet, HKS_EXT_CRYPTO_TAG_UID, &authPinUidParam);
    if (ret == HKS_SUCCESS) {
        const struct HksParam paramsAuthPin[] = {
            {
                .tag = HKS_TAG_PARAM0_INT32,
                .int32Param = authPinUidParam->int32Param
            }
        };
        ret = HksAddParams(reportParamSet, paramsAuthPin, HKS_ARRAY_SIZE(paramsAuthPin));
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "add params failed");
    };
    const struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM0_UINT32,
            .uint32Param = HKS_EVENT_UKEY_AUTH_PIN
        }, {
            .tag = HKS_TAG_PARAM4_BUFFER,
            .blob = ukeyInfo->resourceId
        }
    };
    return HksAddParams(reportParamSet, params, HKS_ARRAY_SIZE(params));
}

int32_t HksAuthPinParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER,
        "HksAuthPinParamSetToEventInfo params is null")

    std::unique_ptr<HksEventInfo, decltype(&FreeCommonEventInfo)> tmpEventInfo(eventInfo, FreeCommonEventInfo);
    int32_t ret = GetCommonEventInfo(paramSetIn, eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);

    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM4_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        CopyParamBlobData(&eventInfo->ukeyInfo.resourceId, paramToEventInfo);
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM0_INT32, &paramToEventInfo) == HKS_SUCCESS) {
        eventInfo->ukeyInfo.callAuthUid = paramToEventInfo->int32Param;
    }

    (void)tmpEventInfo.release();
    return HKS_SUCCESS;
}

bool HksAuthPinNeedReport(const struct HksEventInfo *eventInfo)
{
    return ((eventInfo != nullptr) && (eventInfo->common.result.code != HKS_SUCCESS));
}

bool HksAuthPinEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    HKS_IF_TRUE_RETURN(eventInfo1 == nullptr || eventInfo2 == nullptr, false)
    HKS_IF_TRUE_RETURN(eventInfo1->common.eventId != eventInfo2->common.eventId, false)
    HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.resourceId == nullptr || eventInfo2->ukeyInfo.resourceId == nullptr, false)
    return strcmp(eventInfo1->ukeyInfo.resourceId, eventInfo2->ukeyInfo.resourceId) == 0;
}

void HksEventInfoAddForAuthPin(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    if (HksAuthPinEventInfoEqual(dstEventInfo, srcEventInfo)) {
        dstEventInfo->common.count++;
    }
}

int32_t HksAuthPinEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "eventInfo is null")

    const char *resourceId = (eventInfo->ukeyInfo.resourceId != nullptr) ?
        eventInfo->ukeyInfo.resourceId : EVENT_PROPERTY_UNKNOWN;
    auto ret = reportData.insert_or_assign("resource_id", std::string(resourceId));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert resourceId failed!");

    ret = reportData.insert_or_assign("call_auth_uid", std::to_string(eventInfo->ukeyInfo.callAuthUid));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert callAuthUid failed!");

    return HKS_SUCCESS;
}

/* operator remote handle */
static int32_t AddUKeyRemoteHandleParamSet(const struct UKeyInfo* ukeyInfo, const struct HksParamSet *paramSet,
    struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    const struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM0_UINT32,
            .uint32Param = HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE
        }, {
            .tag = HKS_TAG_PARAM4_BUFFER,
            .blob = ukeyInfo->resourceId
        }, {
            .tag = HKS_TAG_PARAM1_UINT32,
            .uint32Param = ukeyInfo->operation
        }
    };
    return HksAddParams(reportParamSet, params, HKS_ARRAY_SIZE(params));
}

int32_t HksRemoteHandleParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER,
        "HksRemoteHandleParamSetToEventInfo params is null")

    std::unique_ptr<HksEventInfo, decltype(&FreeCommonEventInfo)> tmpEventInfo(eventInfo, FreeCommonEventInfo);
    int32_t ret = GetCommonEventInfo(paramSetIn, eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);

    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM4_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        CopyParamBlobData(&eventInfo->ukeyInfo.resourceId, paramToEventInfo);
    }

    (void)tmpEventInfo.release();
    return HKS_SUCCESS;
}

bool HksRemoteHandleNeedReport(const struct HksEventInfo *eventInfo)
{
    return ((eventInfo != nullptr) && (eventInfo->common.result.code != HKS_SUCCESS));
}

bool HksRemoteHandleEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    HKS_IF_TRUE_RETURN(eventInfo1 == nullptr || eventInfo2 == nullptr, false)
    HKS_IF_TRUE_RETURN(eventInfo1->common.eventId != eventInfo2->common.eventId, false)
    HKS_IF_TRUE_RETURN(eventInfo1->common.operation != eventInfo2->common.operation, false)
    HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.resourceId == nullptr || eventInfo2->ukeyInfo.resourceId == nullptr, false)
    return strcmp(eventInfo1->ukeyInfo.resourceId, eventInfo2->ukeyInfo.resourceId) == 0;
}

void HksEventInfoAddForRemoteHandle(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    if (HksRemoteHandleEventInfoEqual(dstEventInfo, srcEventInfo)) {
        dstEventInfo->common.count++;
    }
}

int32_t HksRemoteHandleEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "eventInfo is null")

    const char *resourceId = (eventInfo->ukeyInfo.resourceId != nullptr) ?
        eventInfo->ukeyInfo.resourceId : EVENT_PROPERTY_UNKNOWN;
    auto ret = reportData.insert_or_assign("resource_id", std::string(resourceId));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert resourceId failed!");

    return HKS_SUCCESS;
}

/* export provider certificates */
static int32_t AddUKeyExportProviderCertParamSet(const struct UKeyInfo* ukeyInfo, const struct HksParamSet *paramSet,
    struct HksParamSet *reportParamSet)
{
    struct HksParam *purposeParam = nullptr;
    int32_t ret = HksGetParam(paramSet, HKS_EXT_CRYPTO_TAG_PURPOSE, &purposeParam);
    if (ret == HKS_SUCCESS) {
        const struct HksParam paramsPurpose[] = {
            {
                .tag = HKS_TAG_PARAM0_INT32,
                .int32Param = purposeParam->int32Param
            }
        };
        ret = HksAddParams(reportParamSet, paramsPurpose, HKS_ARRAY_SIZE(paramsPurpose));
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "add params failed");
    };
    const struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM0_UINT32,
            .uint32Param = HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT
        }, {
            .tag = HKS_TAG_PARAM4_BUFFER,
            .blob = ukeyInfo->providerName
        }
    };
    return HksAddParams(reportParamSet, params, HKS_ARRAY_SIZE(params));
}

int32_t HksExportProviderCertParamSetToEventInfo(const struct HksParamSet *paramSetIn,
    struct HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER,
        "HksExportProviderCertParamSetToEventInfo params is null")
    
    std::unique_ptr<HksEventInfo, decltype(&FreeCommonEventInfo)> tmpEventInfo(eventInfo, FreeCommonEventInfo);
    int32_t ret = GetCommonEventInfo(paramSetIn, eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);

    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM4_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        CopyParamBlobData(&eventInfo->ukeyInfo.providerName, paramToEventInfo);
    }

    (void)tmpEventInfo.release();
    return HKS_SUCCESS;
}

bool HksExportProviderCertNeedReport(const struct HksEventInfo *eventInfo)
{
    return ((eventInfo != nullptr) && (eventInfo->common.result.code != HKS_SUCCESS));
}

bool HksExportProviderCertEventInfoEqual(const struct HksEventInfo *eventInfo1,
    const struct HksEventInfo *eventInfo2)
{
    HKS_IF_TRUE_RETURN(eventInfo1 == nullptr || eventInfo2 == nullptr, false)
    HKS_IF_TRUE_RETURN(eventInfo1->common.eventId != eventInfo2->common.eventId, false)
    HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.purpose != eventInfo2->ukeyInfo.purpose, false)
    HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.providerName == nullptr || eventInfo2->ukeyInfo.providerName == nullptr,
        false)
    return strcmp(eventInfo1->ukeyInfo.providerName, eventInfo2->ukeyInfo.providerName) == 0;
}

void HksEventInfoAddForExportProviderCert(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    if (HksExportProviderCertEventInfoEqual(dstEventInfo, srcEventInfo)) {
        dstEventInfo->common.count++;
    }
}

int32_t HksExportProviderCertEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "eventInfo is null")

    const char *providerName = (eventInfo->ukeyInfo.providerName != nullptr) ?
        eventInfo->ukeyInfo.providerName : EVENT_PROPERTY_UNKNOWN;
    auto ret = reportData.insert_or_assign("provider_name", std::string(providerName));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert providerName failed!");

    ret = reportData.insert_or_assign("purpose", std::to_string(eventInfo->ukeyInfo.purpose));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert purpose failed!");

    return HKS_SUCCESS;
}

/* export certificates */
static int32_t AddUKeyExportCertParamSet(const struct UKeyInfo* ukeyInfo, const struct HksParamSet *paramSet,
    struct HksParamSet *reportParamSet)
{
    struct HksParam *purposeParam = nullptr;
    int32_t ret = HksGetParam(paramSet, HKS_EXT_CRYPTO_TAG_PURPOSE, &purposeParam);
    if (ret == HKS_SUCCESS) {
        const struct HksParam paramsPurpose[] = {
            {
                .tag = HKS_TAG_PARAM0_INT32,
                .int32Param = purposeParam->int32Param
            }
        };
        ret = HksAddParams(reportParamSet, paramsPurpose, HKS_ARRAY_SIZE(paramsPurpose));
        HKS_IF_NOT_SUCC_LOGE_RETURN(ret, ret, "add params failed");
    };
    const struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM0_UINT32,
            .uint32Param = HKS_EVENT_UKEY_EXPORT_CERT
        }, {
            .tag = HKS_TAG_PARAM4_BUFFER,
            .blob = ukeyInfo->resourceId
        }
    };
    return HksAddParams(reportParamSet, params, HKS_ARRAY_SIZE(params));
}

int32_t HksExportCertParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER,
        "HksExportCertParamSetToEventInfo params is null")

    std::unique_ptr<HksEventInfo, decltype(&FreeCommonEventInfo)> tmpEventInfo(eventInfo, FreeCommonEventInfo);
    int32_t ret = GetCommonEventInfo(paramSetIn, eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);

    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM4_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        CopyParamBlobData(&eventInfo->ukeyInfo.resourceId, paramToEventInfo);
    }

    (void)tmpEventInfo.release();
    return HKS_SUCCESS;
}

bool HksExportCertNeedReport(const struct HksEventInfo *eventInfo)
{
    return ((eventInfo != nullptr) && (eventInfo->common.result.code != HKS_SUCCESS));
}

bool HksExportCertEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    HKS_IF_TRUE_RETURN(eventInfo1 == nullptr || eventInfo2 == nullptr, false)
    HKS_IF_TRUE_RETURN(eventInfo1->common.eventId != eventInfo2->common.eventId, false)
    HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.purpose != eventInfo2->ukeyInfo.purpose, false)
    HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.resourceId == nullptr || eventInfo2->ukeyInfo.resourceId == nullptr, false)
    return strcmp(eventInfo1->ukeyInfo.resourceId, eventInfo2->ukeyInfo.resourceId) == 0;
}

void HksEventInfoAddForExportCert(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    if (HksExportCertEventInfoEqual(dstEventInfo, srcEventInfo)) {
        dstEventInfo->common.count++;
    }
}

int32_t HksExportCertEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "eventInfo is null")

    const char *resourceId = (eventInfo->ukeyInfo.resourceId != nullptr) ?
        eventInfo->ukeyInfo.resourceId : EVENT_PROPERTY_UNKNOWN;
    auto ret = reportData.insert_or_assign("resource_id", std::string(resourceId));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert resourceId failed!");

    ret = reportData.insert_or_assign("purpose", std::to_string(eventInfo->ukeyInfo.purpose));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert purpose failed!");

    return HKS_SUCCESS;
}

/* get remote property */
static int32_t AddUKeyGetPropertyParamSet(const struct UKeyInfo* ukeyInfo, const struct HksParamSet *paramSet,
    struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    const struct HksParam params[] = {
        {
            .tag = HKS_TAG_PARAM0_UINT32,
            .uint32Param = HKS_EVENT_UKSY_GET_REMOTE_PROPERTY
        }, {
            .tag = HKS_TAG_PARAM4_BUFFER,
            .blob = ukeyInfo->resourceId
        }, {
            .tag = HKS_TAG_PARAM5_BUFFER,
            .blob = ukeyInfo->propertyId
        }
    };
    return HksAddParams(reportParamSet, params, HKS_ARRAY_SIZE(params));
}

int32_t HksGetPropertyParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER,
        "HksGetPropertyParamSetToEventInfo params is null")

    std::unique_ptr<HksEventInfo, decltype(&FreeCommonEventInfo)> tmpEventInfo(eventInfo, FreeCommonEventInfo);
    int32_t ret = GetCommonEventInfo(paramSetIn, eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);

    struct HksParam *paramToEventInfo = nullptr;
    if (HksGetParam(paramSetIn, HKS_TAG_PARAM4_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        CopyParamBlobData(&eventInfo->ukeyInfo.resourceId, paramToEventInfo);
    }

    if (HksGetParam(paramSetIn, HKS_TAG_PARAM5_BUFFER, &paramToEventInfo) == HKS_SUCCESS) {
        CopyParamBlobData(&eventInfo->ukeyInfo.propertyId, paramToEventInfo);
    }

    (void)tmpEventInfo.release();
    return HKS_SUCCESS;
}

bool HksGetPropertyNeedReport(const struct HksEventInfo *eventInfo)
{
    return (eventInfo != nullptr) && ((eventInfo->common.result.code != HKS_SUCCESS) ||
        eventInfo->common.statInfo.totalCost > UKEY_TIMEOUT);
}

bool HksGetPropertyEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    HKS_IF_TRUE_RETURN(eventInfo1 == nullptr || eventInfo2 == nullptr, false)
    HKS_IF_TRUE_RETURN(eventInfo1->common.eventId != eventInfo2->common.eventId, false)
    HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.resourceId == nullptr || eventInfo2->ukeyInfo.resourceId == nullptr, false)
    HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.propertyId == nullptr || eventInfo2->ukeyInfo.propertyId == nullptr, false)
    return strcmp(eventInfo1->ukeyInfo.resourceId, eventInfo2->ukeyInfo.resourceId) == 0 &&
        strcmp(eventInfo1->ukeyInfo.propertyId, eventInfo2->ukeyInfo.propertyId) == 0;
}

void HksEventInfoAddForGetProperty(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    if (HksGetPropertyEventInfoEqual(dstEventInfo, srcEventInfo)) {
        dstEventInfo->common.count++;
    }
}

int32_t HksGetPropertyEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "eventInfo is null")

    const char *resourceId = (eventInfo->ukeyInfo.resourceId != nullptr) ?
        eventInfo->ukeyInfo.resourceId : EVENT_PROPERTY_UNKNOWN;
    auto ret = reportData.insert_or_assign("resource_id", std::string(resourceId));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert resourceId failed!");

    const char *propertyId = (eventInfo->ukeyInfo.propertyId != nullptr) ?
        eventInfo->ukeyInfo.propertyId : EVENT_PROPERTY_UNKNOWN;
    ret = reportData.insert_or_assign("property_id", std::string(propertyId));
    HKS_IF_NOT_TRUE_LOGI_RETURN(ret.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert propertyId failed!");

    return HKS_SUCCESS;
}

static constexpr UkeyAddParamFunc UKEY_ADD_PARAM_FUNC[] = {
    AddUKeyRegProviderParamSet,
    AddUKeyGetAuthPinStateParamSet,
    AddUKeyAuthPinParamSet,
    AddUKeyRemoteHandleParamSet,
    AddUKeyExportProviderCertParamSet,
    AddUKeyExportCertParamSet,
    AddUKeyGetPropertyParamSet
};

static constexpr uint32_t GetUKeyReportIndex(uint32_t eventId)
{
    return eventId - HKS_EVENT_UKEY_REGISTER_PROVIDER;
}

int32_t ReportUKeyEvent(const struct UKeyInfo* ukeyInfo, const char *funcName, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet, const struct UKeyCommonInfo *ukeyCommon)
{
    if (ukeyInfo == nullptr || funcName == nullptr || processInfo == nullptr ||
        paramSet == nullptr || ukeyCommon == nullptr) {
        HKS_LOG_E("input parameter is invalid");
        return HKS_FAILURE;
    }
    if (!IF_UKEY_EVENT(ukeyInfo->eventId)) {
        HKS_LOG_E("report event %" LOG_PUBLIC "u is invalid", ukeyInfo->eventId);
        return HKS_FAILURE;
    }
    struct HksParamSet *reportParamSet = nullptr;
    int32_t ret = HKS_FAILURE;
    do {
        ret = HksInitParamSet(&reportParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "init report paramset fail")

        ret = UKEY_ADD_PARAM_FUNC[GetUKeyReportIndex(ukeyInfo->eventId)](ukeyInfo, paramSet, reportParamSet);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add param set failed")

        ret = AddTimeCost(reportParamSet, ukeyCommon->startTime);
        HKS_IF_NOT_SUCC_LOGE_BREAK(ret, "add time failed")

        (void)ConstructReportParamSet(funcName, processInfo, ukeyCommon->returnCode, &reportParamSet);
        HksEventReport(funcName, processInfo, paramSet, reportParamSet, ukeyCommon->returnCode);
        ret = HKS_SUCCESS;
    } while (0);
    DeConstructReportParamSet(&reportParamSet);
    return ret;
}