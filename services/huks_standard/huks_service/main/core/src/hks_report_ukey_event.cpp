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

// Field bitmap definitions
#define FLAG_RESOURCE_ID      (1U << 0)
#define FLAG_PROVIDER_NAME    (1U << 1)
#define FLAG_ABILITY_NAME     (1U << 2)
#define FLAG_EXT_BUNDLE_NAME  (1U << 3)
#define FLAG_ALG              (1U << 4)
#define FLAG_PURPOSE          (1U << 5)
#define FLAG_DETAIL_ERRCODE   (1U << 6)
#define FLAG_HANDLE           (1U << 7)
#define FLAG_EXTRA_DATA       (1U << 8)
#define FLAG_PROPERTY_ID      (1U << 9)
#define FLAG_STATE            (1U << 10)
#define FLAG_OPERATION        (1U << 11)
#define FLAG_CALL_AUTH_UID    (1U << 12)

// Compare type definitions
#define COMPARE_RESOURCE_ID   1
#define COMPARE_HANDLE        2
#define COMPARE_PROPERTY_ID   3
#define COMPARE_PROVIDER_NAME 4
#define COMPARE_NONE          0

// Field type definitions
#define FIELD_TYPE_BUFFER     1
#define FIELD_TYPE_UINT32     2
#define FIELD_TYPE_INT32      3

// Field mapping structure
typedef struct {
    uint32_t flag;
    uint32_t tag;
    const char* name;
    uint8_t type;
} FieldMapping;

// Field mapping table
static const FieldMapping FIELD_MAPPINGS[] = {
    {FLAG_RESOURCE_ID,      HKS_TAG_PARAM4_BUFFER,  "resource_id",      FIELD_TYPE_BUFFER},
    {FLAG_PROVIDER_NAME,    HKS_TAG_PARAM5_BUFFER,  "provider_name",    FIELD_TYPE_BUFFER},
    {FLAG_ABILITY_NAME,     HKS_TAG_PARAM6_BUFFER,  "ability_name",     FIELD_TYPE_BUFFER},
    {FLAG_EXT_BUNDLE_NAME,  HKS_TAG_PARAM7_BUFFER,  "extBundleName",    FIELD_TYPE_BUFFER},
    {FLAG_ALG,              HKS_TAG_PARAM1_UINT32,  "alg",              FIELD_TYPE_UINT32},
    {FLAG_PURPOSE,          HKS_TAG_PARAM2_UINT32,  "purpose",          FIELD_TYPE_UINT32},
    {FLAG_DETAIL_ERRCODE,   HKS_TAG_PARAM3_UINT32,  "detailErrcode",    FIELD_TYPE_UINT32},
    {FLAG_HANDLE,           HKS_TAG_PARAM8_BUFFER,  "handle_id",        FIELD_TYPE_BUFFER},
    {FLAG_EXTRA_DATA,       HKS_TAG_PARAM9_BUFFER,  "extraData",        FIELD_TYPE_BUFFER},
    {FLAG_PROPERTY_ID,      HKS_TAG_PARAM10_BUFFER, "property_id",      FIELD_TYPE_BUFFER},
    {FLAG_STATE,            HKS_TAG_PARAM0_INT32,   "state",            FIELD_TYPE_INT32},
    {FLAG_OPERATION,        HKS_TAG_PARAM1_UINT32,  "operation",        FIELD_TYPE_UINT32},
    {FLAG_CALL_AUTH_UID,    HKS_TAG_PARAM0_INT32,   "call_auth_uid",    FIELD_TYPE_INT32},
};

// Event configuration structure
typedef struct {
    uint32_t eventId;
    uint32_t fieldFlags;
    uint8_t compareType;
} UKeyEventConfig;

// Event configuration table (18 events)
static const UKeyEventConfig UKEY_EVENT_CONFIGS[] = {
    {HKS_EVENT_UKEY_REGISTER_PROVIDER,
        FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME | FLAG_DETAIL_ERRCODE,
        COMPARE_NONE},
    {HKS_EVENT_UKEY_GET_AUTH_PIN_STATE,
        FLAG_RESOURCE_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME |
        FLAG_DETAIL_ERRCODE | FLAG_STATE,
        COMPARE_RESOURCE_ID},
    {HKS_EVENT_UKEY_AUTH_PIN,
        FLAG_RESOURCE_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME |
        FLAG_DETAIL_ERRCODE | FLAG_CALL_AUTH_UID,
        COMPARE_RESOURCE_ID},
    {HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE,
        FLAG_RESOURCE_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME |
        FLAG_DETAIL_ERRCODE | FLAG_OPERATION,
        COMPARE_RESOURCE_ID},
    {HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT,
        FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME | FLAG_DETAIL_ERRCODE | FLAG_PURPOSE,
        COMPARE_PROVIDER_NAME},
    {HKS_EVENT_UKEY_EXPORT_CERT,
        FLAG_RESOURCE_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME |
        FLAG_DETAIL_ERRCODE | FLAG_PURPOSE,
        COMPARE_RESOURCE_ID},
    {HKS_EVENT_UKSY_GET_REMOTE_PROPERTY,
        FLAG_RESOURCE_ID | FLAG_PROPERTY_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME |
        FLAG_EXT_BUNDLE_NAME | FLAG_DETAIL_ERRCODE,
        COMPARE_RESOURCE_ID},
    {HKS_EVENT_UKEY_IMPORT_CERT,
        FLAG_RESOURCE_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME |
        FLAG_DETAIL_ERRCODE,
        COMPARE_RESOURCE_ID},
    {HKS_EVENT_UKEY_GET_RESOURCE_ID,
        FLAG_RESOURCE_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME |
        FLAG_DETAIL_ERRCODE | FLAG_EXTRA_DATA,
        COMPARE_RESOURCE_ID},
    {HKS_EVENT_UKEY_CLEAR_PIN_STATE,
        FLAG_RESOURCE_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME |
        FLAG_DETAIL_ERRCODE,
        COMPARE_RESOURCE_ID},
    {HKS_EVENT_UKEY_INIT_SESSION,
        FLAG_RESOURCE_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME |
        FLAG_ALG | FLAG_PURPOSE | FLAG_DETAIL_ERRCODE | FLAG_HANDLE | FLAG_EXTRA_DATA,
        COMPARE_HANDLE},
    {HKS_EVENT_UKEY_UPDATE_SESSION,
        FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME | FLAG_ALG |
        FLAG_PURPOSE | FLAG_DETAIL_ERRCODE | FLAG_HANDLE | FLAG_EXTRA_DATA,
        COMPARE_HANDLE},
    {HKS_EVENT_UKEY_FINISH_SESSION,
        FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME | FLAG_ALG |
        FLAG_PURPOSE | FLAG_DETAIL_ERRCODE | FLAG_HANDLE | FLAG_EXTRA_DATA,
        COMPARE_HANDLE},
    {HKS_EVENT_UKEY_ABORT_SESSION,
        FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME | FLAG_ALG |
        FLAG_PURPOSE | FLAG_DETAIL_ERRCODE | FLAG_HANDLE | FLAG_EXTRA_DATA,
        COMPARE_HANDLE},
    {HKS_EVENT_UKEY_GENERATE_KEY,
        FLAG_RESOURCE_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME | FLAG_EXT_BUNDLE_NAME |
        FLAG_ALG | FLAG_PURPOSE | FLAG_DETAIL_ERRCODE,
        COMPARE_RESOURCE_ID},
    {HKS_EVENT_UKEY_EXPORT_PUBLIC_KEY,
        FLAG_RESOURCE_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME |
        FLAG_EXT_BUNDLE_NAME | FLAG_ALG | FLAG_PURPOSE | FLAG_DETAIL_ERRCODE,
        COMPARE_RESOURCE_ID},
    {HKS_EVENT_UKEY_IMPORT_WRAPPED_KEY,
        FLAG_RESOURCE_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME |
        FLAG_EXT_BUNDLE_NAME | FLAG_ALG | FLAG_PURPOSE | FLAG_DETAIL_ERRCODE,
        COMPARE_RESOURCE_ID},
    {HKS_EVENT_UKEY_SET_REMOTE_PROPERTY,
        FLAG_RESOURCE_ID | FLAG_PROVIDER_NAME | FLAG_ABILITY_NAME |
        FLAG_EXT_BUNDLE_NAME | FLAG_DETAIL_ERRCODE | FLAG_PROPERTY_ID,
        COMPARE_RESOURCE_ID},
};

// Find event configuration
static const UKeyEventConfig* FindEventConfig(uint32_t eventId)
{
    for (size_t i = 0; i < sizeof(UKEY_EVENT_CONFIGS) / sizeof(UKEY_EVENT_CONFIGS[0]); i++) {
        if (UKEY_EVENT_CONFIGS[i].eventId == eventId) {
            return &UKEY_EVENT_CONFIGS[i];
        }
    }
    return nullptr;
}

// Helper: Add blob param with validity check
static inline void AddBlobParam(std::vector<struct HksParam>& params,
    uint32_t tag, const struct HksBlob& blob)
{
    if (blob.size > 0 && blob.data != nullptr) {
        params.push_back({.tag = tag, .blob = blob});
    }
}

// Helper: Add field param based on mapping
static void AddFieldParam(std::vector<struct HksParam>& params, const FieldMapping* mapping,
    const struct UKeyInfo* ukeyInfo)
{
    switch (mapping->flag) {
        case FLAG_RESOURCE_ID:
            AddBlobParam(params, mapping->tag, ukeyInfo->resourceId);
            break;
        case FLAG_PROVIDER_NAME:
            AddBlobParam(params, mapping->tag, ukeyInfo->providerName);
            break;
        case FLAG_ABILITY_NAME:
            AddBlobParam(params, mapping->tag, ukeyInfo->abilityName);
            break;
        case FLAG_EXT_BUNDLE_NAME:
            AddBlobParam(params, mapping->tag, ukeyInfo->extBundleName);
            break;
        case FLAG_HANDLE:
            AddBlobParam(params, mapping->tag, ukeyInfo->handle);
            break;
        case FLAG_EXTRA_DATA:
            AddBlobParam(params, mapping->tag, ukeyInfo->extraData);
            break;
        case FLAG_PROPERTY_ID:
            AddBlobParam(params, mapping->tag, ukeyInfo->propertyId);
            break;
        case FLAG_ALG:
            params.push_back({.tag = mapping->tag, .uint32Param = ukeyInfo->alg});
            break;
        case FLAG_PURPOSE:
            params.push_back({.tag = mapping->tag, .uint32Param = ukeyInfo->purpose});
            break;
        case FLAG_DETAIL_ERRCODE:
            params.push_back({.tag = mapping->tag, .uint32Param = ukeyInfo->detailErrcode});
            break;
        case FLAG_OPERATION:
            params.push_back({.tag = mapping->tag, .uint32Param = ukeyInfo->operation});
            break;
        case FLAG_STATE:
            params.push_back({.tag = mapping->tag, .int32Param = ukeyInfo->state});
            break;
    }
}

static int32_t GenericAddUKeyParamSet(const struct UKeyInfo* ukeyInfo, uint32_t eventId,
    struct HksParamSet *reportParamSet)
{
    const UKeyEventConfig* config = FindEventConfig(eventId);
    if (config == nullptr) return HKS_ERROR_INVALID_ARGUMENT;

    std::vector<struct HksParam> params;
    params.push_back({.tag = HKS_TAG_PARAM0_UINT32, .uint32Param = eventId});

    for (size_t i = 0; i < sizeof(FIELD_MAPPINGS) / sizeof(FIELD_MAPPINGS[0]); i++) {
        if (config->fieldFlags & FIELD_MAPPINGS[i].flag) {
            AddFieldParam(params, &FIELD_MAPPINGS[i], ukeyInfo);
        }
    }
    return HksAddParams(reportParamSet, params.data(), params.size());
}

// Helper: Extract field from ParamSet based on mapping
static int32_t ExtractFieldFromParamSet(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo,
    const FieldMapping* mapping)
{
    struct HksParam *param = nullptr;
    if (HksGetParam(paramSetIn, mapping->tag, &param) != HKS_SUCCESS) return HKS_SUCCESS;

    int32_t ret = HKS_SUCCESS;
    switch (mapping->flag) {
        case FLAG_RESOURCE_ID: ret = CopyParamBlobData(&eventInfo->ukeyInfo.resourceId, param); break;
        case FLAG_PROVIDER_NAME: ret = CopyParamBlobData(&eventInfo->ukeyInfo.providerName, param); break;
        case FLAG_ABILITY_NAME: ret = CopyParamBlobData(&eventInfo->ukeyInfo.abilityName, param); break;
        case FLAG_EXT_BUNDLE_NAME: ret = CopyParamBlobData(&eventInfo->ukeyInfo.extBundleName, param); break;
        case FLAG_HANDLE: ret = CopyParamBlobData(&eventInfo->ukeyInfo.extraData, param); break;
        case FLAG_EXTRA_DATA: ret = CopyParamBlobData(&eventInfo->ukeyInfo.extraData, param); break;
        case FLAG_PROPERTY_ID: ret = CopyParamBlobData(&eventInfo->ukeyInfo.propertyId, param); break;
        case FLAG_ALG: eventInfo->ukeyInfo.alg = param->uint32Param; break;
        case FLAG_PURPOSE: eventInfo->ukeyInfo.purpose = param->uint32Param; break;
        case FLAG_DETAIL_ERRCODE: eventInfo->ukeyInfo.detailErrcode = param->uint32Param; break;
        case FLAG_OPERATION: eventInfo->ukeyInfo.operation = param->uint32Param; break;
        case FLAG_STATE: eventInfo->ukeyInfo.state = param->int32Param; break;
        case FLAG_CALL_AUTH_UID: eventInfo->ukeyInfo.callAuthUid = param->int32Param; break;
        default: return HKS_SUCCESS;
    }
    return ret;
}

// Generic ParamSetToEventInfo function (simplified to 20 lines)
static int32_t GenericParamSetToEventInfo(const struct HksParamSet *paramSetIn,
    struct HksEventInfo *eventInfo, uint32_t eventId)
{
    HKS_IF_TRUE_LOGI_RETURN(paramSetIn == nullptr || eventInfo == nullptr, HKS_ERROR_NULL_POINTER,
        "GenericParamSetToEventInfo params is null")

    std::unique_ptr<struct HksEventInfo *, DeleteEventInfo> commEventInfo(&eventInfo);
    int32_t ret = GetCommonEventInfo(paramSetIn, eventInfo);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "report GetCommonEventInfo failed!  ret = %" LOG_PUBLIC "d", ret);

    const UKeyEventConfig* config = FindEventConfig(eventId);
    if (config == nullptr) return HKS_ERROR_INVALID_ARGUMENT;

    for (size_t i = 0; i < sizeof(FIELD_MAPPINGS) / sizeof(FIELD_MAPPINGS[0]); i++) {
        if (config->fieldFlags & FIELD_MAPPINGS[i].flag) {
            ret = ExtractFieldFromParamSet(paramSetIn, eventInfo, &FIELD_MAPPINGS[i]);
            HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "Extract field %s failed", FIELD_MAPPINGS[i].name)
        }
    }
    (void)commEventInfo.release();
    return HKS_SUCCESS;
}

// Generic NeedReport function
static bool GenericNeedReport(const struct HksEventInfo *eventInfo)
{
    if (eventInfo == nullptr) {
        return false;
    }
    return eventInfo->common.result.code != HKS_SUCCESS;
}

// Generic EventInfoEqual function
static bool GenericEventInfoEqual(const struct HksEventInfo *eventInfo1,
    const struct HksEventInfo *eventInfo2, uint32_t eventId)
{
    HKS_IF_TRUE_RETURN(eventInfo1 == nullptr || eventInfo2 == nullptr, false)
    HKS_IF_TRUE_RETURN(eventInfo1->common.eventId != eventInfo2->common.eventId, false)

    const UKeyEventConfig* config = FindEventConfig(eventId);
    if (config == nullptr) {
        return false;
    }

    switch (config->compareType) {
        case COMPARE_RESOURCE_ID:
            HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.resourceId == nullptr ||
                eventInfo2->ukeyInfo.resourceId == nullptr, false)
            return strcmp(eventInfo1->ukeyInfo.resourceId, eventInfo2->ukeyInfo.resourceId) == 0;

        case COMPARE_HANDLE:
            HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.extraData == nullptr ||
                eventInfo2->ukeyInfo.extraData == nullptr, false)
            return strcmp(eventInfo1->ukeyInfo.extraData, eventInfo2->ukeyInfo.extraData) == 0;

        case COMPARE_PROPERTY_ID:
            HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.resourceId == nullptr ||
                eventInfo2->ukeyInfo.resourceId == nullptr, false)
            HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.propertyId == nullptr ||
                eventInfo2->ukeyInfo.propertyId == nullptr, false)
            return strcmp(eventInfo1->ukeyInfo.resourceId, eventInfo2->ukeyInfo.resourceId) == 0 &&
                strcmp(eventInfo1->ukeyInfo.propertyId, eventInfo2->ukeyInfo.propertyId) == 0;

        case COMPARE_PROVIDER_NAME:
            HKS_IF_TRUE_RETURN(eventInfo1->ukeyInfo.providerName == nullptr ||
                eventInfo2->ukeyInfo.providerName == nullptr, false)
            return strcmp(eventInfo1->ukeyInfo.providerName, eventInfo2->ukeyInfo.providerName) == 0;

        default:
            return false;
    }
}

// Generic EventInfoAdd function
static void GenericEventInfoAdd(struct HksEventInfo *dstEventInfo,
    const struct HksEventInfo *srcEventInfo, uint32_t eventId)
{
    if (GenericEventInfoEqual(dstEventInfo, srcEventInfo, eventId)) {
        dstEventInfo->common.count++;
    }
}

// Helper: Convert field to Map based on mapping
static int32_t ConvertFieldToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData, const FieldMapping* mapping)
{
    std::string value;
    switch (mapping->flag) {
        case FLAG_RESOURCE_ID:
            value = eventInfo->ukeyInfo.resourceId ? eventInfo->ukeyInfo.resourceId : EVENT_PROPERTY_UNKNOWN; break;
        case FLAG_PROVIDER_NAME:
            value = eventInfo->ukeyInfo.providerName ? eventInfo->ukeyInfo.providerName : EVENT_PROPERTY_UNKNOWN; break;
        case FLAG_ABILITY_NAME:
            value = eventInfo->ukeyInfo.abilityName ? eventInfo->ukeyInfo.abilityName : EVENT_PROPERTY_UNKNOWN; break;
        case FLAG_EXT_BUNDLE_NAME:
            value = eventInfo->ukeyInfo.extBundleName ?
                eventInfo->ukeyInfo.extBundleName : EVENT_PROPERTY_UNKNOWN; break;
        case FLAG_HANDLE:
            value = eventInfo->ukeyInfo.extraData ? eventInfo->ukeyInfo.extraData : EVENT_PROPERTY_UNKNOWN; break;
        case FLAG_EXTRA_DATA:
            value = eventInfo->ukeyInfo.extraData ? eventInfo->ukeyInfo.extraData : EVENT_PROPERTY_UNKNOWN; break;
        case FLAG_PROPERTY_ID:
            value = eventInfo->ukeyInfo.propertyId ? eventInfo->ukeyInfo.propertyId : EVENT_PROPERTY_UNKNOWN; break;
        case FLAG_ALG: value = std::to_string(eventInfo->ukeyInfo.alg); break;
        case FLAG_PURPOSE: value = std::to_string(eventInfo->ukeyInfo.purpose); break;
        case FLAG_DETAIL_ERRCODE: value = std::to_string(eventInfo->ukeyInfo.detailErrcode); break;
        case FLAG_OPERATION: value = std::to_string(eventInfo->ukeyInfo.operation); break;
        case FLAG_STATE: value = std::to_string(eventInfo->ukeyInfo.state); break;
        case FLAG_CALL_AUTH_UID: value = std::to_string(eventInfo->ukeyInfo.callAuthUid); break;
        default: return HKS_SUCCESS;
    }
    auto ret = reportData.insert_or_assign(mapping->name, value);
    return ret.second ? HKS_SUCCESS : HKS_ERROR_BUFFER_TOO_SMALL;
}

// Generic EventInfoToMap function (simplified to 20 lines)
static int32_t GenericEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData, uint32_t eventId)
{
    HKS_IF_NULL_LOGI_RETURN(eventInfo, HKS_ERROR_NULL_POINTER, "eventInfo is null")

    const UKeyEventConfig* config = FindEventConfig(eventId);
    if (config == nullptr) return HKS_ERROR_INVALID_ARGUMENT;

    auto insertRet = reportData.insert_or_assign("event_id", std::to_string(eventId));
    HKS_IF_NOT_TRUE_LOGI_RETURN(insertRet.second, HKS_ERROR_BUFFER_TOO_SMALL, "reportData insert eventId failed!");

    for (size_t i = 0; i < sizeof(FIELD_MAPPINGS) / sizeof(FIELD_MAPPINGS[0]); i++) {
        if (config->fieldFlags & FIELD_MAPPINGS[i].flag) {
            int32_t ret = ConvertFieldToMap(eventInfo, reportData, &FIELD_MAPPINGS[i]);
            HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "Convert field %s failed", FIELD_MAPPINGS[i].name)
        }
    }
    return HKS_SUCCESS;
}

// Wrapper functions (non-inline to export symbols for HA Plugin)
int32_t HksRegProviderParamSetToEventInfo(const struct HksParamSet *paramSetIn,
    struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_REGISTER_PROVIDER);
}
bool HksRegProviderNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksRegProviderEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_REGISTER_PROVIDER);
}

void HksEventInfoAddForRegProvider(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_REGISTER_PROVIDER);
}

int32_t HksRegProviderEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_REGISTER_PROVIDER);
}

int32_t HksGetAuthPinStateParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_GET_AUTH_PIN_STATE);
}

bool HksGetAuthPinStateNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksGetAuthPinStateEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_GET_AUTH_PIN_STATE);
}

void HksEventInfoAddForGetAuthPinState(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_GET_AUTH_PIN_STATE);
}

int32_t HksGetAuthPinStateEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_GET_AUTH_PIN_STATE);
}

int32_t HksAuthPinParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_AUTH_PIN);
}

bool HksAuthPinNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksAuthPinEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_AUTH_PIN);
}

void HksEventInfoAddForAuthPin(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_AUTH_PIN);
}

int32_t HksAuthPinEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_AUTH_PIN);
}

int32_t HksRemoteHandleParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE);
}

bool HksRemoteHandleNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksRemoteHandleEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE);
}

void HksEventInfoAddForRemoteHandle(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE);
}

int32_t HksRemoteHandleEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE);
}

int32_t HksExportProviderCertParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT);
}

bool HksExportProviderCertNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksExportProviderCertEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT);
}

void HksEventInfoAddForExportProviderCert(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT);
}

int32_t HksExportProviderCertEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT);
}

int32_t HksExportCertParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_EXPORT_CERT);
}

bool HksExportCertNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksExportCertEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_EXPORT_CERT);
}

void HksEventInfoAddForExportCert(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_EXPORT_CERT);
}

int32_t HksExportCertEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_EXPORT_CERT);
}

int32_t HksGetPropertyParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKSY_GET_REMOTE_PROPERTY);
}

bool HksGetPropertyNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksGetPropertyEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKSY_GET_REMOTE_PROPERTY);
}

void HksEventInfoAddForGetProperty(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKSY_GET_REMOTE_PROPERTY);
}

int32_t HksGetPropertyEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKSY_GET_REMOTE_PROPERTY);
}

int32_t HksImportCertParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_IMPORT_CERT);
}

bool HksImportCertNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksImportCertEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_IMPORT_CERT);
}

void HksEventInfoAddForImportCert(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_IMPORT_CERT);
}

int32_t HksImportCertEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_IMPORT_CERT);
}

int32_t HksGetResourceIdParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_GET_RESOURCE_ID);
}

bool HksGetResourceIdNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksGetResourceIdEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_GET_RESOURCE_ID);
}

void HksEventInfoAddForGetResourceId(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_GET_RESOURCE_ID);
}

int32_t HksGetResourceIdEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_GET_RESOURCE_ID);
}

int32_t HksClearPinStateParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_CLEAR_PIN_STATE);
}

bool HksClearPinStateNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksClearPinStateEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_CLEAR_PIN_STATE);
}

void HksEventInfoAddForClearPinState(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_CLEAR_PIN_STATE);
}

int32_t HksClearPinStateEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_CLEAR_PIN_STATE);
}

int32_t HksInitSessionParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_INIT_SESSION);
}

bool HksInitSessionNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksInitSessionEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_INIT_SESSION);
}

void HksEventInfoAddForInitSession(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_INIT_SESSION);
}

int32_t HksInitSessionEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_INIT_SESSION);
}

int32_t HksUpdateSessionParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_UPDATE_SESSION);
}

bool HksUpdateSessionNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksUpdateSessionEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_UPDATE_SESSION);
}

void HksEventInfoAddForUpdateSession(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_UPDATE_SESSION);
}

int32_t HksUpdateSessionEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_UPDATE_SESSION);
}

int32_t HksFinishSessionParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_FINISH_SESSION);
}

bool HksFinishSessionNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksFinishSessionEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_FINISH_SESSION);
}

void HksEventInfoAddForFinishSession(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_FINISH_SESSION);
}

int32_t HksFinishSessionEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_FINISH_SESSION);
}

int32_t HksAbortSessionParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_ABORT_SESSION);
}

bool HksAbortSessionNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksAbortSessionEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_ABORT_SESSION);
}

void HksEventInfoAddForAbortSession(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_ABORT_SESSION);
}

int32_t HksAbortSessionEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_ABORT_SESSION);
}

int32_t HksGenerateKeyParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_GENERATE_KEY);
}

bool HksGenerateKeyNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksGenerateKeyEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_GENERATE_KEY);
}

void HksEventInfoAddForGenerateKey(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_GENERATE_KEY);
}

int32_t HksGenerateKeyEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_GENERATE_KEY);
}

int32_t HksExportPublicKeyParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_EXPORT_PUBLIC_KEY);
}

bool HksExportPublicKeyNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksExportPublicKeyEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_EXPORT_PUBLIC_KEY);
}

void HksEventInfoAddForExportPublicKey(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_EXPORT_PUBLIC_KEY);
}

int32_t HksExportPublicKeyEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_EXPORT_PUBLIC_KEY);
}

int32_t HksImportWrappedKeyParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_IMPORT_WRAPPED_KEY);
}

bool HksImportWrappedKeyNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksImportWrappedKeyEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_IMPORT_WRAPPED_KEY);
}

void HksEventInfoAddForImportWrappedKey(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_IMPORT_WRAPPED_KEY);
}

int32_t HksImportWrappedKeyEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_IMPORT_WRAPPED_KEY);
}

int32_t HksSetPropertyParamSetToEventInfo(const struct HksParamSet *paramSetIn, struct HksEventInfo *eventInfo)
{
    return GenericParamSetToEventInfo(paramSetIn, eventInfo, HKS_EVENT_UKEY_SET_REMOTE_PROPERTY);
}

bool HksSetPropertyNeedReport(const struct HksEventInfo *eventInfo)
{
    return GenericNeedReport(eventInfo);
}

bool HksSetPropertyEventInfoEqual(const struct HksEventInfo *eventInfo1, const struct HksEventInfo *eventInfo2)
{
    return GenericEventInfoEqual(eventInfo1, eventInfo2, HKS_EVENT_UKEY_SET_REMOTE_PROPERTY);
}

void HksEventInfoAddForSetProperty(struct HksEventInfo *dstEventInfo, const struct HksEventInfo *srcEventInfo)
{
    GenericEventInfoAdd(dstEventInfo, srcEventInfo, HKS_EVENT_UKEY_SET_REMOTE_PROPERTY);
}

int32_t HksSetPropertyEventInfoToMap(const struct HksEventInfo *eventInfo,
    std::unordered_map<std::string, std::string> &reportData)
{
    return GenericEventInfoToMap(eventInfo, reportData, HKS_EVENT_UKEY_SET_REMOTE_PROPERTY);
}

// ParamSet function array
using UkeyAddParamFunc = int32_t(*)(const struct UKeyInfo*, const struct HksParamSet *, struct HksParamSet *);

static int32_t AddUKeyRegProviderParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_REGISTER_PROVIDER, reportParamSet);
}

static int32_t AddUKeyGetAuthPinStateParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_GET_AUTH_PIN_STATE, reportParamSet);
}

static int32_t AddUKeyAuthPinParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_AUTH_PIN, reportParamSet);
}

static int32_t AddUKeyRemoteHandleParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE, reportParamSet);
}

static int32_t AddUKeyExportProviderCertParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT, reportParamSet);
}

static int32_t AddUKeyExportCertParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_EXPORT_CERT, reportParamSet);
}

static int32_t AddUKeyGetPropertyParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKSY_GET_REMOTE_PROPERTY, reportParamSet);
}

static int32_t AddUKeyImportCertParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_IMPORT_CERT, reportParamSet);
}

static int32_t AddUKeyGetResourceIdParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_GET_RESOURCE_ID, reportParamSet);
}

static int32_t AddUKeyClearPinStateParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_CLEAR_PIN_STATE, reportParamSet);
}

static int32_t AddUKeyInitSessionParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_INIT_SESSION, reportParamSet);
}

static int32_t AddUKeyUpdateSessionParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_UPDATE_SESSION, reportParamSet);
}

static int32_t AddUKeyFinishSessionParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_FINISH_SESSION, reportParamSet);
}

static int32_t AddUKeyAbortSessionParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_ABORT_SESSION, reportParamSet);
}

static int32_t AddUKeyGenerateKeyParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_GENERATE_KEY, reportParamSet);
}

static int32_t AddUKeyExportPublicKeyParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_EXPORT_PUBLIC_KEY, reportParamSet);
}

static int32_t AddUKeyImportWrappedKeyParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_IMPORT_WRAPPED_KEY, reportParamSet);
}

static int32_t AddUKeySetPropertyParamSet(const struct UKeyInfo* ukeyInfo,
    const struct HksParamSet *paramSet, struct HksParamSet *reportParamSet)
{
    (void)paramSet;
    return GenericAddUKeyParamSet(ukeyInfo, HKS_EVENT_UKEY_SET_REMOTE_PROPERTY, reportParamSet);
}

static constexpr UkeyAddParamFunc UKEY_ADD_PARAM_FUNC[] = {
    AddUKeyRegProviderParamSet,
    AddUKeyGetAuthPinStateParamSet,
    AddUKeyAuthPinParamSet,
    AddUKeyRemoteHandleParamSet,
    AddUKeyExportProviderCertParamSet,
    AddUKeyExportCertParamSet,
    AddUKeyGetPropertyParamSet,
    AddUKeyInitSessionParamSet,
    AddUKeyUpdateSessionParamSet,
    AddUKeyFinishSessionParamSet,
    AddUKeyAbortSessionParamSet,
    AddUKeyImportCertParamSet,
    AddUKeyGetResourceIdParamSet,
    AddUKeyClearPinStateParamSet,
    AddUKeyGenerateKeyParamSet,
    AddUKeyExportPublicKeyParamSet,
    AddUKeyImportWrappedKeyParamSet,
    AddUKeySetPropertyParamSet
};

static constexpr uint32_t GetUKeyReportIndex(uint32_t eventId)
{
    return eventId - HKS_EVENT_UKEY_REGISTER_PROVIDER;
}

int32_t ReportUKeyEvent(const struct UKeyInfo* ukeyInfo, const char *funcName,
    const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet,
    const struct UKeyCommonInfo *ukeyCommon)
{
    if (ukeyInfo == nullptr || funcName == nullptr || processInfo == nullptr ||
        ukeyCommon == nullptr) {
        HKS_LOG_E("input parameter is invalid");
        return HKS_FAILURE;
    }
    if (!IF_UKEY_EVENT(ukeyInfo->eventId)) {
        HKS_LOG_E("report event %" LOG_PUBLIC "u is invalid", ukeyInfo->eventId);
        return HKS_FAILURE;
    }
    struct HksParamSet *reportParamSet = nullptr;

    std::unique_ptr<struct HksParamSet *, DeleteParamSet> commonEventInfo(&reportParamSet);

    int32_t ret = HksInitParamSet(&reportParamSet);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "init report paramset fail")

    ret = UKEY_ADD_PARAM_FUNC[GetUKeyReportIndex(ukeyInfo->eventId)](ukeyInfo, paramSet, reportParamSet);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add param set failed")

    ret = AddTimeCost(reportParamSet, ukeyCommon->startTime);
    HKS_IF_NOT_SUCC_LOGI_RETURN(ret, ret, "add time failed")

    (void)ConstructReportParamSet(funcName, processInfo, nullptr, ukeyCommon->returnCode, &reportParamSet);
    HksEventReport(funcName, processInfo, paramSet, reportParamSet, ukeyCommon->returnCode);
    
    return HKS_SUCCESS;
}

void ReportUKeySessionEvent(uint32_t eventId, int32_t ret,
    const struct HksBlob *handle, const struct HksProcessInfo *processInfo,
    const struct HksParamSet *paramSet)
{
    struct UKeyInfo ukeyInfo = { .eventId = eventId, .detailErrcode = ret };
    if (handle != nullptr && handle->size > 0) {
        ukeyInfo.handle = *handle;
    }
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret };
    (void)ReportUKeyEvent(&ukeyInfo, __func__, processInfo, paramSet, &ukeyCommon);
}

void ReportUKeyKeyEvent(uint32_t eventId, int32_t ret,
    const struct HksProcessInfo *processInfo, const struct HksParamSet *paramSet)
{
    struct UKeyInfo ukeyInfo = { .eventId = eventId, .detailErrcode = ret };
    struct UKeyCommonInfo ukeyCommon = { .returnCode = ret };
    (void)ReportUKeyEvent(&ukeyInfo, __func__, processInfo, paramSet, &ukeyCommon);
}