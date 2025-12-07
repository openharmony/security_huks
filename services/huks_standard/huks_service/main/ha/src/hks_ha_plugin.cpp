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

#include "hks_ha_plugin.h"

#include <cstring>

#include "securec.h"
#include "hks_ha_event_queue.h"
#include "hks_mem.h"
#include "hks_log.h"
#include "hks_plugin_adapter.h"
#include "hks_plugin_def.h"
#include "hks_template.h"
#include "hks_report_generate_key.h"
#include "hks_report_import_key.h"
#include "hks_report_delete_key.h"
#include "hks_report_check_key_exited.h"
#include "hks_report_rename_key.h"
#include "hks_report_three_stage.h"
#include "hks_report_list_aliases.h"
#include "hks_report_data_size.h"
#include "hks_report_three_stage_build.h"
#include "hks_report_ukey_event.h"
#include "hks_param.h"

static HksEventProcMap g_eventProcMap[] = {
    {
        HKS_EVENT_CRYPTO,
        HksParamSetToEventInfoCrypto,
        HksEventInfoNeedReportCrypto,
        HksEventInfoIsEqualCrypto,
        HksEventInfoAddCrypto,
        HksEventInfoToMapCrypto,
    },
    {
        HKS_EVENT_SIGN_VERIFY,
        HksParamSetToEventInfoCrypto,
        HksEventInfoNeedReportCrypto,
        HksEventInfoIsEqualCrypto,
        HksEventInfoAddCrypto,
        HksEventInfoToMapCrypto,
    },
    {
        HKS_EVENT_DERIVE,
        HksParamSetToEventInfoAgreeDerive,
        HksEventInfoNeedReportAgreeDerive,
        HksEventInfoIsEqualAgreeDerive,
        HksEventInfoAddAgreeDerive,
        HksEventInfoToMapAgreeDerive,
    },
    {
        HKS_EVENT_AGREE,
        HksParamSetToEventInfoAgreeDerive,
        HksEventInfoNeedReportAgreeDerive,
        HksEventInfoIsEqualAgreeDerive,
        HksEventInfoAddAgreeDerive,
        HksEventInfoToMapAgreeDerive,
    },
    {
        HKS_EVENT_MAC,
        HksParamSetToEventInfoMac,
        HksEventInfoNeedReportMac,
        HksEventInfoIsEqualMac,
        HksEventInfoAddMac,
        HksEventInfoToMapMac,
    },
    {
        HKS_EVENT_ATTEST,
        HksParamSetToEventInfoAttest,
        HksEventInfoNeedReportAttest,
        HksEventInfoIsEqualAttest,
        HksEventInfoAddAttest,
        HksEventInfoToMapAttest,
    },
    {
        HKS_EVENT_GENERATE_KEY,
        HksParamSetToEventInfoForKeyGen,
        HksEventInfoIsNeedReportForKeyGen,
        HksEventInfoIsEqualForKeyGen,
        HksEventInfoAddForKeyGen,
        HksEventInfoToMapForKeyGen
    },
    {
        HKS_EVENT_IMPORT_KEY,
        HksParamSetToEventInfoForImport,
        HksEventInfoIsNeedReportForImport,
        HksEventInfoIsEqualForImport,
        HksEventInfoAddForImport,
        HksEventInfoToMapForImport,
    },
    {
        HKS_EVENT_DELETE_KEY,
        HksParamSetToEventInfoForDelete,
        HksEventInfoIsNeedReportForDelete,
        HksEventInfoIsEqualForDelete,
        HksEventInfoAddForDelete,
        HksEventInfoToMapForDelete
    },
    {
        HKS_EVENT_CHECK_KEY_EXISTED,
        HksParamSetToEventInfoForCheckKeyExited,
        HksEventInfoIsNeedReportForCheckKeyExited,
        HksEventInfoIsEqualForCheckKeyExited,
        HksEventInfoAddForCheckKeyExited,
        HksEventInfoToMapForCheckKeyExited
    },
    {
        HKS_EVENT_RENAME_KEY,
        HksParamSetToEventInfoForRename,
        HksEventInfoIsNeedReportForRename,
        HksEventInfoIsEqualForRename,
        HksEventInfoAddForRename,
        HksEventInfoToMapForRename
    },
    {
        HKS_EVENT_LIST_ALIASES,
        HksParamSetToEventInfoForListAliases,
        HksEventInfoIsNeedReportForListAliases,
        HksEventInfoIsEqualForListAliases,
        HksEventInfoAddForListAliases,
        HksEventInfoToMapForListAliases
    },
    {
        HKS_EVENT_DATA_SIZE_STATISTICS,
        HksParamSetToEventInfoForDataSize,
        HksEventInfoIsNeedReportForDataSize,
        HksEventInfoIsEqualForDataSize,
        HksEventInfoAddForDataSize,
        HksEventInfoToMapForDataSize
    },
    {
        HKS_EVENT_UKEY_REGISTER_PROVIDER,
        HksRegProviderParamSetToEventInfo,
        HksRegProviderNeedReport,
        HksRegProviderEventInfoEqual,
        HksEventInfoAddForRegProvider,
        HksRegProviderEventInfoToMap,
    },
    {
        HKS_EVENT_UKEY_GET_AUTH_PIN_STATE,
        HksGetAuthPinStateParamSetToEventInfo,
        HksGetAuthPinStateNeedReport,
        HksGetAuthPinStateEventInfoEqual,
        HksEventInfoAddForGetAuthPinState,
        HksGetAuthPinStateEventInfoToMap,
    },
    {
        HKS_EVENT_UKEY_AUTH_PIN,
        HksAuthPinParamSetToEventInfo,
        HksAuthPinNeedReport,
        HksAuthPinEventInfoEqual,
        HksEventInfoAddForAuthPin,
        HksAuthPinEventInfoToMap,
    },
    {
        HKS_EVENT_UKEY_OPERATE_REMOTE_HANDLE,
        HksRemoteHandleParamSetToEventInfo,
        HksRemoteHandleNeedReport,
        HksRemoteHandleEventInfoEqual,
        HksEventInfoAddForRemoteHandle,
        HksRemoteHandleEventInfoToMap,
    },
    {
        HKS_EVENT_UKEY_EXPORT_PROVIDER_CERT,
        HksExportProviderCertParamSetToEventInfo,
        HksExportProviderCertNeedReport,
        HksExportProviderCertEventInfoEqual,
        HksEventInfoAddForExportProviderCert,
        HksExportProviderCertEventInfoToMap,
    },
    {
        HKS_EVENT_UKEY_EXPORT_CERT,
        HksExportCertParamSetToEventInfo,
        HksExportCertNeedReport,
        HksExportCertEventInfoEqual,
        HksEventInfoAddForExportCert,
        HksExportCertEventInfoToMap,
    },
    {
        HKS_EVENT_UKSY_GET_REMOTE_PROPERTY,
        HksGetPropertyParamSetToEventInfo,
        HksGetPropertyNeedReport,
        HksGetPropertyEventInfoEqual,
        HksEventInfoAddForGetProperty,
        HksGetPropertyEventInfoToMap,
    }
};

HksHaPlugin::HksHaPlugin() : queue(), stopFlag(false)
{}

HksHaPlugin::~HksHaPlugin()
{
    Destroy();
}

void HksHaPlugin::Destroy()
{
    queue.Stop();

    StopWorkerThread();

    eventCacheList.RemoveFront(eventCacheList.GetSize());
}

void HksHaPlugin::StartWorkerThread()
{
    workerThread = std::thread(&HksHaPlugin::WorkerThread, this);
}

void HksHaPlugin::StopWorkerThread()
{
    stopFlag = true;
}

bool HksHaPlugin::Enqueue(uint32_t eventId, struct HksParamSet *paramSet)
{
    return queue.Enqueue(eventId, paramSet);
}

HksEventProcMap *HksHaPlugin::HksEventProcFind(uint32_t eventId)
{
    for (uint32_t i = 0; i < HKS_ARRAY_SIZE(g_eventProcMap); ++i) {
        HKS_IF_TRUE_RETURN(g_eventProcMap[i].eventId == eventId, &g_eventProcMap[i])
    }
    return nullptr;
}

void HksHaPlugin::HandlerReport(HksEventQueueItem &item)
{
    HKS_IF_NULL_LOGE_RETURN_VOID(item.paramSet, "HandlerReport: paramSet is"
        "null for eventId %" LOG_PUBLIC "u", item.eventId);

    uint32_t eventId = item.eventId;
    auto procMap = HksEventProcFind(eventId);
    HKS_IF_NULL_LOGE_RETURN_VOID(procMap, "HandlerReport: Event ID %" LOG_PUBLIC "u not found in"
        "the eventProcMap", eventId);

    struct HksEventInfo *eventInfo = (struct HksEventInfo *)HksMalloc(sizeof(struct HksEventInfo));
    HKS_IF_NULL_LOGE_RETURN_VOID(eventInfo, "Failed to allocate HksEventInfo");

    int32_t ret = procMap->eventInfoCreate(item.paramSet, eventInfo);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("Failed to create HksEventInfo for eventId %" LOG_PUBLIC "u", eventId);
        HKS_FREE(eventInfo);
        return;
    }

    bool needReport = procMap->needReport(eventInfo);
    HKS_IF_NOT_TRUE_RETURN(needReport, HandleStatisticEvent(eventInfo, eventId, procMap))
    
    std::unordered_map<std::string, std::string> eventMap;
    ret = procMap->eventInfoToMap(eventInfo, eventMap);
    HKS_IF_NOT_SUCC_LOGE(ret, "Failed to convert HksEventInfo to map"
        "for eventId %" LOG_PUBLIC "u", eventId);
    HandleFaultEvent(&eventInfo->common, eventMap);

    HksFreeEventInfo(&eventInfo);
    HKS_FREE(eventInfo);
}

void HksHaPlugin::WorkerThread()
{
    while (!stopFlag) {
        HksEventQueueItem item;
        bool success = queue.Dequeue(item);
        if (!success) {
            continue;
        }

        HandlerReport(item);
        HksFreeParamSet(&item.paramSet);
    }
}

void HksHaPlugin::HandleFaultEvent(
    HksEventCommonInfo *commonInfo, std::unordered_map<std::string, std::string> &eventMap)
{
    int32_t ret = HksPluginOnLocalRequest(CODE_FAULT_METRICS, commonInfo, &eventMap);
    HKS_IF_NOT_SUCC_LOGE_RETURN_VOID(ret, "Failed to call OnSingleEventRequest: error code %" LOG_PUBLIC "d", ret);
}

static uint32_t GetCurrentTimestamp()
{
    return static_cast<uint32_t>(time(nullptr));
}

void HksHaPlugin::HandleStatisticEvent(struct HksEventInfo *eventInfo, uint32_t eventId, HksEventProcMap *procMap)
{
    HKS_IF_NULL_LOGE_RETURN_VOID(eventInfo, "HandleStatisticEvent: Invalid eventInfo parameters");
    HKS_IF_NULL_LOGE_RETURN_VOID(procMap, "HandleStatisticEvent: Invalid procMap parameters");

    bool found = eventCacheList.FindAndUpdate(eventInfo, procMap);
    if (!found) {
        AddEventCache(eventId, eventInfo);
    } else {
        HksFreeEventInfo(&eventInfo);
        HKS_FREE(eventInfo);
    }

    uint32_t currentSize = eventCacheList.GetSize();
    HKS_IF_TRUE_RETURN_VOID(currentSize <= 0)

    HKS_IF_TRUE_RETURN_VOID(eventCacheList.cacheList.empty())
    const HksEventCacheNode &firstNode = eventCacheList.cacheList.front();
    uint32_t reportCount = 0;
    time_t currentTime = GetCurrentTimestamp();

    HKS_IF_TRUE_RETURN_VOID((currentTime - firstNode.timestamp) <= MAX_CACHE_DURATION && currentSize < MAX_CACHE_SIZE)
    reportCount = currentSize;
    HKS_LOG_I("HksHaPlugin::HandleStatisticEvent:reportCount is %" LOG_PUBLIC "u", reportCount);
    BatchReportEvents(reportCount);
}

void HksHaPlugin::AddEventCache(uint32_t eventId, struct HksEventInfo *eventInfo)
{
    HksEventCacheNode newNode{eventId, GetCurrentTimestamp(), eventInfo};
    eventCacheList.Add(newNode);
}

int32_t HksHaPlugin::FillEventInfos(uint32_t reportCount, HksEventWithMap *eventsWithMap)
{
    uint32_t count = 0;

    for (auto it = eventCacheList.cacheList.begin(); it != eventCacheList.cacheList.end() && count < reportCount;
         ++it) {
        if (it->data) {
            struct HksEventInfo *eventInfo = it->data;
            eventsWithMap[count].common = eventInfo->common;

            HksEventProcMap *procMap = HksEventProcFind(eventsWithMap[count].common.eventId);
            HKS_IF_NULL_LOGI_RETURN(procMap, HKS_ERROR_NULL_POINTER, "procMap is null");

            int32_t ret = procMap->eventInfoToMap(eventInfo, eventsWithMap[count].eventMap);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("FillEventInfos: Failed to convert HksEventInfo to map for eventId %" LOG_PUBLIC "u",
                    eventsWithMap[count].common.eventId);
                continue;
            }
        }
        ++count;
    }

    return HKS_SUCCESS;
}

int32_t HksHaPlugin::CallBatchReport(uint32_t reportCount, HksEventWithMap *eventsWithMap)
{
    int32_t ret = HksPluginOnLocalRequest(CODE_STATISTICS_METRICS, (const void *)eventsWithMap, (void *)&reportCount);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HKS_ERROR_BAD_STATE, "CallBatchReport: HksHaPlugin_OnBatchEventRequest failed,"
        "error code: %" LOG_PUBLIC "d", ret);

    return HKS_SUCCESS;
}

void HksHaPlugin::RemoveReportedEvents(uint32_t reportCount)
{
    eventCacheList.RemoveFront(reportCount);
}

int32_t HksHaPlugin::BatchReportEvents(uint32_t reportCount)
{
    HKS_IF_TRUE_LOGI_RETURN(reportCount > eventCacheList.GetSize(), HKS_ERROR_INVALID_ARGUMENT,
        "HksHaPlugin::BatchReportEvents:reportCount > queueSize")
    HksEventWithMap *eventsWithMap = new (std::nothrow) HksEventWithMap[reportCount];
    HKS_IF_NULL_LOGI_RETURN(eventsWithMap, HKS_ERROR_NULL_POINTER, "eventsWithMap is null");

    int32_t ret = HKS_SUCCESS;
    do {
        ret = FillEventInfos(reportCount, eventsWithMap);
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "HksHaPlugin::BatchReportEvents:FillEventInfos fail");
        ret = CallBatchReport(reportCount, eventsWithMap);
        HKS_IF_NOT_SUCC_LOGI_BREAK(ret, "HksHaPlugin::BatchReportEvents:CallBatchReport fail");
    } while (0);

    RemoveReportedEvents(reportCount);
    delete[] eventsWithMap;

    return HKS_SUCCESS;
}

int32_t HksHaPluginInit(void)
{
    HksHaPlugin::GetInstance().StartWorkerThread();
    return HKS_SUCCESS;
}

void HksHaPluginDestroy()
{
    HksHaPlugin::GetInstance().Destroy();
}