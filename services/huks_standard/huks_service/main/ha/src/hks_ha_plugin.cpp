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
#include "hks_ha_event_queue.h"
#include "hks_mem.h"
#include "hks_log.h"
#include "hks_plugin_adapter.h"
#include "hks_plugin_def.h"
#include "securec.h"
#include "hks_report_generate_key.h"
#include "hks_report_import_key.h"
#include "hks_report_delete_key.h"
#include "hks_report_check_key_exited.h"
#include "hks_report_rename_key.h"
#include "hks_report_three_stage.h"
#include "hks_report_list_aliases.h"
#include "hks_param.h"
#include <cstring>

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
        HKS_EVENT_AGREE_DERIVE,
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
        HKS_EVENT_CHECK_KEY_EXITED,
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
    if (stopFlag) {
        return;
    }

    StopWorkerThread();

    eventCacheList.RemoveFront(eventCacheList.GetSize());
}

void HksHaPlugin::StartWorkerThread()
{
    HKS_LOG_I("start HksHaPlugin::StartWorkerThread");
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
        if (g_eventProcMap[i].eventId == eventId) {
            return &g_eventProcMap[i];
        }
    }
    return nullptr;
}

void HksHaPlugin::HandlerReport(HksEventQueueItem item)
{
    if (!item.paramSet) {
        HKS_LOG_E("HandlerReport: paramSet is null for eventId %u", item.eventId);
        return;
    }

    uint32_t eventId = item.eventId;
    HKS_LOG_I("HandlerReport: Start processing eventId %u", eventId);

    auto procMap = HksEventProcFind(eventId);
    if (!procMap) {
        HKS_LOG_E("HandlerReport: Event ID %u not found in the eventProcMap", eventId);
        return;
    }
    HKS_LOG_I("HandlerReport: Found eventProcMap for eventId %u", eventId);

    struct HksEventInfo eventInfo {};
    int32_t ret = procMap->eventInfoCreate(item.paramSet, &eventInfo);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HandlerReport: Failed to create HksEventInfo from data for eventId %u", eventId);
        return;
    }
    HKS_LOG_I("HandlerReport: Successfully created HksEventInfo for eventId %u", eventId);

    bool needReport = procMap->needReport(&eventInfo);
    if (needReport) {
        HKS_LOG_I("HandlerReport: Fault event detected for eventId %u", eventId);

        std::unordered_map<std::string, std::string> eventMap;
        ret = procMap->eventInfoToMap(&eventInfo, eventMap);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_E("HandlerReport: Failed to convert HksEventInfo to map for eventId %u", eventId);
        } else {
            HKS_LOG_I("HandlerReport: Successfully converted HksEventInfo to map for eventId %u, map size: %zu",
                eventId,
                eventMap.size());
        }

        HandleFaultEvent(&eventInfo.common, eventMap);
    } else {
        HKS_LOG_I("HandlerReport: Statistics event detected for eventId %u", eventId);
        HandleStatisticEvent(&eventInfo, eventId, procMap);
    }
    HKS_FREE(eventInfo.common.function);
    HKS_FREE(eventInfo.common.callerInfo.name);
    HKS_FREE(eventInfo.common.result.errMsg);

    HKS_LOG_I("HandlerReport: Completed processing for eventId %u", eventId);
}

void HksHaPlugin::WorkerThread()
{
    HKS_LOG_I("WorkerThread: Thread started");

    while (!stopFlag) {
        HksEventQueueItem item;
        bool success = queue.Dequeue(item);
        if (!success) {
            HKS_LOG_I("WorkerThread: Queue is empty, retrying...");
            continue;
        }

        HKS_LOG_I("WorkerThread: Successfully dequeued eventId %u", item.eventId);

        if (stopFlag) {
            HKS_LOG_I("WorkerThread: Stop signal received, exiting thread");
            break;
        }

        HandlerReport(item);
        HKS_LOG_I("WorkerThread: Event processed for eventId %u", item.eventId);

        HksFreeParamSet(&item.paramSet);
        HKS_LOG_I("WorkerThread: Freed paramSet for eventId %u", item.eventId);
    }

    HKS_LOG_I("WorkerThread: Thread stopped");
}

void HksHaPlugin::HandleFaultEvent(
    HksEventCommonInfo *eventInfo, std::unordered_map<std::string, std::string> &eventMap)
{
    HKS_LOG_I("HksPluginOnLocalRequest HandleFaultEvent is start");
    int32_t ret = HksPluginOnLocalRequest(CODE_FAULT_METRICS, eventInfo, &eventMap);
    if (ret != 0) {
        HKS_LOG_E("Failed to call OnSingleEventRequest: error code %d", ret);
    }
    HKS_LOG_I("HksPluginOnLocalRequest HandleFaultEvent is End");
}

uint32_t GetCurrentTimestamp()
{
    return static_cast<uint32_t>(time(nullptr));
}

void HksHaPlugin::HandleStatisticEvent(struct HksEventInfo *eventInfo, uint32_t eventId, HksEventProcMap *procMap)
{
    if (!eventInfo || !procMap) {
        HKS_LOG_E("HandleStatisticEvent: Invalid parameters");
        return;
    }

    bool found = eventCacheList.FindAndUpdate(eventInfo, procMap);
    if (!found) {
        AddEventCache(eventId, eventInfo);
    }
    uint32_t currentSize = eventCacheList.GetSize();
    if (currentSize > 0) {
        time_t currentTime = GetCurrentTimestamp();
        if (!eventCacheList.GetList().empty()) {
            const HksEventCacheNode &firstNode = eventCacheList.GetList().front();
            uint32_t reportCount = 0;

            if ((currentTime - firstNode.timestamp) > MAX_CACHE_DURATION) {
                // 如果最早的事件时间超过24小时，报送所有缓存的事件
                reportCount = currentSize;
            } else if (currentSize >= MAX_CACHE_SIZE) {
                // 如果缓存数量超过100，报送所有缓存的事件
                reportCount = currentSize;
            }

            if (reportCount > 0) {
                HKS_LOG_I("HksHaPlugin::HandleStatisticEvent:reportCount is %u", reportCount);
                BatchReportEvents(reportCount);
            } else {
                HKS_LOG_I("HksHaPlugin::HandleStatisticEvent: No events to report");
            }
        }
    }
}

void HksHaPlugin::AddEventCache(uint32_t eventId, struct HksEventInfo *eventInfo)
{
    HksEventCacheNode newNode{eventId, GetCurrentTimestamp(), eventInfo};
    eventCacheList.Add(newNode);
    HKS_LOG_I("HksHaPlugin::AddEventCache: Added new event cache for eventId=%u, total cache size=%u",
        eventId,
        eventCacheList.GetSize());
}

int32_t HksHaPlugin::FillEventInfos(uint32_t reportCount, HksEventWithMap *eventsWithMap)
{
    HKS_LOG_I("enter to FillEventInfos");
    uint32_t count = 0;

    HKS_LOG_I("FillEventInfos: Start processing, requested reportCount: %u", reportCount);

    for (auto it = eventCacheList.GetList().begin(); it != eventCacheList.GetList().end() && count < reportCount;
         ++it, ++count) {
        if (it->data) {
            struct HksEventInfo *eventInfo = &(*it->data);
            eventsWithMap[count].common = eventInfo->common;

            HKS_LOG_I("Processing eventId: %u", eventsWithMap[count].common.eventId);

            HksEventProcMap *procMap = HksEventProcFind(eventsWithMap[count].common.eventId);
            if (procMap == nullptr) {
                HKS_LOG_E("No eventInfoToMap found for eventId %u", eventsWithMap[count].common.eventId);
                continue;
            }

            HKS_LOG_I("Found eventProcMap for eventId %u", eventsWithMap[count].common.eventId);

            int32_t ret = procMap->eventInfoToMap(eventInfo, eventsWithMap[count].eventMap);
            if (ret != HKS_SUCCESS) {
                HKS_LOG_E("FillEventInfos: Failed to convert HksEventInfo to map for eventId %u",
                    eventsWithMap[count].common.eventId);
                continue;
            }

            HKS_LOG_I("Successfully converted HksEventInfo to map for eventId %u, map size: %zu",
                eventsWithMap[count].common.eventId,
                eventsWithMap[count].eventMap.size());
        }
    }

    HKS_LOG_I("FillEventInfos: Processed %u events out of %u requested", count, reportCount);

    if (count != reportCount) {
        HKS_LOG_E("FillEventInfos: Mismatch in reportCount and filled events. Filled %u events, expected %u.",
            count, reportCount);
        return HKS_ERROR_BAD_STATE;
    }

    HKS_LOG_I("FillEventInfos: Successfully filled all events, total events: %u", reportCount);
    return HKS_SUCCESS;
}

int32_t HksHaPlugin::CallBatchReport(uint32_t reportCount, HksEventWithMap *eventsWithMap)
{
    HKS_LOG_I("HksPluginOnLocalRequest is start");
    HKS_LOG_I("eventsWithMap size: %u", reportCount);
    int32_t ret = HksPluginOnLocalRequest(CODE_STATISTICS_METRICS, (const void *)eventsWithMap, (void *)&reportCount);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksHaPlugin::CallBatchReport: HksHaPlugin_OnBatchEventRequest failed, error code: %d", ret);
        return HKS_ERROR_BAD_STATE;
    } else {
        HKS_LOG_I("HksHaPlugin::CallBatchReport: Successfully reported %u events", reportCount);
    }
    HKS_LOG_I("HksPluginOnLocalRequest is end");
    return HKS_SUCCESS;
}

void HksHaPlugin::RemoveReportedEvents(uint32_t reportCount)
{
    eventCacheList.RemoveFront(reportCount);
}

int32_t HksHaPlugin::BatchReportEvents(uint32_t reportCount)
{
    HKS_LOG_I("enter to BatchReportEvents");
    if (reportCount > eventCacheList.GetSize()) {
        HKS_LOG_I("HksHaPlugin::BatchReportEvents:reportCount > queueSize");
        return HKS_ERROR_INVALID_ARGUMENT;
    }
    HKS_LOG_I("HksHaPlugin::BatchReportEvents:Enter BatchReportEvents");
    HksEventWithMap *eventsWithMap = new HksEventWithMap[reportCount];

    int32_t ret = HKS_SUCCESS;
    do {
        HKS_LOG_I("HksHaPlugin::BatchReportEvents:Enter FillEventInfos");
        HKS_LOG_I("eventsWithMap before fillEventInfos size: %u", reportCount);
        ret = FillEventInfos(reportCount, eventsWithMap);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_I("HksHaPlugin::BatchReportEvents:FillEventInfos fail");
            break;
        }

        HKS_LOG_I("HksHaPlugin::BatchReportEvents:Enter CallBatchReport");
        HKS_LOG_I("eventsWithMap before CallBatchReport size: %u", reportCount);
        ret = CallBatchReport(reportCount, eventsWithMap);
        if (ret != HKS_SUCCESS) {
            HKS_LOG_I("HksHaPlugin::BatchReportEvents:CallBatchReport fail");
            break;
        }

        HKS_LOG_I("HksHaPlugin::BatchReportEvents:Finish CallBatchReport");

        RemoveReportedEvents(reportCount);
    } while (0);
    
    delete[] eventsWithMap;

    HKS_LOG_I("HksHaPlugin::BatchReportEvents:Finish RemoveReportedEvents");

    return HKS_SUCCESS;
}

int32_t HksHaPluginInit(void)
{
    HKS_LOG_I("Start initialize plugin");
    HksHaPlugin::GetInstance().StartWorkerThread();
    HKS_LOG_I("End initialize plugin");
    return HKS_SUCCESS;
}

void HksHaPluginDestroy()
{
    HksHaPlugin::GetInstance().Destroy();
    HKS_LOG_I("HksHaPlugin_Destroy: HA Plugin destroyed successfully.");
}