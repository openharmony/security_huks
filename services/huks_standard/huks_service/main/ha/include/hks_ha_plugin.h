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

#ifndef HKS_HA_PLUGIN_H
#define HKS_HA_PLUGIN_H

#include "hks_ha_event_queue.h"
#include "hks_event_info.h"
#include "hks_event_types.h"
#include "hks_type.h"
#include "hks_log.h"
#include "hks_mem.h"
#include <memory>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <list>
#include <string>
#include <cstdint>
#include <ctime>
#include <singleton.h>

constexpr uint32_t MAX_CACHE_SIZE = 50;
constexpr time_t MAX_CACHE_DURATION = 3600; // Unit: seconds

typedef struct {
    struct HksEventCommonInfo common;
    std::unordered_map<std::string, std::string> eventMap;
} HksEventWithMap;

typedef struct {
    uint32_t eventId;
    time_t timestamp;
    struct HksEventInfo *data;
} HksEventCacheNode;

class HksEventCacheList {
public:
    HksEventCacheList() {}

    void Add(const HksEventCacheNode& node)
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        cacheList.emplace_back(node);
    }
    
    bool FindAndUpdate(struct HksEventInfo *eventInfo, HksEventProcMap *procMap)
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        for (auto& node : cacheList) {
            if (procMap->eventInfoEqual(node.data, eventInfo)) {
                procMap->eventInfoAdd(node.data, eventInfo);
                return true;
            }
        }
        return false;
    }
    
    uint32_t GetSize() const
    {
        return cacheList.size();
    }

    void RemoveFront(uint32_t count)
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        auto it = cacheList.begin();
        for (uint32_t i = 0; i < count && it != cacheList.end(); ++i, ++it) {
            if (it->data != nullptr) {
                HKS_FREE(it->data->common.function);
                HKS_FREE(it->data->common.callerInfo.name);
                HKS_FREE(it->data->common.result.errMsg);
                if (IF_UKEY_EVENT(it->data->common.eventId)) {
                    HKS_FREE(it->data->ukeyInfo.providerName);
                    HKS_FREE(it->data->ukeyInfo.abilityName);
                    HKS_FREE(it->data->ukeyInfo.resourceId);
                    HKS_FREE(it->data->ukeyInfo.propertyId);
                }
                HKS_FREE(it->data);
            }
        }
        cacheList.erase(cacheList.begin(), it);
    }

    std::list<HksEventCacheNode> cacheList;
private:
    mutable std::mutex queueMutex_;
};

class HksHaPlugin : public OHOS::Singleton<HksHaPlugin> {
public:
    HksHaPlugin();

    ~HksHaPlugin();

    void Destroy();

    void StartWorkerThread();

    void StopWorkerThread();

    void HandleEvent(uint32_t eventId, struct HksParamSet *reportParamSet);

    bool Enqueue(uint32_t eventId, struct HksParamSet *paramSet);

    int32_t RegisterEventProc(const struct HksEventProcMap *procMap);

    int32_t RegisterEventProcs(const struct HksEventProcMap *procMaps, uint32_t count);

    int32_t UnregisterEventProc(uint32_t eventId);

    void ClearAllEventProcs();
    
    uint32_t GetEventProcCount() const;

private:
    HksEventQueue queue;
    std::thread workerThread;
    std::atomic<bool> stopFlag;
    HksEventCacheList eventCacheList;

    std::vector<HksEventProcMap> eventProcList;
    mutable std::mutex eventProcMutex;

    void WorkerThread();

    void AddEventCache(uint32_t eventId, struct HksEventInfo *eventInfo);

    int32_t FillEventInfos(uint32_t reportCount, HksEventWithMap *eventsWithMap);

    int32_t CallBatchReport(uint32_t reportCount, HksEventWithMap *eventsWithMap);

    void RemoveReportedEvents(uint32_t reportCount);

    int32_t BatchReportEvents(uint32_t reportCount);

    void HandleFaultEvent(struct HksEventCommonInfo *eventInfo, std::unordered_map<std::string, std::string> &eventMap);

    void HandleStatisticEvent(struct HksEventInfo *eventInfo, uint32_t eventId, HksEventProcMap *procMap);

    HksEventProcMap* HksEventProcFind(uint32_t eventId);

    void HandlerReport(HksEventQueueItem &item);

    void InitDefaultEventProcs();

    bool IsValidEventProcMap(const struct HksEventProcMap *procMap) const;
};

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksHaPluginInit(void);

void HksHaPluginDestroy(HksHaPlugin *plugin);

// 供HksBasicInterface调用
int32_t HksRegisterEventProcWrapper(const struct HksEventProcMap *procMap);

int32_t HksRegisterEventProcs(const struct HksEventProcMap *procMaps, uint32_t count);

int32_t HksUnregisterEventProcWrapper(uint32_t eventId);

int32_t HksEnqueueEventWrapper(uint32_t eventId, struct HksParamSet *paramSet);

#ifdef __cplusplus
}
#endif

#endif