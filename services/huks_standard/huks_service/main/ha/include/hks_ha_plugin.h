#ifndef HKS_HA_PLUGIN_H
#define HKS_HA_PLUGIN_H

#include "hks_ha_event_queue.h"
#include "hks_event_info.h"
#include "hks_type.h"
#include "hks_log.h"
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


constexpr uint32_t MAX_CACHE_SIZE = 30;
constexpr time_t MAX_CACHE_DURATION = 600; // 单位秒

typedef int32_t (*HksParamSetToEventInfo)(const struct HksParamSet *paramSet, struct HksEventInfo *keyInfo);

typedef bool (*HksEventInfoNeedReport)(const struct HksEventInfo *eventInfo);

typedef bool (*HksEventInfoIsEqual)(const struct HksEventInfo *info1, const struct HksEventInfo *info2);

typedef void (*HksEventInfoAdd)(struct HksEventInfo *info, const struct HksEventInfo *entry);

typedef int32_t (*HksEventInfoToMap)(const struct HksEventInfo *info, std::unordered_map<std::string, std::string>& map);

typedef struct {
    uint32_t eventId;
    HksParamSetToEventInfo eventInfoCreate;
    HksEventInfoNeedReport needReport;
    HksEventInfoIsEqual eventInfoEqual;
    HksEventInfoAdd eventInfoAdd;
    HksEventInfoToMap eventInfoToMap;
} HksEventProcMap;

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
    
    void Add(const HksEventCacheNode& node) {
        std::lock_guard<std::mutex> lock(queueMutex);
        cacheList.emplace_back(node);
    }
    
    bool FindAndUpdate(struct HksEventInfo *eventInfo, HksEventProcMap *procMap) {
        std::lock_guard<std::mutex> lock(queueMutex);
        for (auto& node : cacheList) {
            if (procMap->eventInfoEqual(node.data, eventInfo)) {
                procMap->eventInfoAdd(node.data, eventInfo);
                return true;
            }
        }
        return false;
    }

    std::list<HksEventCacheNode>& GetList() { return cacheList; }
    
    uint32_t GetSize() const {
        std::lock_guard<std::mutex> lock(queueMutex);
        return cacheList.size();
    }
    
    void RemoveFront(uint32_t count) {
        std::lock_guard<std::mutex> lock(queueMutex);
        if (count <= cacheList.size()) {
            auto it = cacheList.begin();
            std::advance(it, count);
            cacheList.erase(cacheList.begin(), it);
        }
    }

private:
    std::list<HksEventCacheNode> cacheList;
    mutable std::mutex queueMutex;
};

class HksHaPlugin : public OHOS::Singleton<HksHaPlugin>{
public:
    HksHaPlugin();

    ~HksHaPlugin();

    void Destroy();

    void StartWorkerThread();

    void StopWorkerThread();

    void HandleEvent(uint32_t eventId, struct HksParamSet *reportParamSet);

    bool Enqueue(uint32_t eventId, struct HksParamSet *paramSet);

private:

    HksEventQueue queue;
    std::thread workerThread;
    std::atomic<bool> stopFlag;
    HksEventCacheList eventCacheList;
    std::vector<HksEventProcMap *> eventProcMap;

    void WorkerThread();

    void AddEventCache(uint32_t eventId, struct HksEventInfo *eventInfo);

    int32_t FillEventInfos(uint32_t reportCount, HksEventWithMap *eventsWithMap);

    int32_t CallBatchReport(uint32_t reportCount, HksEventWithMap *eventsWithMap);

    void RemoveReportedEvents(uint32_t reportCount);

    int32_t BatchReportEvents(uint32_t reportCount);

    void HandleFaultEvent(struct HksEventCommonInfo *eventInfo, std::unordered_map<std::string, std::string> &eventMap);

    void HandleStatisticEvent(struct HksEventInfo *eventInfo, uint32_t eventId,  HksEventProcMap * procMap);

    HksEventProcMap* HksEventProcFind(uint32_t eventId);

    void HandlerReport(HksEventQueueItem item);
};

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksHaPluginInit(void);

void HksHaPluginDestroy(HksHaPlugin *plugin);

#ifdef __cplusplus
}
#endif

#endif // HKS_HA_PLUGIN_H