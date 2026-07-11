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
#include "hks_report_common.h"
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

// Cache size budget: total entries across all event buckets capped at this value.
// Each event's bucket size = WEIGHT / TOTAL_WEIGHT * CACHE_SIZE_TOTAL (min 2).
// Adding new events only redistributes the budget — total never exceeds this cap.
constexpr uint32_t CACHE_SIZE_TOTAL = 300;
constexpr uint32_t CACHE_WEIGHT_HIGH   = 5;  // Cipher/Mac: high-frequency, many unique caller combos
constexpr uint32_t CACHE_WEIGHT_MID    = 2;  // SignVerify/GenerateKey/Attest/DeleteKey/ImportKey/Derive/Agree
constexpr uint32_t CACHE_WEIGHT_LOW    = 1;  // KeyExist/ListAliases/RenameKey/GetProperties
constexpr uint32_t CACHE_WEIGHT_SYSTEM = 1;  // DataSize: single aggregated entry
constexpr time_t MAX_CACHE_DURATION = 3600;  // Unit: seconds

typedef struct {
    struct HksEventCommonInfo common;
    std::unordered_map<std::string, std::string> eventMap;
} HksEventWithMap;

typedef struct {
    uint32_t eventId;
    time_t timestamp;
    struct HksEventInfo *data;
    bool isAncoCall;
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
                FreeCommonEventInfo(it->data);
                if (IF_UKEY_EVENT(it->data->common.eventId)) {
                    HKS_FREE(it->data->ukeyInfo.providerName);
                    HKS_FREE(it->data->ukeyInfo.abilityName);
                    HKS_FREE(it->data->ukeyInfo.resourceId);
                    HKS_FREE(it->data->ukeyInfo.propertyId);
                }
                if (it->data->common.eventId == HKS_EVENT_DATA_SIZE_STATISTICS) {
                    HKS_FREE(it->data->dataSizeInfo.component);
                    HKS_FREE(it->data->dataSizeInfo.partition);
                    HKS_FREE(it->data->dataSizeInfo.foldPath);
                    HKS_FREE(it->data->dataSizeInfo.foldSize);
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

private:
    HksEventQueue queue{};
    std::thread workerThread{};
    std::atomic<bool> stopFlag{};
    std::unordered_map<uint32_t, HksEventCacheList> businessCacheMap{};

    std::vector<HksEventProcMap> eventProcList = {
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
    #ifdef HKS_UKEY_EXTENSION_CRYPTO
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
        },
        {
            HKS_EVENT_UKEY_IMPORT_CERT,
            HksImportCertParamSetToEventInfo,
            HksImportCertNeedReport,
            HksImportCertEventInfoEqual,
            HksEventInfoAddForImportCert,
            HksImportCertEventInfoToMap,
        },
        {
            HKS_EVENT_UKEY_GET_RESOURCE_ID,
            HksGetResourceIdParamSetToEventInfo,
            HksGetResourceIdNeedReport,
            HksGetResourceIdEventInfoEqual,
            HksEventInfoAddForGetResourceId,
            HksGetResourceIdEventInfoToMap,
        },
        {
            HKS_EVENT_UKEY_CLEAR_PIN_STATE,
            HksClearPinStateParamSetToEventInfo,
            HksClearPinStateNeedReport,
            HksClearPinStateEventInfoEqual,
            HksEventInfoAddForClearPinState,
            HksClearPinStateEventInfoToMap,
        },
        {
            HKS_EVENT_UKEY_INIT_SESSION,
            HksInitSessionParamSetToEventInfo,
            HksInitSessionNeedReport,
            HksInitSessionEventInfoEqual,
            HksEventInfoAddForInitSession,
            HksInitSessionEventInfoToMap,
        },
        {
            HKS_EVENT_UKEY_UPDATE_SESSION,
            HksUpdateSessionParamSetToEventInfo,
            HksUpdateSessionNeedReport,
            HksUpdateSessionEventInfoEqual,
            HksEventInfoAddForUpdateSession,
            HksUpdateSessionEventInfoToMap,
        },
        {
            HKS_EVENT_UKEY_FINISH_SESSION,
            HksFinishSessionParamSetToEventInfo,
            HksFinishSessionNeedReport,
            HksFinishSessionEventInfoEqual,
            HksEventInfoAddForFinishSession,
            HksFinishSessionEventInfoToMap,
        },
        {
            HKS_EVENT_UKEY_ABORT_SESSION,
            HksAbortSessionParamSetToEventInfo,
            HksAbortSessionNeedReport,
            HksAbortSessionEventInfoEqual,
            HksEventInfoAddForAbortSession,
            HksAbortSessionEventInfoToMap,
        },
        {
            HKS_EVENT_UKEY_GENERATE_KEY,
            HksGenerateKeyParamSetToEventInfo,
            HksGenerateKeyNeedReport,
            HksGenerateKeyEventInfoEqual,
            HksEventInfoAddForGenerateKey,
            HksGenerateKeyEventInfoToMap,
        },
        {
            HKS_EVENT_UKEY_EXPORT_PUBLIC_KEY,
            HksExportPublicKeyParamSetToEventInfo,
            HksExportPublicKeyNeedReport,
            HksExportPublicKeyEventInfoEqual,
            HksEventInfoAddForExportPublicKey,
            HksExportPublicKeyEventInfoToMap,
        },
        {
            HKS_EVENT_UKEY_IMPORT_WRAPPED_KEY,
            HksImportWrappedKeyParamSetToEventInfo,
            HksImportWrappedKeyNeedReport,
            HksImportWrappedKeyEventInfoEqual,
            HksEventInfoAddForImportWrappedKey,
            HksImportWrappedKeyEventInfoToMap,
        },
        {
            HKS_EVENT_UKEY_SET_REMOTE_PROPERTY,
            HksSetPropertyParamSetToEventInfo,
            HksSetPropertyNeedReport,
            HksSetPropertyEventInfoEqual,
            HksEventInfoAddForSetProperty,
            HksSetPropertyEventInfoToMap,
        },
    #endif
        {
            HKS_EVENT_DATA_SIZE_STATISTICS,
            HksParamSetToEventInfoForDataSize,
            HksEventInfoIsNeedReportForDataSize,
            HksEventInfoIsEqualForDataSize,
            HksEventInfoAddForDataSize,
            HksEventInfoToMapForDataSize
        }
    };

    mutable std::mutex eventProcMutex{};

    void WorkerThread();

    void AddEventCache(uint32_t eventId, struct HksEventInfo *eventInfo, bool isAncoCall);

    int32_t FillEventInfos(uint32_t eventId, uint32_t reportCount, HksEventWithMap *eventsWithMap);

    int32_t CallBatchReport(uint32_t reportCount, HksEventWithMap *eventsWithMap);

    void RemoveReportedEvents(uint32_t eventId, uint32_t reportCount);

    int32_t BatchReportEvents(uint32_t eventId, uint32_t reportCount);

    void HandleFaultEvent(struct HksEventCommonInfo *eventInfo, std::unordered_map<std::string, std::string> &eventMap);

    void HandleStatisticEvent(struct HksEventInfo *eventInfo, uint32_t eventId, HksEventProcMap *procMap,
        bool isAncoCall);

    HksEventProcMap* HksEventProcFind(uint32_t eventId);

    void HandlerReport(HksEventQueueItem &item);

    bool IsValidEventProcMap(const struct HksEventProcMap *procMap) const;

    uint32_t GetCacheSizeByEventId(uint32_t eventId) const;

    uint32_t GetCacheWeightByEventId(uint32_t eventId) const;

    uint32_t GetTotalCacheWeight() const;
};

#ifdef __cplusplus
extern "C" {
#endif

int32_t HksHaPluginInit(void);

void HksHaPluginDestroy(HksHaPlugin *plugin);

int32_t HksRegisterEventProcWrapper(const void *procMap);

int32_t HksRegisterEventProcs(const void *procMaps, uint32_t count);

int32_t HksEnqueueEventWrapper(uint32_t eventId, struct HksParamSet *paramSet);

#ifdef __cplusplus
}
#endif

#endif