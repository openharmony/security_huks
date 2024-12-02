/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "hks_sa.h"

#include <ipc_skeleton.h>
#include <iservice_registry.h>
#include <mutex>
#include <set>
#include <string_ex.h>
#include <system_ability_definition.h>
#include "parameters.h"
#include "hks_client_service.h"
#include "hks_dcm_callback_handler.h"
#include "hks_ipc_service.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_message_handler.h"
#include "hks_plugin_adapter.h"
#include "hks_response.h"
#include "hks_template.h"
#include "hks_type_inner.h"
#include "hks_upgrade.h"
#include "hks_upgrade_lock.h"
#include "hks_util.h"
#include "huks_service_ipc_interface_code.h"
#include "rwlock.h"

#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
#include "malloc.h"
#endif

#ifdef SUPPORT_COMMON_EVENT
#include <pthread.h>
#include <unistd.h>

#include "hks_event_observer.h"
#endif

#include <array>
#include <cinttypes>
#include <filesystem>
#include <string>
#include <system_error>

#ifdef HKS_USE_RKC_IN_STANDARD
#include <dirent.h>
#endif

uint32_t g_sessionId = 0;

namespace OHOS {
namespace Security {
namespace Hks {

const std::string BOOTEVENT_HUKSSERVICE_READY = "bootevent.huksService.ready";

REGISTER_SYSTEM_ABILITY_BY_ID(HksService, SA_ID_KEYSTORE_SERVICE, true);

std::mutex HksService::instanceLock;
sptr<HksService> HksService::instance;
const uint32_t MAX_MALLOC_LEN = 1 * 1024 * 1024; /* max malloc size 1 MB */

static std::mutex g_requestMutex {};

const std::set<uint32_t> g_asyncCodeSet = { HKS_MSG_GEN_KEY, HKS_MSG_IMPORT_KEY, HKS_MSG_IMPORT_WRAPPED_KEY };
constexpr uint32_t HUKS_IPC_THREAD_NUM = 16;
constexpr uint32_t HUKS_IPC_THREAD_NUM_LIMIT = 14;
std::atomic_uint32_t HksIpcCounter::count {};

#ifdef SUPPORT_COMMON_EVENT
const uint32_t MAX_DELAY_TIMES = 100;
#endif

#ifdef SUPPORT_COMMON_EVENT
static void SubscribEvent()
{
    for (uint32_t i = 0; i < MAX_DELAY_TIMES; ++i) {
        if (SystemEventObserver::SubscribeEvent()) {
            HKS_LOG_I("subscribe system event success, i = %" LOG_PUBLIC "u", i);
            pthread_detach(pthread_self());
            return;
        } else {
            HKS_LOG_E("subscribe system event failed %" LOG_PUBLIC "u times", i);
            usleep(HKS_SLEEP_TIME_FOR_RETRY);
        }
    }
    HKS_LOG_E("subscribe system event failed");
    pthread_detach(pthread_self());
    return;
}

static void HksSubscribeEvent()
{
    pthread_t subscribeThread;
    if ((pthread_create(&subscribeThread, nullptr, (void *(*)(void *))SubscribEvent, nullptr)) == -1) {
        HKS_LOG_E("create thread failed");
        return;
    }
    pthread_setname_np(subscribeThread, "HUKS_SUBSCRIBE_THREAD");
    HKS_LOG_I("create thread success");
}
#endif

static inline bool IsInvalidLength(uint32_t length)
{
    return (length == 0) || (length > MAX_MALLOC_LEN);
}

static int32_t ProcessMessage(uint32_t code, uint32_t outSize, const struct HksBlob &srcData, MessageParcel &reply)
{
    uint32_t size = sizeof(HKS_IPC_MESSAGE_HANDLER) / sizeof(HKS_IPC_MESSAGE_HANDLER[0]);
    for (uint32_t i = 0; i < size; ++i) {
        if (code == HKS_IPC_MESSAGE_HANDLER[i].msgId) {
            HKS_IPC_MESSAGE_HANDLER[i].handler(reinterpret_cast<const struct HksBlob *>(&srcData),
                reinterpret_cast<const uint8_t *>(&reply));
            return HKS_SUCCESS;
        }
    }

    if (outSize > MAX_MALLOC_LEN) {
        HKS_LOG_E("outSize is invalid, size:%" LOG_PUBLIC "u", outSize);
        return HKS_ERROR_INVALID_ARGUMENT;
    }

    size = sizeof(HKS_IPC_THREE_STAGE_HANDLER) / sizeof(HKS_IPC_THREE_STAGE_HANDLER[0]);
    for (uint32_t i = 0; i < size; ++i) {
        if (code == HKS_IPC_THREE_STAGE_HANDLER[i].msgId) {
            struct HksBlob outData = { 0, nullptr };
            if (outSize != 0) {
                outData.size = outSize;
                outData.data = static_cast<uint8_t *>(HksMalloc(outData.size));
                HKS_IF_NULL_LOGE_RETURN(outData.data, HKS_ERROR_MALLOC_FAIL, "Malloc outData failed.")
            }
            HKS_IPC_THREE_STAGE_HANDLER[i].handler(reinterpret_cast<const struct HksBlob *>(&srcData), &outData,
                reinterpret_cast<const uint8_t *>(&reply));
            HKS_FREE_BLOB(outData);
            break;
        }
    }
    return HKS_SUCCESS;
}

HksService::HksService(int saId, bool runOnCreate = true)
    : SystemAbility(saId, runOnCreate), registerToService_(false), runningState_(STATE_NOT_START)
{
    HKS_LOG_D("HksService");
}

HksService::~HksService()
{
    HKS_LOG_D("~HksService");
}

sptr<HksService> HksService::GetInstance()
{
    std::lock_guard<std::mutex> autoLock(instanceLock);
    if (instance == nullptr) {
        instance = new (std::nothrow) HksService(SA_ID_KEYSTORE_SERVICE, true);
    }

    return instance;
}

bool HksService::Init()
{
    HKS_LOG_I("HksService::Init Ready to init");
    if (registerToService_) {
        HKS_LOG_I("HksService::Init already finished.");
        return true;
    }

    int32_t ret = HksServiceInitialize();
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, false, "Init hks service failed!")
    sptr<HksService> ptrInstance = HksService::GetInstance();
    HKS_IF_NULL_LOGE_RETURN(ptrInstance, false, "HksService::Init GetInstance Failed")
    if (!Publish(ptrInstance)) {
        HKS_LOG_E("HksService::Init Publish Failed");
        return false;
    }
    HKS_LOG_I("HksService::Init Publish service success");
    registerToService_ = true;

    if (!system::GetBoolParameter(BOOTEVENT_HUKSSERVICE_READY.c_str(), false)) {
        system::SetParameter(BOOTEVENT_HUKSSERVICE_READY.c_str(), "true");
        HKS_LOG_E("set bootevent.huksService.ready true");
    }
    HKS_LOG_I("HksService::Init success.");
    return true;
}

static void HksInitMemPolicy(void)
{
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    // disable mem cache and delay free because the size of mem data in HUKS is associated with caller tasks and
    // changeable, which is not suitable for this case
    (void)mallopt(M_SET_THREAD_CACHE, M_THREAD_CACHE_DISABLE);
    (void)mallopt(M_DELAYED_FREE, M_DELAYED_FREE_DISABLE);
#endif
}

static int32_t ProcessAttestOrNormalMessage(
    uint32_t code, MessageParcel &data, uint32_t outSize, const struct HksBlob &srcData, MessageParcel &reply)
{
    // Since we have wrote a HksStub instance in client side, we can now read it if it is anonymous attestation.
    if (code == HKS_MSG_ATTEST_KEY) {
        HksIpcServiceAttestKey(reinterpret_cast<const HksBlob *>(&srcData),
            reinterpret_cast<const uint8_t *>(&reply), nullptr);
        return HKS_SUCCESS;
    } else if (code == HKS_MSG_ATTEST_KEY_ASYNC_REPLY) {
        auto ptr = data.ReadRemoteObject();
        if (ptr == nullptr) {
            // ReadRemoteObject will fail if huks_service has no selinux permission to call the client side.
            HKS_LOG_E("ReadRemoteObject ptr failed");
            return HKS_ERROR_IPC_INIT_FAIL;
        }

        HksIpcServiceAttestKey(reinterpret_cast<const HksBlob *>(&srcData),
            reinterpret_cast<const uint8_t *>(&reply), reinterpret_cast<const uint8_t *>(ptr.GetRefPtr()));
        return HKS_SUCCESS;
    } else {
        return ProcessMessage(code, outSize, srcData, reply);
    }
}

static void ProcessRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    uint32_t outSize = 0;
    struct HksBlob srcData = { 0, nullptr };
    int32_t ret = HKS_ERROR_INVALID_ARGUMENT;
    do {
        if (!data.ReadUint32(outSize)) {
            HKS_LOG_E("Read outSize failed!");
            break;
        }

        ret = HksPluginOnLocalRequest(CODE_UPGRADE, NULL, NULL);
        HKS_IF_NOT_SUCC_BREAK(ret, "Failed to handle local request. ret = %" LOG_PUBLIC "d", ret);

        if (!data.ReadUint32(srcData.size) || IsInvalidLength(srcData.size)) {
            HKS_LOG_E("srcData size is invalid, size:%" LOG_PUBLIC "u", srcData.size);
            ret = HKS_ERROR_INVALID_ARGUMENT;
            break;
        }

        srcData.data = static_cast<uint8_t *>(HksMalloc(srcData.size));
        if (srcData.data == nullptr) {
            HKS_LOG_E("Malloc srcData failed.");
            ret = HKS_ERROR_MALLOC_FAIL;
            break;
        }

        const uint8_t *pdata = data.ReadBuffer(static_cast<size_t>(srcData.size));
        if (pdata == nullptr) {
            ret = HKS_ERROR_IPC_MSG_FAIL;
            break;
        }
        (void)memcpy_s(srcData.data, srcData.size, pdata, srcData.size);
        ret = ProcessAttestOrNormalMessage(code, data, outSize, srcData, reply);
    } while (0);

    HKS_FREE_BLOB(srcData);

    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("handle ipc msg failed!");
        HksSendResponse(reinterpret_cast<const uint8_t *>(&reply), ret, nullptr);
    }
}

int HksService::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    g_requestMutex.lock();

    if (HksIpcCounter::count >= HUKS_IPC_THREAD_NUM_LIMIT && g_asyncCodeSet.count(code) == 1) {
        HKS_LOG_E("ipc thread num is insufficient");
        HksSendResponse(reinterpret_cast<const uint8_t *>(&reply), HUKS_ERR_CODE_SESSION_LIMIT, nullptr);
        g_requestMutex.unlock();
        return HUKS_ERR_CODE_SESSION_LIMIT;
    }

    HksIpcCounter ipcCounter {};
    g_requestMutex.unlock();

    HksInitMemPolicy();

    uint64_t enterTime = 0;
    (void)HksElapsedRealTime(&enterTime);
    g_sessionId++;
    auto callingUid = IPCSkeleton::GetCallingUid();
    int userId = HksGetOsAccountIdFromUid(callingUid);

    HKS_LOG_I("OnRemoteRequest code:%" LOG_PUBLIC "u,  callingUid = %" LOG_PUBLIC "d, userId = %" LOG_PUBLIC
        "d, sessionId = %" LOG_PUBLIC "u", code, callingUid, userId, g_sessionId);

#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    // judge whether is upgrading, wait for upgrade finished
    if (HksWaitIfPowerOnUpgrading() != HKS_SUCCESS) {
        HKS_LOG_E("wait on upgrading failed.");
        return HW_SYSTEM_ERROR;
    }
    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> readGuard(g_upgradeOrRequestLock);
#endif

    if (code < HksIpcInterfaceCode::HKS_MSG_BASE || code >= HksIpcInterfaceCode::HKS_MSG_MAX) {
        int32_t ret = RetryLoadPlugin();
        if (ret != HKS_SUCCESS) {
            HksSendResponse(reinterpret_cast<const uint8_t *>(&reply), ret, nullptr);
            return HKS_SUCCESS; // send error code by IPC.
        }
        return HksPluginOnRemoteRequest(code, &data, &reply, &option);
    }
    // this is the temporary version which comments the descriptor check
    if (HksService::GetDescriptor() != data.ReadInterfaceToken()) {
        HKS_LOG_E("descriptor is diff.");
        return HW_SYSTEM_ERROR;
    }

    ProcessRemoteRequest(code, data, reply);

    uint64_t leaveTime = 0;
    (void)HksElapsedRealTime(&leaveTime);
    HKS_LOG_I("finish code:%" LOG_PUBLIC "d, total cost %" LOG_PUBLIC PRIu64 " ms, sessionId = %"
        LOG_PUBLIC "u", code, leaveTime - enterTime, g_sessionId);

    return NO_ERROR;
}

#define OLD_PATH "/data/service/el2/public/huks_service/maindata"
#define NEW_PATH "/data/service/el1/public/huks_service/maindata"

#ifdef HKS_USE_RKC_IN_STANDARD
#define OLD_MINE_PATH "/data/data/huks_service/maindata"
#define INTERMEDIATE_MINE_RKC_PATH "/data/service/el1/public/huks_service/maindata/hks_client"
#define NEW_MINE_RKC_PATH "/data/data/huks_service/maindata/hks_client"

#define DEFAULT_PATH_LEN 1024
#endif

#ifdef HKS_USE_RKC_IN_STANDARD
void MoveMineOldFile(const char *oldDir, const char *newDir)
{
    auto dir = opendir(oldDir);
    HKS_IF_NULL_LOGE_RETURN_VOID(dir, "open old dir failed!")
    struct dirent *ptr;
    while ((ptr = readdir(dir)) != NULL) {
        // move dir expect hks_client, for it is the rkc root key and should be in same position
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0 || strcmp(ptr->d_name, "hks_client") == 0) {
            continue;
        }
        char curPath[DEFAULT_PATH_LEN] = { 0 };
        if (strcpy_s(curPath, DEFAULT_PATH_LEN, oldDir) != EOK) {
            break;
        }
        if (strcat_s(curPath, DEFAULT_PATH_LEN, "/") != EOK) {
            break;
        }
        if (strcat_s(curPath, DEFAULT_PATH_LEN, ptr->d_name) != EOK) {
            break;
        }
        char newPath[DEFAULT_PATH_LEN] = { 0 };
        if (strcpy_s(newPath, DEFAULT_PATH_LEN, newDir) != EOK) {
            break;
        }
        if (strcat_s(newPath, DEFAULT_PATH_LEN, "/") != EOK) {
            break;
        }
        if (strcat_s(newPath, DEFAULT_PATH_LEN, ptr->d_name) != EOK) {
            break;
        }
        std::error_code errCode{};
        std::filesystem::create_directory(newDir, errCode);
        if (errCode.value() != 0) {
            HKS_LOG_E("create_directory newDir failed %" LOG_PUBLIC "s", errCode.message().c_str());
        }
        std::filesystem::copy(curPath, newPath,
            std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, errCode);
        if (errCode.value() != 0) {
            HKS_LOG_E("copy curPath to newPath failed %" LOG_PUBLIC "s", errCode.message().c_str());
            break;
        }
        std::filesystem::remove_all(curPath, errCode);
        if (errCode.value() != 0) {
            HKS_LOG_E("remove_all curPath failed %" LOG_PUBLIC "s", errCode.message().c_str());
        }
    }
    closedir(dir);
}
#endif

void MoveDirectoryTree(const char *oldDir, const char *newDir)
{
    std::error_code errCode{};
    std::filesystem::create_directory(newDir, errCode);
    if (errCode.value() != 0) {
        HKS_LOG_E("create_directory newDir failed %" LOG_PUBLIC "s", errCode.message().c_str());
    } else {
        HKS_LOG_I("create_directory newDir ok!");
    }
    std::filesystem::copy(oldDir, newDir,
        std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, errCode);
    if (errCode.value() != 0) {
        HKS_LOG_E("copy oldDir to newDir failed %" LOG_PUBLIC "s", errCode.message().c_str());
        return;
    }
    HKS_LOG_I("copy oldDir to newDir ok!");
    std::filesystem::remove_all(oldDir, errCode);
    if (errCode.value() != 0) {
        HKS_LOG_E("remove_all oldDir failed %" LOG_PUBLIC "s", errCode.message().c_str());
        return;
    }
    HKS_LOG_I("remove_all oldDir ok!");
}

void HksService::OnStart()
{
    HKS_LOG_I("HksService OnStart");
    std::lock_guard<std::mutex> lock(runningStateLock);
    if (std::atomic_load(&runningState_) == STATE_RUNNING) {
        HKS_LOG_I("HksService has already started");
        return;
    }
    MoveDirectoryTree(OLD_PATH, NEW_PATH);
#ifdef HKS_USE_RKC_IN_STANDARD
    // the intermediate mine's rkc is located in INTERMEDIATE_MINE_RKC_PATH, normal keys is located in NEW_PATH
    MoveDirectoryTree(INTERMEDIATE_MINE_RKC_PATH, NEW_MINE_RKC_PATH);
    // the original mine's rkc and normal keys are both located in OLD_MINE_PATH, should move all expect for rkc files
    MoveMineOldFile(OLD_MINE_PATH, NEW_PATH);
#endif

    if (HksProcessConditionCreate() != HKS_SUCCESS) {
        HKS_LOG_E("create process condition on init failed.");
        return;
    }

    // lock before huks init, for the upgrading will be thread safe.
#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    {
        OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> writeGuard(g_upgradeOrRequestLock);
#endif

        if (!Init()) {
            HKS_LOG_E("Failed to init HksService");
            return;
        }

        #ifdef SUPPORT_COMMON_EVENT
            (void)AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
        #endif

        // this should be excuted after huks published and listener added.
        HksUpgradeOnPowerOn();
#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    }
    HksUpgradeOnPowerOnDoneNotifyAll();
#endif

    std::atomic_store(&runningState_, STATE_RUNNING);
    IPCSkeleton::SetMaxWorkThreadNum(HUKS_IPC_THREAD_NUM);
    HKS_LOG_I("HksService start success.");
}

void HksService::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    HKS_LOG_I("systemAbilityId is %" LOG_PUBLIC "d!", systemAbilityId);
#ifdef SUPPORT_COMMON_EVENT
    HksSubscribeEvent();
#endif
}

void HksService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    HKS_LOG_I("systemAbilityId is %" LOG_PUBLIC "d!", systemAbilityId);
}

void HksService::OnStop()
{
    HKS_LOG_I("HksService Service OnStop");
    std::lock_guard<std::mutex> lock(runningStateLock);
    std::atomic_store(&runningState_, STATE_NOT_START);
    registerToService_ = false;
#ifndef HKS_UNTRUSTED_RUNNING_ENV
    HksCloseDcmFunction();
#endif // HKS_UNTRUSTED_RUNNING_ENV
}
} // namespace Hks
} // namespace Security
} // namespace OHOS
