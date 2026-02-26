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
#include <securec.h>
#include <set>
#include <sstream>
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
#include "hks_xcollie.h"
#include "huks_service_ipc_interface_code.h"
#include "hks_ha_plugin.h"
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

std::atomic_uint32_t g_sessionId = 0;

namespace OHOS {
namespace Security {
namespace Hks {

const std::string BOOTEVENT_HUKSSERVICE_READY = "bootevent.huksService.ready";
const int32_t MAX_OPERATIONS_EACH_PID = 32;

REGISTER_SYSTEM_ABILITY_BY_ID(HksService, SA_ID_KEYSTORE_SERVICE, true);

std::mutex HksService::instanceLock;
sptr<HksService> HksService::instance;
const uint32_t MAX_MALLOC_LEN = 1 * 1024 * 1024; /* max malloc size 1 MB */

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
    HKS_IF_TRUE_LOGE_RETURN_VOID(pthread_create(&subscribeThread, nullptr, (void *(*)(void *))SubscribEvent,
        nullptr) == -1, "create thread failed")
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

    HKS_IF_TRUE_LOGE_RETURN(outSize > MAX_MALLOC_LEN, HKS_ERROR_INVALID_ARGUMENT,
        "outSize is invalid, size:%" LOG_PUBLIC "u", outSize)

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
    HKS_IF_TRUE_RETURN(instance != nullptr, instance)
    instance = new (std::nothrow) HksService(SA_ID_KEYSTORE_SERVICE, true);
    return instance;
}

bool HksService::Init()
{
    HKS_LOG_I("HksService::Init Ready to init");
    HKS_IF_TRUE_LOGI_RETURN(registerToService_, true, "HksService::Init already finished.")

    int32_t ret = HksServiceInitialize();
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, false, "Init hks service failed!")
    sptr<HksService> ptrInstance = HksService::GetInstance();
    HKS_IF_NULL_LOGE_RETURN(ptrInstance, false, "HksService::Init GetInstance Failed")
    HKS_IF_NOT_TRUE_LOGE_RETURN(Publish(ptrInstance), false, "HksService::Init Publish Failed")

    ret = HksHaPluginInit();
    HKS_IF_NOT_SUCC_LOGE(ret, "Init ha plugin failed!");
    
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

void HksDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remoteObject)
{
    int32_t index = 0;
    while (HksServiceAbortByPid(callingPid_) == HKS_SUCCESS && index < MAX_OPERATIONS_EACH_PID) {
        index++;
    }

    NotifyExtOnBinderDied(callingUid_);

    HKS_LOG_I("The death process[%" LOG_PUBLIC "d] cache has been cleared [%" LOG_PUBLIC "d] operations!",
        callingPid_, index);
}

void HksDeathRecipient::NotifyExtOnBinderDied(int32_t uid)
{
#ifdef SUPPORT_COMMON_EVENT
    OHOS::AAFwk::Want want;
    want.SetAction(COMMON_EVENT_HKS_BINDER_DIED);
    want.SetParam("uid", uid);
    
    OHOS::EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    
    HksPluginOnReceiveEvent(&eventData);
#else
    HKS_LOG_E("not support common event on binder died");
#endif
}

HksDeathRecipient::HksDeathRecipient(int32_t callingPid, int32_t callingUid)
    : callingPid_(callingPid), callingUid_(callingUid) {}

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
        // ReadRemoteObject will fail if huks_service has no selinux permission to call the client side.
        HKS_IF_NULL_LOGE_RETURN(ptr, HKS_ERROR_IPC_INIT_FAIL, "ReadRemoteObject ptr failed")

        HksIpcServiceAttestKey(reinterpret_cast<const HksBlob *>(&srcData),
            reinterpret_cast<const uint8_t *>(&reply), reinterpret_cast<const uint8_t *>(ptr.GetRefPtr()));
        return HKS_SUCCESS;
    } else if (code == HKS_MSG_INIT) {
        sptr<IRemoteObject> remoteObject = data.ReadRemoteObject();
        if (remoteObject != HKS_NULL_POINTER) {
            int32_t callingPid = IPCSkeleton::GetCallingPid();
            int32_t callingUid = IPCSkeleton::GetCallingUid();
            remoteObject->AddDeathRecipient(
                new (std::nothrow) OHOS::Security::Hks::HksDeathRecipient(callingPid, callingUid));
            HKS_LOG_I("Add bundleDead for pid: %" LOG_PUBLIC "d, uid: %" LOG_PUBLIC "d", callingPid, callingUid);
        }
    } else if (code == HKS_MSG_EXT_GET_REMOTE_PROPERTY) {
        auto ptr = data.ReadRemoteObject();
        // ReadRemoteObject will fail if huks_service has no selinux permission to call the client side.
        HKS_IF_NULL_LOGE_RETURN(ptr, HKS_ERROR_IPC_INIT_FAIL, "ReadExtRemoteObject ptr failed")
        HksIpcServiceGetRemoteProperty(reinterpret_cast<const HksBlob *>(&srcData),
            reinterpret_cast<const uint8_t *>(&reply), reinterpret_cast<const uint8_t *>(ptr.GetRefPtr()));
        return HKS_SUCCESS;
    }
    return ProcessMessage(code, outSize, srcData, reply);
}

static void ProcessRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    uint32_t outSize = 0;
    struct HksBlob srcData = { 0, nullptr };
    int32_t ret = HKS_ERROR_INVALID_ARGUMENT;
    do {
        HKS_IF_NOT_TRUE_LOGE_BREAK(data.ReadUint32(outSize), "Read outSize failed!")

        ret = HksPluginOnLocalRequest(CODE_UPGRADE, NULL, NULL);
        HKS_IF_NOT_SUCC_BREAK(ret, "Failed to handle local request. ret = %" LOG_PUBLIC "d", ret);

        ret = HKS_ERROR_INVALID_ARGUMENT;
        HKS_IF_TRUE_LOGE_BREAK(!data.ReadUint32(srcData.size) || IsInvalidLength(srcData.size),
            "srcData size is invalid, size:%" LOG_PUBLIC "u", srcData.size)

        ret = HKS_ERROR_MALLOC_FAIL;
        srcData.data = static_cast<uint8_t *>(HksMalloc(srcData.size));
        HKS_IF_NULL_LOGE_BREAK(srcData.data, "Malloc srcData failed.")

        ret = HKS_ERROR_IPC_MSG_FAIL;
        const uint8_t *pdata = data.ReadBuffer(static_cast<size_t>(srcData.size));
        HKS_IF_NULL_BREAK(pdata)
        (void)memcpy_s(srcData.data, srcData.size, pdata, srcData.size);
        ret = ProcessAttestOrNormalMessage(code, data, outSize, srcData, reply);
    } while (0);

    HKS_FREE_BLOB(srcData);
    HKS_IF_NOT_SUCC_LOGE_RETURN(ret, HksSendResponse(reinterpret_cast<const uint8_t *>(&reply), ret, nullptr),
        "handle ipc msg failed!")
}

static std::string GetTimeoutMonitorMarkTag(uint32_t code, uint32_t callingUid)
{
    std::string markTag = (std::ostringstream{} << "huks:OnRemoteRequest, code = " << code << ", callingUid = " <<
        callingUid << ", sessionId = " << g_sessionId).str();
    return markTag;
}

static void ReportCostTime(uint64_t enterTime, uint64_t leaveTime, uint32_t sessionId, int32_t reply)
{
    if (leaveTime >= enterTime) {
        HKS_LOG_I("cost %" LOG_PUBLIC PRIu64 " ms, sessionId = %" LOG_PUBLIC "u, ret:%" LOG_PUBLIC "d",
            leaveTime - enterTime, sessionId, reply);
    } else {
        HKS_LOG_E("time error. diff: %" LOG_PUBLIC PRIu64 " ms, sessionId = %" LOG_PUBLIC "u, ret:%" LOG_PUBLIC "d",
            enterTime - leaveTime, sessionId, reply);
    }
}

int HksService::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    HksInitMemPolicy();

    uint64_t enterTime = 0;
    (void)HksElapsedRealTime(&enterTime);
    uint32_t currentSessionId = g_sessionId.fetch_add(1, std::memory_order_relaxed);
    auto callingUid = IPCSkeleton::GetCallingUid();
    int userId = HksGetOsAccountIdFromUid(callingUid);

#ifdef L2_STANDARD
    HksClearThreadErrorMsg();
    constexpr unsigned int DEFAULT_TIMEOUT = 5U; // seconds
    HksXCollie hksXCollie(GetTimeoutMonitorMarkTag(code, callingUid), DEFAULT_TIMEOUT, [](void *)->void {}, nullptr,
        HiviewDFX::XCOLLIE_FLAG_LOG);
#endif

    HKS_LOG_I("code:%" LOG_PUBLIC "u, callingUid = %" LOG_PUBLIC "d, userId = %" LOG_PUBLIC
        "d, sessionId = %" LOG_PUBLIC "u", code, callingUid, userId, currentSessionId);

#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    // judge whether is upgrading, wait for upgrade finished
    HKS_IF_NOT_SUCC_LOGE_RETURN(HksWaitIfPowerOnUpgrading(), HW_SYSTEM_ERROR, "wait on upgrading failed.")
    HksUpgradeOrRequestLockRead();
#endif

    if (code < HksIpcInterfaceCode::HKS_MSG_BASE || code >= HksIpcInterfaceCode::HKS_MSG_MAX) {
        int32_t ret = RetryLoadPlugin();
        if (ret != HKS_SUCCESS) {
            HksSendResponse(reinterpret_cast<const uint8_t *>(&reply), ret, nullptr);
            ret = HKS_SUCCESS; // send error code by IPC.
        } else {
            ret = HksPluginOnRemoteRequest(code, &data, &reply, &option);
        }
#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
        HksUpgradeOrRequestUnlockRead();
#endif
        return ret;
    }

    int retSys = NO_ERROR;
    // this is the temporary version which comments the descriptor check
    if (HksService::GetDescriptor() != data.ReadInterfaceToken()) {
        HKS_LOG_E("descriptor is diff.");
        retSys = HW_SYSTEM_ERROR;
    } else {
        ProcessRemoteRequest(code, data, reply);
        uint64_t leaveTime = 0;
        (void)HksElapsedRealTime(&leaveTime);
        ReportCostTime(enterTime, leaveTime, currentSessionId, reply.ReadInt32());
    }

#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    HksUpgradeOrRequestUnlockRead();
#endif
    return retSys;
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
        HKS_IF_NOT_EOK_BREAK(strcpy_s(curPath, DEFAULT_PATH_LEN, oldDir))
        HKS_IF_NOT_EOK_BREAK(strcat_s(curPath, DEFAULT_PATH_LEN, "/"))
        HKS_IF_NOT_EOK_BREAK(strcat_s(curPath, DEFAULT_PATH_LEN, ptr->d_name))
        char newPath[DEFAULT_PATH_LEN] = { 0 };
        HKS_IF_NOT_EOK_BREAK(strcpy_s(newPath, DEFAULT_PATH_LEN, newDir))
        HKS_IF_NOT_EOK_BREAK(strcat_s(newPath, DEFAULT_PATH_LEN, "/"))
        HKS_IF_NOT_EOK_BREAK(strcat_s(newPath, DEFAULT_PATH_LEN, ptr->d_name))
        std::error_code errCode{};
        std::filesystem::create_directory(newDir, errCode);
        HKS_IF_TRUE_LOGE(errCode.value() != 0, "create_directory newDir failed %" LOG_PUBLIC "s",
            errCode.message().c_str())
        std::filesystem::copy(curPath, newPath,
            std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, errCode);
        HKS_IF_TRUE_LOGE_BREAK(errCode.value() != 0, "copy curPath to newPath failed %" LOG_PUBLIC "s",
            errCode.message().c_str())
        std::filesystem::remove_all(curPath, errCode);
        HKS_IF_TRUE_LOGE(errCode.value() != 0, "remove_all curPath failed %" LOG_PUBLIC "s", errCode.message().c_str())
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
    HKS_IF_TRUE_LOGE_RETURN_VOID(errCode.value() != 0, "copy oldDir to newDir failed %" LOG_PUBLIC "s",
        errCode.message().c_str())
    HKS_LOG_I("copy oldDir to newDir ok!");
    std::filesystem::remove_all(oldDir, errCode);
    HKS_IF_TRUE_LOGE_RETURN_VOID(errCode.value() != 0, "remove_all oldDir failed %" LOG_PUBLIC "s",
        errCode.message().c_str())
    HKS_LOG_I("remove_all oldDir ok!");
}

void HksService::OnStart()
{
    HKS_LOG_I("HksService OnStart");
    std::lock_guard<std::mutex> lock(runningStateLock);
    HKS_IF_TRUE_LOGI_RETURN_VOID(std::atomic_load(&runningState_) == STATE_RUNNING, "HksService has already started")
    MoveDirectoryTree(OLD_PATH, NEW_PATH);
#ifdef HKS_USE_RKC_IN_STANDARD
    // the intermediate mine's rkc is located in INTERMEDIATE_MINE_RKC_PATH, normal keys is located in NEW_PATH
    MoveDirectoryTree(INTERMEDIATE_MINE_RKC_PATH, NEW_MINE_RKC_PATH);
    // the original mine's rkc and normal keys are both located in OLD_MINE_PATH, should move all expect for rkc files
    MoveMineOldFile(OLD_MINE_PATH, NEW_PATH);
#endif

    HKS_IF_NOT_SUCC_LOGE_RETURN_VOID(HksProcessConditionCreate(), "create process condition on init failed.")

    // lock before huks init, for the upgrading will be thread safe.
#ifdef HUKS_ENABLE_UPGRADE_KEY_STORAGE_SECURE_LEVEL
    {
        OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> writeGuard(g_upgradeOrRequestLock);
#endif

        HKS_IF_NOT_TRUE_LOGE_RETURN_VOID(Init(), "Failed to init HksService")

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

void HksService::OnAddSystemAbility(int32_t systemAbilityId, [[maybe_unused]] const std::string &deviceId)
{
    HKS_LOG_I("systemAbilityId is %" LOG_PUBLIC "d!", systemAbilityId);
#ifdef SUPPORT_COMMON_EVENT
    HksSubscribeEvent();
#endif
}

void HksService::OnRemoveSystemAbility(int32_t systemAbilityId, [[maybe_unused]] const std::string& deviceId)
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
