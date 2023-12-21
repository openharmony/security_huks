/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

#include "hks_client_service.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_message_handler.h"
#include "hks_template.h"
#include "hks_util.h"

#include "hks_response.h"

#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
#include "malloc.h"
#endif

#ifdef SUPPORT_COMMON_EVENT
#include <pthread.h>
#include <unistd.h>

#include "hks_event_observer.h"
#endif

#include <filesystem>
#include <string>
#include <system_error>

#ifdef HKS_USE_RKC_IN_STANDARD
#include <dirent.h>
#endif

namespace OHOS {
namespace Security {
namespace Hks {
REGISTER_SYSTEM_ABILITY_BY_ID(HksService, SA_ID_KEYSTORE_SERVICE, true);

std::mutex HksService::instanceLock;
sptr<HksService> HksService::instance;
const uint32_t MAX_MALLOC_LEN = 1 * 1024 * 1024; /* max malloc size 1 MB */
#define HUKS_IPC_THREAD_NUM 2
#ifdef SUPPORT_COMMON_EVENT
const uint32_t MAX_DELAY_TIMES = 100;
const uint32_t DELAY_INTERVAL = 200000; /* delay 200ms waiting for system event */
#endif

#ifdef SUPPORT_COMMON_EVENT
static void SubscribEvent()
{
    for (uint32_t i = 0; i < MAX_DELAY_TIMES; ++i) {
        if (SystemEventObserver::SubscribeSystemEvent()) {
            HKS_LOG_I("subscribe system event success, i = %" LOG_PUBLIC "u", i);
            pthread_detach(pthread_self());
            return;
        } else {
            HKS_LOG_E("subscribe system event failed %" LOG_PUBLIC "u times", i);
            usleep(DELAY_INTERVAL);
        }
    }
    HKS_LOG_E("subscribe system event failed");
    pthread_detach(pthread_self());
    return;
}

static void HksSubscribeSystemEvent()
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

    size = sizeof(HKS_IPC_THREE_STAGE_HANDLER) / sizeof(HKS_IPC_THREE_STAGE_HANDLER[0]);
    for (uint32_t i = 0; i < size; ++i) {
        if (code == HKS_IPC_THREE_STAGE_HANDLER[i].msgId) {
            struct HksBlob outData = { 0, nullptr };
            if (outSize != 0) {
                outData.size = outSize;
                if (outData.size > MAX_MALLOC_LEN) {
                    HKS_LOG_E("outData size is invalid, size:%" LOG_PUBLIC "u", outData.size);
                    return HKS_ERROR_INVALID_ARGUMENT;
                }
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

int HksService::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    HksInitMemPolicy();
    // this is the temporary version which comments the descriptor check
    std::u16string descriptor = HksService::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HKS_LOG_E("descriptor is diff.");
        return HW_SYSTEM_ERROR;
    }

    uint64_t enterTime = 0;
    (void)HksElapsedRealTime(&enterTime);
    HKS_LOG_I("OnRemoteRequest code:%" LOG_PUBLIC "d, enter time is %" LOG_PUBLIC "llu ms", code, enterTime);

    // check that the code is valid
    if (code < HksIpcInterfaceCode::HKS_MSG_BASE || code >= HksIpcInterfaceCode::HKS_MSG_MAX) {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    uint32_t outSize = static_cast<uint32_t>(data.ReadUint32());
    struct HksBlob srcData = { 0, nullptr };
    int32_t ret = HKS_SUCCESS;
    do {
        srcData.size = static_cast<uint32_t>(data.ReadUint32());
        if (IsInvalidLength(srcData.size)) {
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

        ret = ProcessMessage(code, outSize, srcData, reply);
    } while (0);

    HKS_FREE_BLOB(srcData);

    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("handle ipc msg failed!");
        HksSendResponse(reinterpret_cast<const uint8_t *>(&reply), ret, nullptr);
    }

    uint64_t leaveTime = 0;
    (void)HksElapsedRealTime(&leaveTime);
    HKS_LOG_I("finish code:%" LOG_PUBLIC "d, leave time is %" LOG_PUBLIC "llu ms, total cost %" LOG_PUBLIC "llu ms",
        code, leaveTime, leaveTime - enterTime);

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
    if (dir == NULL) {
        HKS_LOG_E("open old dir failed!");
        return;
    }
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
            HKS_LOG_E("create_directory %" LOG_PUBLIC "s failed %" LOG_PUBLIC "s", newPath, errCode.message().c_str());
        }
        std::filesystem::copy(curPath, newPath,
            std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, errCode);
        if (errCode.value() != 0) {
            HKS_LOG_E("copy %" LOG_PUBLIC "s to %" LOG_PUBLIC "s failed %" LOG_PUBLIC "s",
                curPath, newPath, errCode.message().c_str());
            return;
        }
        std::filesystem::remove_all(curPath, errCode);
        if (errCode.value() != 0) {
            HKS_LOG_E("remove_all %" LOG_PUBLIC "s failed %" LOG_PUBLIC "s", curPath, errCode.message().c_str());
        }
    }
}
#endif

void MoveDirectoryTree(const char *oldDir, const char *newDir)
{
    std::error_code errCode{};
    std::filesystem::create_directory(newDir, errCode);
    if (errCode.value() != 0) {
        HKS_LOG_E("create_directory %" LOG_PUBLIC "s failed %" LOG_PUBLIC "s", newDir, errCode.message().c_str());
    } else {
        HKS_LOG_I("create_directory %" LOG_PUBLIC "s ok!", newDir);
    }
    std::filesystem::copy(oldDir, newDir,
        std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing, errCode);
    if (errCode.value() != 0) {
        HKS_LOG_E("copy %" LOG_PUBLIC "s to %" LOG_PUBLIC "s failed %" LOG_PUBLIC "s",
            oldDir, newDir, errCode.message().c_str());
        return;
    }
    HKS_LOG_I("copy %" LOG_PUBLIC "s to %" LOG_PUBLIC "s ok!", oldDir, newDir);
    std::filesystem::remove_all(oldDir, errCode);
    if (errCode.value() != 0) {
        HKS_LOG_E("remove_all %" LOG_PUBLIC "s failed %" LOG_PUBLIC "s", oldDir, errCode.message().c_str());
        return;
    }
    HKS_LOG_I("remove_all %" LOG_PUBLIC "s ok!", oldDir);
}

void HksService::OnStart()
{
    HKS_LOG_I("HksService OnStart");
    MoveDirectoryTree(OLD_PATH, NEW_PATH);
#ifdef HKS_USE_RKC_IN_STANDARD
    // the intermediate mine's rkc is located in INTERMEDIATE_MINE_RKC_PATH, normal keys is located in NEW_PATH
    MoveDirectoryTree(INTERMEDIATE_MINE_RKC_PATH, NEW_MINE_RKC_PATH);
    // the original mine's rkc and normal keys are both located in OLD_MINE_PATH, should move all expect for rkc files
    MoveMineOldFile(OLD_MINE_PATH, NEW_PATH);
#endif
    if (runningState_ == STATE_RUNNING) {
        HKS_LOG_I("HksService has already Started");
        return;
    }

    if (!Init()) {
        HKS_LOG_E("Failed to init HksService");
        return;
    }

#ifdef SUPPORT_COMMON_EVENT
    (void)AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
#endif

    runningState_ = STATE_RUNNING;
    IPCSkeleton::SetMaxWorkThreadNum(HUKS_IPC_THREAD_NUM);
    HKS_LOG_I("HksService start success.");
}

void HksService::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    HKS_LOG_I("systemAbilityId is %" LOG_PUBLIC "d!", systemAbilityId);
#ifdef SUPPORT_COMMON_EVENT
    HksSubscribeSystemEvent();
#endif
}

void HksService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    HKS_LOG_I("systemAbilityId is %" LOG_PUBLIC "d!", systemAbilityId);
}

void HksService::OnStop()
{
    HKS_LOG_I("HksService Service OnStop");
    runningState_ = STATE_NOT_START;
    registerToService_ = false;
}
} // namespace Hks
} // namespace Security
} // namespace OHOS
