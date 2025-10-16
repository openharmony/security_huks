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
 
#include "hks_error_code.h"
#include "hks_provider_life_cycle_manager.h"
#include "hks_remote_handle_manager.h"
#include "hks_session_manger.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <random>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include "hks_cpp_paramset.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_json_wrapper.h"
#include "hks_template.h"
namespace OHOS {
namespace Security {
namespace Huks {

std::shared_ptr<HksSessionManager> HksSessionManager::GetInstanceWrapper()
{
    return HksSessionManager::GetInstance();
}

void HksSessionManager::ReleaseInstance()
{
    HksSessionManager::DestroyInstance();
}

static bool GenerateRand(uint8_t *buf, size_t len)
{
    FILE *randfp = fopen("/dev/random", "rb");
    if (randfp == nullptr) {
        HKS_LOG_E("fopen file failed");
        return false;
    }
    size_t readLen = fread(buf, sizeof(uint8_t), len, randfp);
    (void)fclose(randfp);
    if (readLen != len) {
        HKS_LOG_E("read file failed");
        return false;
    }
    return true;
}

std::pair<int32_t, uint32_t> HksSessionManager::GenRandomUint32()
{
    uint32_t random = std::numeric_limits<uint32_t>::max();
    auto *randomNumPtr = static_cast<uint8_t *>(static_cast<void *>(&random));
    if (!GenerateRand(randomNumPtr, sizeof(uint32_t))) {
        HKS_LOG_E("GenerateRand failed");
        return std::make_pair(HKS_ERROR_GEN_RANDOM_FAIL, 0);
    }
    return std::make_pair(HKS_SUCCESS, random);
}

int32_t HksSessionManager::ExtensionInitSession(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, uint32_t &handle)
{
    ProviderInfo providerInfo;
    std::string newIndex;
    std::string sIndexHandle;
    int32_t ret = HksRemoteHandleManager::GetInstanceWrapper()->ParseAndValidateIndex(index, providerInfo, newIndex, sIndexHandle);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("ParseAndValidateIndex failed: %" LOG_PUBLIC "d", ret);
        return ret;
    }
    std::string sessionHandle;
    auto proxy = HksRemoteHandleManager::GetInstanceWrapper()->GetProviderProxy(providerInfo, ret);
    if (proxy == nullptr) {
        return ret;
    }
    auto ipcCode = proxy->InitSession(sIndexHandle, paramSet, sessionHandle, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipcCode != EOK, HKS_ERROR_IPC_MSG_FAIL, "proxy InitSession ipcCode: %" LOG_PUBLIC "d", ipcCode)
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("InitSession get handle failed: %" LOG_PUBLIC "d", ret);
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }
    auto random = GenRandomUint32();
    if (random.first != HKS_SUCCESS) {
        HKS_LOG_E("GenRandomUint32 failed");
        return HKS_ERROR_GEN_RANDOM_FAIL;
    }
    handle = random.second;
    HKS_LOG_I("ExtensionInitSession return sessionHandle: %" LOG_PUBLIC "s", sessionHandle.c_str());
    HKS_LOG_I("ExtensionInitSession out handle: %" LOG_PUBLIC "u", handle);
    std::pair<ProviderInfo, std::string> handleInfo{providerInfo, sessionHandle};
    m_handlers.Insert(handle, handleInfo);
    return HKS_SUCCESS;
}
int32_t HksSessionManager::ExtensionUpdateSession(const HksProcessInfo &processInfo,
    const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
    std::vector<uint8_t> &outData)
{
    std::pair<ProviderInfo, std::string> handleInfo;
    HKS_LOG_I("ExtensionUpdateSession handle: %" LOG_PUBLIC "u", handle);
    if(!m_handlers.Find(handle, handleInfo)) {
        HKS_LOG_E("Find handle failed");
        return HKS_ERROR_UKY_FIND_SESSION_HANDLE_FAIL;
    }
    sptr<IHuksAccessExtBase> proxy{nullptr};
    int32_t ret = HksProviderLifeCycleManager::GetInstanceWrapper()->GetExtensionProxy(handleInfo.first, proxy);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("GetExtensionProxy failed: %" LOG_PUBLIC "d", ret);
        return ret;
    }
    auto ipcCode = proxy->UpdateSession(handleInfo.second, paramSet, inData, outData, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipcCode != EOK, HKS_ERROR_IPC_MSG_FAIL, "proxy UpdateSession ipcCode: %" LOG_PUBLIC "d", ipcCode)
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("UpdateSession failed: %" LOG_PUBLIC "d", ret);
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }
    return HKS_SUCCESS;
}
int32_t HksSessionManager::ExtensionFinishSession(const HksProcessInfo &processInfo,
    const uint32_t &handle, const CppParamSet &paramSet, const std::vector<uint8_t> &inData,
    std::vector<uint8_t> &outData)
{
    std::pair<ProviderInfo, std::string> handleInfo;
    if(!m_handlers.Find(handle, handleInfo)) {
        HKS_LOG_E("Find handle failed");
        return HKS_ERROR_UKY_FIND_SESSION_HANDLE_FAIL;
    }
    sptr<IHuksAccessExtBase> proxy{nullptr};
    int32_t ret = HksProviderLifeCycleManager::GetInstanceWrapper()->GetExtensionProxy(handleInfo.first, proxy);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("GetExtensionProxy failed: %" LOG_PUBLIC "d", ret);
        return ret;
    }
    auto ipcCode = proxy->FinishSession(handleInfo.second, paramSet, inData, outData, ret);
    HKS_IF_TRUE_LOGE_RETURN(ipcCode != EOK, HKS_ERROR_IPC_MSG_FAIL, "proxy FinishSession ipcCode: %" LOG_PUBLIC "d", ipcCode)
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("FinishSession failed: %" LOG_PUBLIC "d", ret);
        return HKS_ERROR_REMOTE_OPERATION_FAILED;
    }
    m_handlers.Erase(handle);
    return HKS_SUCCESS;
}

}
}
}