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

#include "hks_plugin_lifecycle_manager.h"
#include "hks_plugin_loader.h"
#include "hks_cfi.h"

#define NO_EXTENSION 0
#define ONE_EXTENSION 1
namespace OHOS {
namespace Security {
namespace Huks {

std::shared_ptr<HuksPluginLifeCycleMgr> HuksPluginLifeCycleMgr::GetInstanceWrapper()
{
    return HuksPluginLifeCycleMgr::GetInstance();
}

void HuksPluginLifeCycleMgr::ReleaseInstance()
{
    HuksPluginLifeCycleMgr::DestroyInstance();
}

int32_t HuksPluginLifeCycleMgr::RegisterProvider(const struct HksProcessInfo &info,
    const std::string &providerName, const CppParamSet &paramSet)
{
    int32_t ret;
    std::unique_lock<std::mutex> lock(soMutex);
    if (m_refCount.load() == NO_EXTENSION) {
        auto pluginLoader = HuksPluginLoader::GetInstanceWrapper();
        HKS_IF_TRUE_LOGE_RETURN(pluginLoader == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get pluginLoader instance.")
        ret = pluginLoader->LoadPlugins(info, providerName, paramSet, m_pluginProviderMap);
        HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "regist provider failed!")
    }

    ret = OnRegistProvider(info, providerName, paramSet, [this, info, providerName, paramSet](bool deathFlag) {
        HKS_LOG_I("UnRegisterProvider from ExtensionConnection");
        isDeath = true;
        UnRegisterProvider(info, providerName, paramSet, isDeath);
    });

    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "regist provider method in plugin loader is fail")
    m_refCount.fetch_add(1, std::memory_order_acq_rel);

    return ret;
}

int32_t HuksPluginLifeCycleMgr::UnRegisterProvider(const struct HksProcessInfo &info, const std::string &providerName,
    const CppParamSet &paramSet, bool isdeath)
{
    std::unique_lock<std::mutex> lock(soMutex);
    if (m_refCount.load() == NO_EXTENSION) {
        HKS_LOG_I("lib has closed!");
        return HKS_ERROR_LIB_REPEAT_CLOSE;
    }

    int32_t ret = HKS_SUCCESS;
    do {
        ret = OnUnRegistProvider(info, providerName, paramSet, isdeath);
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "unregist provider failed! ret = %{public}d", ret)

        HKS_IF_TRUE_LOGE_BREAK(m_refCount.load() != ONE_EXTENSION,
            "don't need close lib, refCount = %{public}d", m_refCount.load())

        auto pluginLoader = HuksPluginLoader::GetInstanceWrapper();
        if (pluginLoader == nullptr) {
            ret = HKS_ERROR_NULL_POINTER;
            HKS_LOG_E("Failed to get pluginLoader instance.");
            break;
        }

        ret = pluginLoader->UnLoadPlugins(info, providerName, paramSet, m_pluginProviderMap);
        HKS_IF_TRUE_LOGE_BREAK(ret != HKS_SUCCESS, "close lib failed!, ret = %{public}d", ret)
    } while (0);

    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "unregist provider fail")
    m_refCount.fetch_sub(1, std::memory_order_acq_rel);

    return ret;
}

struct AutoRefCount {
    std::atomic<int32_t> &m_refCount;
    explicit AutoRefCount(std::atomic<int32_t> &refCount) : m_refCount(refCount)
    {
        m_refCount.fetch_add(1, std::memory_order_acq_rel);
    }
    ~AutoRefCount()
    {
        m_refCount.fetch_sub(1, std::memory_order_acq_rel);
    }
};

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnRegistProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::function<void(bool)> callback))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_REGISTER_PROVIDER, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "OnRegistProvider method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnRegisterProviderFunc>(funcPtr))(processInfo, providerName, paramSet, callback);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "OnRegistProvider fail, ret = %{public}d", ret)
    HKS_LOG_I("regist provider success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnUnRegistProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, bool isdeath))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_UN_REGISTER_PROVIDER, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "UnRegistProvider method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnUnRegisterProviderFunc>(funcPtr))(processInfo, providerName, paramSet, isdeath);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "UnRegistProvider fail, ret = %{public}d", ret)
    HKS_LOG_I("unregist provider success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnCreateRemoteKeyHandle(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::string &handle))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_CREATE_REMOTE_KEY_HANDLE, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "CreateRemoteKeyHandle method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnCreateRemoteKeyHandleFunc>(funcPtr))(processInfo, index, paramSet, handle);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "CreateRemoteKeyHandle fail, ret = %{public}d", ret)
    HKS_LOG_I("create remote key handle success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnCloseRemoteKeyHandle(
    const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_CLOSE_REMOTE_KEY_HANDLE, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "CloseRemoteKeyHandle method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnCloseRemoteKeyHandleFunc>(funcPtr))(processInfo, index, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "CloseRemoteKeyHandle fail, ret = %{public}d", ret)
    HKS_LOG_I("close remote key handle success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnAuthUkeyPin(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &authState, uint32_t &retryCnt))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_AUTH_UKEY_PIN, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "AuthUkeyPin method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnAuthUkeyPinFunc>(funcPtr))(processInfo, index, paramSet, authState, retryCnt);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "AuthUkeyPin fail, ret = %{public}d", ret)
    HKS_LOG_I("auth ukey pin success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnGetVerifyPinStatus(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &state))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_GET_VERIFY_PIN_STATUS, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "GetVerifyPinStatus method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnGetVerifyPinStatusFunc>(funcPtr))(processInfo, index, paramSet, state);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "GetVerifyPinStatus fail, ret = %{public}d", ret)
    HKS_LOG_I("get verify pin status success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnClearUkeyPinAuthStatus(const HksProcessInfo &processInfo,
    const std::string &index))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_CLEAR_PIN_STATUS, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "ClearPinStatus method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnClearUkeyPinAuthStatusFunc>(funcPtr))(processInfo, index);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "ClearPinStatus fail, ret = %{public}d", ret)
    HKS_LOG_I("clear pin status success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnGetRemoteProperty(
    const HksProcessInfo &processInfo, const std::string &index,
    const std::string &propertyId, const CppParamSet &paramSet, CppParamSet &outParams))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_GET_REMOTE_PROPERTY, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "ClearPinStatus method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnGetRemotePropertyFunc>(funcPtr))(processInfo, index,
        propertyId, paramSet, outParams);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "ClearPinStatus fail, ret = %{public}d", ret)
    HKS_LOG_I("get remote property success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnExportCertificate(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::string &certsJson))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_LIST_INDEX_CERTIFICATE, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "FindProviderCertificate method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnListIndexCertificateFunc>(funcPtr))(processInfo, index, paramSet, certsJson);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "FindProviderCertificate fail, ret = %{public}d", ret)
    HKS_LOG_I("list provider certificate success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnExportProviderAllCertificates(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string &certsJsonArr))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_LIST_PROVIDER_ALL_CERTIFICATE, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "ListProviderAllCertificate method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnListProviderAllCertificateFunc>(funcPtr))
        (processInfo, providerName, paramSet, certsJsonArr);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "ListProviderAllCertificate fail, ret = %{public}d", ret)
    HKS_LOG_I("list provider all certificate success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnInitSession(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, uint32_t &handle))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_INIT_SESSION, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "InitSession method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnInitSessionFunc>(funcPtr))(processInfo, index, paramSet, handle);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "InitSession fail, ret = %{public}d", ret)
    HKS_LOG_I("init session success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnUpdateSession(const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_UPDATE_SESSION, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "UpdateSession method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnUpdateSessionFunc>(funcPtr))(processInfo, handle, paramSet, inData, outData);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "UpdateSession fail, ret = %{public}d", ret)
    HKS_LOG_I("update session success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnFinishSession(const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_FINISH_SESSION, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "FinishSession method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnFinishSessionFunc>(funcPtr))(processInfo, handle, paramSet, inData, outData);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "FinishSession fail, ret = %{public}d", ret)
    HKS_LOG_I("finish session success");
    return HKS_SUCCESS;
}

ENABLE_CFI(int32_t HuksPluginLifeCycleMgr::OnAbortSession(const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet))
{
    AutoRefCount refCnt(m_refCount);
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_ABORT_SESSION, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "AbortSession method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnAbortSessionFunc>(funcPtr))(processInfo, handle, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "AbortSession fail, ret = %" LOG_PUBLIC "d", ret)
    HKS_LOG_I("abort session success");
    return HKS_SUCCESS;
}
}
}
}