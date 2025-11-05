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

#include "hks_lib_interface.h"
#include "hks_function_types.h"

namespace OHOS {
namespace Security {
namespace Huks {
std::shared_ptr<HuksLibInterface> HuksLibInterface::GetInstanceWrapper()
{
    return HuksLibInterface::GetInstance();
}

void HuksLibInterface::ReleaseInstance()
{
    HuksLibInterface::DestroyInstance();
}

void HuksLibInterface::initProviderMap(OHOS::SafeMap<PluginMethodEnum, void*> &pluginProviderMap)
{
    std::lock_guard<std::mutex> lock(mapMutex_);
    m_pluginProviderMap = pluginProviderMap;
}

int32_t HuksLibInterface::OnRegistProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet)
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_REGISTER_PROVIDER, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "OnRegistProvider method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnRegisterProviderFunc>(funcPtr))(processInfo, providerName, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "OnRegistProvider fail, ret = %{public}d", ret)
    HKS_LOG_I("regist provider success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnUnRegistProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet)
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_UN_REGISTER_PROVIDER, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "UnRegistProvider method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnUnRegisterProviderFunc>(funcPtr))(processInfo, providerName, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "UnRegistProvider fail, ret = %{public}d", ret)
    m_pluginProviderMap.Clear();
    HKS_LOG_I("unregist provider success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnCreateRemoteKeyHandle(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &handle)
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_CREATE_REMOTE_KEY_HANDLE, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "CreateRemoteKeyHandle method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnCreateRemoteKeyHandleFunc>(funcPtr))(processInfo, index, paramSet, handle);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "CreateRemoteKeyHandle fail, ret = %{public}d", ret)
    HKS_LOG_I("create remote key handle success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnCloseRemoteKeyHandle(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet)
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_CLOSE_REMOTE_KEY_HANDLE, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "CloseRemoteKeyHandle method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnCloseRemoteKeyHandleFunc>(funcPtr))(processInfo, index, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "CloseRemoteKeyHandle fail, ret = %{public}d", ret)
    HKS_LOG_I("close remote key handle success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnAuthUkeyPin(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &authState, uint32_t &retryCnt)
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_AUTH_UKEY_PIN, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "AuthUkeyPin method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnAuthUkeyPinFunc>(funcPtr))(processInfo, index, paramSet, authState, retryCnt);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "AuthUkeyPin fail, ret = %{public}d", ret)
    HKS_LOG_I("auth ukey pin success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnGetVerifyPinStatus(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &state)
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_GET_VERIFY_PIN_STATUS, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "GetVerifyPinStatus method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnGetVerifyPinStatusFunc>(funcPtr))(processInfo, index, paramSet, state);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "GetVerifyPinStatus fail, ret = %{public}d", ret)
    HKS_LOG_I("get verify pin status success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnClearUkeyPinAuthStatus(const HksProcessInfo &processInfo, const std::string &index)
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_CLEAR_PIN_STATUS, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "ClearPinStatus method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnClearUkeyPinAuthStatusFunc>(funcPtr))(processInfo, index);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "ClearPinStatus fail, ret = %{public}d", ret)
    HKS_LOG_I("clear pin status success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnGetRemoteProperty(const HksProcessInfo &processInfo, const std::string &index,
    const std::string &propertyId, const CppParamSet &paramSet, CppParamSet &outParams)
{
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

int32_t HuksLibInterface::OnExportCertificate(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::string &certsJson)
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_LIST_INDEX_CERTIFICATE, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "FindProviderCertificate method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnListIndexCertificateFunc>(funcPtr))(processInfo, index, paramSet, certsJson);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "FindProviderCertificate fail, ret = %{public}d", ret)
    HKS_LOG_I("list provider certificate success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnExportProviderAllCertificates(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string &certsJsonArr)
{
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

int32_t HuksLibInterface::OnInitSession(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, uint32_t &handle)
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_INIT_SESSION, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "InitSession method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnInitSessionFunc>(funcPtr))(processInfo, index, paramSet, handle);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "InitSession fail, ret = %{public}d", ret)
    HKS_LOG_I("init session success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnUpdateSession(const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData)
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_UPDATE_SESSION, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "UpdateSession method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnUpdateSessionFunc>(funcPtr))(processInfo, handle, paramSet, inData, outData);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "UpdateSession fail, ret = %{public}d", ret)
    HKS_LOG_I("update session success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnFinishSession(const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData)
{
    void *funcPtr = nullptr;
    bool isFind = m_pluginProviderMap.Find(PluginMethodEnum::FUNC_ON_FINISH_SESSION, funcPtr);
    HKS_IF_TRUE_LOGE_RETURN(!isFind, HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "FinishSession method enum not found in plugin provider map.")
    
    int32_t ret = (*reinterpret_cast<OnFinishSessionFunc>(funcPtr))(processInfo, handle, paramSet, inData, outData);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "FinishSession fail, ret = %{public}d", ret)
    HKS_LOG_I("finish session success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnAbortSession(const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet)
{
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