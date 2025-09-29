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
#include "hks_funtion_types.h"

namespace OHOS {
namespace Security {
namespace Huks {
std::shared_ptr<HuksLibInterface> HuksLibInterface::GetInstanceWrapper() {
    return HuksLibInterface::GetInstance();
}

void HuksLibInterface::ReleaseInstance() {
    HuksLibInterface::DestroyInstance();
}

void HuksLibInterface::initProviderMap(std::unordered_map<PluginMethodEnum, void*>& mpluginProviderMap) {
    std::lock_guard<std::mutex> lock(mapMutex_);
    pluginProviderMap = mpluginProviderMap;
}

int32_t HuksLibInterface::OnRegistProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet) {
    auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_REGISTER_PROVIDER);
    HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "OnRegistProvider method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnRegisterProviderFunc>(it->second))(processInfo, providerName, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret, "OnRegistProvider fail, ret = %{public}d", ret)
    HKS_LOG_I("regist provider success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnUnRegistProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet) {
    auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_UN_REGISTER_PROVIDER);
    HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "UnRegistProvider method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnUnRegisterProviderFunc>(it->second))(processInfo, providerName, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "UnRegistProvider fail, ret = %{public}d", ret)
    HKS_LOG_I("unregist provider success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnCreateRemoteIndex(const std::string &providerName, const CppParamSet& paramSet,
    std::string &outIndex) {
    auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_CREATE_REMOTE_INDEX);
    HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "CreateRemoteIndex method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnCreateRemoteIndexFunc>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "CreateRemoteIndex fail, ret = %{public}d", ret)
    HKS_LOG_I("create remote index success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnOpenRemoteKeyHandle(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &handle) {
    auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_CREATE_REMOTE_KEY_HANDLE);
    HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "CreateRemoteKeyHandle method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnCreateRemoteKeyHandleFunc>(it->second))(processInfo, index, paramSet, handle);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "CreateRemoteKeyHandle fail, ret = %{public}d", ret)
    HKS_LOG_I("create remote key handle success");
    return HKS_SUCCESS;
}

// int32_t HuksLibInterface::OnFindRemoteKeyHandle(const std::string &index, std::string &keyIndex) {
//     auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_FIND_REMOTE_KEY_HANDLE);
//     HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
//         "FindRemoteKeyHandle method enum not found in plugin provider map.")
    
//     int ret = (*reinterpret_cast<OnFindRemoteKeyHandleFunc>(it->second))();
//     HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
//         "FindRemoteKeyHandle fail, ret = %{public}d", ret)
//     HKS_LOG_I("find remote key handle success")
//     return HKS_SUCCESS;
// }

int32_t HuksLibInterface::OnCloseRemoteKeyHandle(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet) {
    auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_CLOSE_REMOTE_KEY_HANDLE);
    HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "CloseRemoteKeyHandle method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnCloseRemoteKeyHandleFunc>(it->second))(processInfo, index, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "CloseRemoteKeyHandle fail, ret = %{public}d", ret)
    HKS_LOG_I("close remote key handle success");
    return HKS_SUCCESS;
}

// int32_t HuksLibInterface::OnSigned(const std::string &index, const CppParamSet& paramSet, std::vector<uint8_t> &outData) {
//     auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_SIGNED);
//     HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
//         "Signed method enum not found in plugin provider map.")
    
//     int ret = (*reinterpret_cast<OnSignedFunc>(it->second))();
//     HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
//         "Signed fail, ret = %{public}d", ret)
//     HKS_LOG_I("sign success")
//     return HKS_SUCCESS;
// }

int32_t HuksLibInterface::OnAuthUkeyPin(const HksProcessInfo &processInfo, 
    const std::string &index, const CppParamSet &paramSet, int32_t& authState, uint32_t& retryCnt) {
    auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_AUTH_UKEY_PIN);
    HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "AuthUkeyPin method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnAuthUkeyPinFunc>(it->second))(processInfo, index, paramSet, authState, retryCnt);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "AuthUkeyPin fail, ret = %{public}d", ret)
    HKS_LOG_I("auth ukey pin success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnGetVerifyPinStatus(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, uint32_t &state) {
    auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_GET_VERIFY_PIN_STATUS);
    HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "GetVerifyPinStatus method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnGetVerifyPinStatusFunc>(it->second))(processInfo, index, paramSet, state);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "GetVerifyPinStatus fail, ret = %{public}d", ret)
    HKS_LOG_I("get verify pin status success");
    return HKS_SUCCESS;
}

// int32_t HuksLibInterface::OnClearPinStatus(const std::string &index) {
//     auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_CLEAR_PIN_STATUS);
//     HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
//         "ClearPinStatus method enum not found in plugin provider map.")
    
//     int ret = (*reinterpret_cast<OnClearPinStatusFunc>(it->second))();
//     HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
//         "ClearPinStatus fail, ret = %{public}d", ret)
//     //HKS_LOG_I("clear pin status success")
//     return HKS_SUCCESS;
// }

// int32_t HuksLibInterface::OnListProviders(std::vector<uint8_t> &providersOut) {
//     auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_LIST_PROVIDER);
//     HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
//         "ListProviders method enum not found in plugin provider map.")
    
//     int ret = (*reinterpret_cast<OnListProvidersFunc>(it->second))();
//     HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
//         "ListProviders fail, ret = %{public}d", ret)
//     //HKS_LOG_I("list providers success")
//     return HKS_SUCCESS;
// }

int32_t HuksLibInterface::OnListIndexCertificate(const HksProcessInfo &processInfo,
   const std::string &index, const CppParamSet &paramSet, std::string &certsJson) {
    auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_LIST_INDEX_CERTIFICATE);
    HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "FindProviderCertificate method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnListIndexCertificateFunc>(it->second))(processInfo, index, paramSet, certsJson);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "FindProviderCertificate fail, ret = %{public}d", ret)
    HKS_LOG_I("list provider certificate success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnListProviderAllCertificate(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string &certsJsonArr) {
    auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_LIST_PROVIDER_ALL_CERTIFICATE);
    HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "ListProviderAllCertificate method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnListProviderAllCertificateFunc>(it->second))
        (processInfo, providerName, paramSet, certsJsonArr);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "ListProviderAllCertificate fail, ret = %{public}d", ret)
    HKS_LOG_I("list provider all certificate success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnInitSession (const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, uint32_t &handle) {
    auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_INIT_SESSION);
    HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "InitSession method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnInitSessionFunc>(it->second))(processInfo, index, paramSet, handle);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "InitSession fail, ret = %{public}d", ret)
    HKS_LOG_I("init session success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnUpdateSession (const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData) {
    auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_UPDATE_SESSION);
    HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "UpdateSession method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnUpdateSessionFunc>(it->second))(processInfo, handle, paramSet, inData, outData);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "UpdateSession fail, ret = %{public}d", ret)
    HKS_LOG_I("update session success");
    return HKS_SUCCESS;
}

int32_t HuksLibInterface::OnFinishSession (const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData) {
    auto it = pluginProviderMap.find(PluginMethodEnum::FUNC_ON_FINISH_SESSION);
    HKS_IF_TRUE_LOGE_RETURN(it == pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "FinishSession method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnFinishSessionFunc>(it->second))(processInfo, handle, paramSet, inData, outData);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "FinishSession fail, ret = %{public}d", ret)
    HKS_LOG_I("finish session success");
    return HKS_SUCCESS;
}

}
}
}


