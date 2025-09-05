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

#include "hks_extension_plugin_manager.h"

#include <vector>
// -999 没找到函数
//

namespace OHOS::Security::Huks {

std::shared_ptr<HuksExtensionPluginManager> HuksExtensionPluginManager::GetInstanceWrapper()
{
    return HuksExtensionPluginManager::GetInstance();
}

int32_t HuksExtensionPluginManager::RegisterProvider(struct HksProcessInfo &info, const std::string& AbilityName,
    const CppParamSet& paramSet){
    int32_t ret = -2;

    // 使用 std::call_once 来确保初始化逻辑只执行一次
    std::call_once(initFlag, [this, &AbilityName, &ret]() {
        ret = this->LoadPlugins(AbilityName); // 执行初始化
    });
    // 如果初始化失败，每次调用都返回错误码
    if (ret != HKS_SUCCESS) {
        // 记录日志：初始化失败
        return ret;
    }

    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_REGISTERPROVIDE);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.End() || it->second == nullptr,
        HKS_ERROR_FIND_FUNC_MAP_FAIL, "method OnRegisterProvider is not found")

    int32_t ret = (*reinterpret_cast<OnRegisterProviderFunc>(it->second))(info, AbilityName, paramSet);
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "OnRegisterProvider fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("regist provider success")
    return HKS_SUCCESS;
}

int32_t HuksExtensionPluginManager::LoadPlugins(){
    m_pluginHandle = dlopen(PLUGIN_SO, RTLD_NOW);
    HKS_IF_NULL_LOGE_RETURN(m_pluginHandle, HKS_ERROR_OPEN_LIB_FAIL, "dlopen " PLUGIN_SO " failed! %" LOG_PUBLIC "s", dlerror())

    for (auto i = 0; i < static_cast<int>(PluginMethodEnum::COUNT); ++i) {
        std::string methodString = GetMethodByEnum(static_cast<PluginMethodEnum>(i));
        if (methodString.empty()) {
            HKS_LOG_E("the entry %{public}d is not include", PLUGIN_SO)
            dlclose(m_pluginHandle);
            m_pluginHandle = nullptr;
            m_pluginProviderMap.clear();
            return HKS_ERROR_FIND_FUNC_MAP_FAIL;
        }
        dlerror();
        void* func = dlsym(m_pluginHandle, methodString.c_str());
        const char *dlsym_error = dlerror();
        if (dlsym_error != nullptr) {
            HKS_LOG_E("failed to find entry %{public}d in dynamic link liberary, error is %{public}d",
                methodString.c_str(), dlsym_error)
            dlclose(m_pluginHandle);
            m_pluginHandle = nullptr;
            m_pluginProviderMap.clear();
            return HKS_ERROR_GET_FUNC_POINTER_FAIL;
        }
        m_pluginProviderMap.emplace(std::make_pair(static_cast<PluginMethodEnum>(i), func));
    }
    // 没有找到对应的函数指针，返回错误
    return -1;
}

int32_t HuksExtensionPluginManager::LoadPlugins(const std::string& AbilityName){

    m_pluginProviderMap.Clear();
    dlclose(m_pluginHandle);
    m_pluginHandle == nullptr;
    return HKS_SUCCESS;
}

static std::string HuksExtensionPluginManager::GetMethodByEnum(PluginMethodEnum methodEnum) {
    const auto& it = m_pluginMethodNameMap.find(methodEnum);
    HKS_IF_TRUE_RETURN(it != m_pluginMethodNameMap.end(), it->second)
    HKS_LOG_E("enum = %{public}d can not find string", methodEnum)
    return "";
}

int32_t HuksExtensionPluginManager::OnSigned(const std::string &index,
    const CppParamSet& paramSet, vector<uint8_t> &outData) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_SIGNED);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "Signed method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnSignedFunc>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "Signedfunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("sign data success")

    return HKS_SUCCESS;
}

int32_t HuksExtensionPluginManager::OnVerifyPin(const std::string &index, vector<uint8_t> &pinData) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_VERIFYPIN);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "VerifyPin method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnVerifyPinFunc>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "VerifyPinfunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("verify pin success")
    return HKS_SUCCESS;
}

int32_t OnVerifyPinStatus(const std::string &index) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_VERIFYPIN_STATUS);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "VerifyPinStatus method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnVerifyPinStatusFunc>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "VerifyPinStatusfunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("verify pin status success")
    return HKS_SUCCESS;
}

int32_t OnClearPinStatus(const std::string &index) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_VERIFYPIN_STATUS);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "VerifyPinStatus method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnVerifyPinStatusFunc>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "VerifyPinStatusfunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("verify pin status success")
    return HKS_SUCCESS;
}

int32_t OnFindProviderList(const std::string &index, vector<uint8_t> &providersOut) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_FIND_PROVIDER_LIST);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "FindProviderList method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnFindProviderListFunc>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "FindProviderListfunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("find provider list success")
    return HKS_SUCCESS;
}

int32_t OnFindProviderCertificate(const std::string &index, vector<uint8_t> &cetificatesOut) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_FIND_PROVIDER_CERTIFICATE);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "FindProviderCertificate method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnFindProviderCertificateFunc>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "FindProviderCertificatefunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("find provider certificates success")
    return HKS_SUCCESS;
}

int32_t OnFindProviderAllCertificate(const std::string &index, vector<uint8_t> &cetificatesOut) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_FIND_PROVIDER_ALL_CERTIFICATE);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "FindProviderAllCertificate method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnFindProviderAllCertificateFunc>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "FindProviderAllCertificatefunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("find provider all certificates success")
    return HKS_SUCCESS;
}

int32_t OnGetContainerIndex(vector<uint8_t> &providersOut, std::string &outIndex) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_GET_CONTAINER_INDEX);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "GetContainerIndex method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnGetContainerIndexFunc>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "GetContainerIndexfunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("get container index success")
    return HKS_SUCCESS;
}

int32_t OnCreateRemoteKeyHandle(const std::string &index, std::string &keyIndex) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_CREATE_REMOTE_KEY_HANDLE);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "CreateRemoteKeyHandle method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnCreateRemoteKeyHandleFunc>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "CreateRemoteKeyHandlefunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("create remote key handle success")
    return HKS_SUCCESS;
}

int32_t OnFindRemoteKeyHandle(const std::string &index, std::string &keyIndex) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_FIND_REMOTE_KEY_HANDLE);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "FindRemoteKeyHandle method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnFindRemoteKeyHandleFunc>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "FindRemoteKeyHandlefunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("find remote key handle success")
    return HKS_SUCCESS;
}

int32_t OnCloseRemoteKeyHandle(const std::string &index, std::string &keyIndex) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_CLOSE_REMOTE_KEY_HANDLE);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "CloseRemoteKeyHandle method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnCloseRemoteKeyHandleFunc>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "CloseRemoteKeyHandlefunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("close remote key handle success")
    return HKS_SUCCESS;
}
    
int32_t HuksExtensionPluginManager::OnEncryptData(const std::string &index,
    const CppParamSet& paramSet, vector<uint8_t> &outData) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_ENCYPTDATA);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "EncryptData method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnEncryptData>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "EncryptDatafunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("encypt data success")
    return HKS_SUCCESS;
}

int32_t HuksExtensionPluginManager::OnDecryptData(const std::string &index, const CppParamSet& paramSet) {
    auto it = m_pluginProviderMap.find(PluginMethodEnum::FUNC_ON_DECYPTDATA);
    HKS_IF_TRUE_LOGE_RETURN(it == m_pluginProviderMap.end(), HKS_ERROR_FIND_FUNC_MAP_FAIL,
        "DecryptData method enum not found in plugin provider map.")
    
    int ret = (*reinterpret_cast<OnDecryptData>(it->second))();
    HKS_IF_TRUE_LOGE_RETURN(ret != HKS_SUCCESS, ret,
        "DecryptDatafunc fail, lib can not be loaded now, ret = %{public}d", ret)
    HKS_LOG_I("decypt data success")
    return HKS_SUCCESS;
}