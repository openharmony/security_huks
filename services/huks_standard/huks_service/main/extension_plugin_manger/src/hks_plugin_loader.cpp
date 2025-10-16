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
#include <vector>

namespace OHOS {
namespace Security {
namespace Huks {

std::string pluginSo = "libhuks_external_crypto_ext_core.z.so";

std::shared_ptr<HuksPluginLoader> HuksPluginLoader::GetInstanceWrapper()
{
    return HuksPluginLoader::GetInstance();
}

void HuksPluginLoader::ReleaseInstance()
{
    HuksPluginLoader::DestroyInstance();
}

int32_t HuksPluginLoader::LoadPlugins(const struct HksProcessInfo &info,
    const std::string &providerName, const CppParamSet &paramSet)
{
    std::lock_guard<std::mutex> lock(libMutex);
    HKS_IF_TRUE_RETURN(m_pluginHandle != nullptr, HKS_ERROR_LIB_HAS_OPENED)
    InitMethodNameMap();
    m_pluginHandle = dlopen(pluginSo.c_str(), RTLD_NOW);
    HKS_IF_NULL_LOGE_RETURN(m_pluginHandle, HKS_ERROR_OPEN_LIB_FAIL,
        "dlopen %{public}s failed! %{public}s", pluginSo.c_str(), dlerror())

    for (auto i = 0; i < static_cast<int32_t>(PluginMethodEnum::COUNT); ++i) {
        std::string methodString = GetMethodByEnum(static_cast<PluginMethodEnum>(i));
        if (methodString.empty()) {
            HKS_LOG_E("the entry %{public}s is not include", pluginSo.c_str());
            dlclose(m_pluginHandle);
            m_pluginHandle = nullptr;
            m_pluginProviderMap.Clear();
            return HKS_ERROR_FIND_FUNC_MAP_FAIL;
        }

        dlerror();
        void *func = dlsym(m_pluginHandle, methodString.c_str());
        const char *dlsym_error = dlerror();
        if (dlsym_error != nullptr) {
            HKS_LOG_E("failed to Find entry %{public}s in dynamic link liberary, error is %{public}s",
                methodString.c_str(), dlsym_error);
            dlclose(m_pluginHandle);
            m_pluginHandle= nullptr;
            m_pluginProviderMap.Clear();
            return HKS_ERROR_GET_FUNC_POINTER_FAIL;
        }
        m_pluginProviderMap.Insert(static_cast<PluginMethodEnum>(i), func);
    }

    auto libInstance = HuksLibInterface::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInstance == nullptr, HKS_ERROR_NULL_POINTER, "Failed to get LibInterface instance.")
    libInstance->initProviderMap(m_pluginProviderMap);
    return HKS_SUCCESS;
}

int32_t HuksPluginLoader::UnLoadPlugins(const struct HksProcessInfo &info,
    const std::string &providerName, const CppParamSet &paramSet)
{
    std::lock_guard<std::mutex> lock(libMutex);
    HKS_IF_TRUE_RETURN(m_pluginHandle == nullptr, HKS_SUCCESS)

    m_pluginProviderMap.Clear();
    dlerror();
    dlclose(m_pluginHandle);
    const char *dlsym_error = dlerror();
    HKS_IF_TRUE_LOGE_RETURN(dlsym_error != nullptr, HKS_ERROR_CLOSE_LIB_FAIL,
        "close lib fail, error:%{public}s", dlsym_error)
    m_pluginHandle = nullptr;
    return HKS_SUCCESS;
}

std::string HuksPluginLoader::GetMethodByEnum(PluginMethodEnum methodEnum)
{
    std::string methodString = "";
    bool isFindMethodEnum = m_pluginMethodNameMap.Find(methodEnum, methodString);
    HKS_IF_TRUE_RETURN(isFindMethodEnum, methodString)
    HKS_LOG_E("don't find enum = %{public}d", methodEnum);
    return "";
}

void HuksPluginLoader::SetPluginPath(std::string &pluginPath)
{
    pluginSo = pluginPath;
}

void HuksPluginLoader::InitMethodNameMap()
{
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_REGISTER_PROVIDER,
        "_ZN4OHOS8Security4Huks30HksExtPluginOnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSet");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_UN_REGISTER_PROVIDER,
        "_ZN4OHOS8Security4Huks32HksExtPluginOnUnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSet");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_CREATE_REMOTE_INDEX,
        "_ZN4OHOS8Security4Huks31HksExtPluginOnCreateRemoteIndexERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_CREATE_REMOTE_KEY_HANDLE,
        "_ZN4OHOS8Security4Huks30HksExtPluginOnOpemRemoteHandleERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_CLOSE_REMOTE_KEY_HANDLE,
        "_ZN4OHOS8Security4Huks31HksExtPluginOnCloseRemoteHandleERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSet");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_AUTH_UKEY_PIN,
        "_ZN4OHOS8Security4Huks25HksExtPluginOnAuthUkeyPinERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRiRj");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_GET_VERIFY_PIN_STATUS,
        "_ZN4OHOS8Security4Huks33HksExtPluginOnGetUkeyPinAuthStateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRi");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_CLEAR_PIN_STATUS,
        "_ZN4OHOS8Security4Huks24HksClearUkeyPinAuthStateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEE");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_GET_REMOTE_PROPERTY,
        "_ZN4OHOS8Security4Huks20HksGetRemotePropertyERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEESD_RK11CppParamSetRSE_");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_LIST_INDEX_CERTIFICATE,
        "_ZN4OHOS8Security4Huks29HksExtPluginOnExportCerticateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_LIST_PROVIDER_ALL_CERTIFICATE,
        "_ZN4OHOS8Security4Huks38HksExtPluginOnExportProviderCerticatesERK14HksProcessInfo"
        "RKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_INIT_SESSION,
        "_ZN4OHOS8Security4Huks25HksExtPluginOnInitSessionERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRj");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_UPDATE_SESSION,
        "_ZN4OHOS8Security4Huks27HksExtPluginOnUpdateSessionERK14HksProcessInfoRKjRK11CppParamSet"
        "RKNSt3__h6vectorIhNSA_9allocatorIhEEEERSE_");
    m_pluginMethodNameMap.Insert(PluginMethodEnum::FUNC_ON_FINISH_SESSION,
        "_ZN4OHOS8Security4Huks27HksExtPluginOnFinishSessionERK14HksProcessInfoRKjRK11CppParamSet"
        "RKNSt3__h6vectorIhNSA_9allocatorIhEEEERSE_");
}

}
}
}