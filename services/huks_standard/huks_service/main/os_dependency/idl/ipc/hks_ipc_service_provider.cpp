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

#include "hks_ipc_service_provider.h"
#include "hks_plugin_lifecycle_manager.h"

int HksIpcServiceProviderRegister(const struct HksProcessInfo *processInfo, std::string name, 
    CppParamSet &paramSet)
{
    HKS_LOG_E("===========HksIpcServiceProviderRegister income");
    int32_t ret;

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    if (pluginManager == nullptr) {
        HKS_LOG_E("Failed to get plugin manager instance.");
        ret = HKS_ERROR_NULL_POINTER;
    }

    HKS_LOG_E("Register provider name is %{public}s", name.data());
    HKS_LOG_E("Register provider paramSet is %{public}p", &paramSet);

    ret = pluginManager->RegisterProvider(*processInfo, name, paramSet); 

    return ret;
}

int HksIpcServiceProviderUnRegister(const struct HksProcessInfo *processInfo, std::string name, 
    CppParamSet &paramSet)
{
    int32_t ret;

    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    if (pluginManager == nullptr) {
        HKS_LOG_E("Failed to get plugin manager instance.");
        ret = HKS_ERROR_NULL_POINTER;
    }

    ret = pluginManager->UnRegisterProvider(*processInfo, name, paramSet); 

    return ret;
}

int HksIpcServiceRegistLibFunction(int32_t funCode, int *fun) {

    return 0;
}

int HksIpcServiceOnCreateRemoteIndex(const std::string &providerName, const CppParamSet& paramSet, std::string &outIndex) {

    return 0;
}

int HksIpcServiceOnCreateRemoteKeyHandle(const struct HksProcessInfo *processInfo, std::string index, 
    CppParamSet &paramSet, std::string &remoteHandleOut) {

    return 0;
}

int HksIpcServiceOnFindRemoteKeyHandle(const struct HksProcessInfo *processInfo, std::string index, 
    CppParamSet &paramSet, std::string &remoteHandleOut) {

    return 0;
}

int HksIpcServiceOnSigned(const struct HksProcessInfo *processInfo, std::string index, 
    CppParamSet &paramSet, std::string srcData, std::string &signature) {

    return 0;
}

int HksIpcServiceOnCloseRemoteKeyHandle(const struct HksProcessInfo *processInfo, 
    std::string index, CppParamSet &paramSet) 
{
    return 0;
}

int HksIpcServiceOnAuthUkeyPin(const std::string &index, const std::vector<uint8_t> &pinData, bool outStatus, int32_t retryCnt) {

    return 0;
}

int HksIpcServiceOnGetVerifyPinStatus(const std::string &index, int32_t &pinStatus) {

    return 0;
}

int HksIpcServiceOnClearPinStatus(const std::string &index) {

    return 0;
}
    
void HksIpcServiceOnListProviders(std::vector<uint8_t> &providersOut) {

}

void HksIpcServiceOnFindProviderCertificate(const std::string &index, std::vector<uint8_t> &cetificatesOut) {

}

void HksIpcServiceOnListProviderAllCertificate(const std::string &providerName, std::string &cetificatesOut) {

}






