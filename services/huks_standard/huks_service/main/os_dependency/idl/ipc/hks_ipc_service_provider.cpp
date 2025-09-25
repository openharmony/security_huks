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

namespace OHOS {
namespace Security {
namespace Huks {
std::shared_ptr<HuksPluginLifeCycleMgr> GetExtPluginMgrInstance() {
    auto pluginManager = OHOS::Security::Huks::HuksPluginLifeCycleMgr::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(pluginManager == nullptr, nullptr, "Failed to get plugin manager instance.")

    return pluginManager;
}

std::shared_ptr<HuksLibEntry> GetExtLibInterfaceInstance() {
    auto libInterface = OHOS::Security::Huks::HuksLibEntry::GetInstanceWrapper();
    HKS_IF_TRUE_LOGE_RETURN(libInterface == nullptr, nullptr, "Failed to get lib interface instance.")

    return libInterface;
}

int32_t HksIpcServiceProviderRegister(const struct HksProcessInfo *processInfo, std::string name, 
    CppParamSet &paramSet)
{
    HKS_LOG_I("===========HksIpcServiceProviderRegister income");
    auto pluginManager = GetExtPluginMgrInstance();
    HKS_LOG_I("got pluginManager instance");

    int32_t ret = pluginManager->RegisterProvider(*processInfo, name, paramSet); 
    return ret;
}

int32_t HksIpcServiceProviderUnRegister(const struct HksProcessInfo *processInfo, std::string name, 
    CppParamSet &paramSet)
{
    HKS_LOG_I("===========HksIpcServiceProviderUnRegister income");
    auto pluginManager = GetExtPluginMgrInstance();
    HKS_LOG_I("got pluginManager instance");

    int32_t ret = pluginManager->UnRegisterProvider(*processInfo, name, paramSet); 
    return ret;
}

// TODO:注册具体功能？要存吗？
int32_t HksIpcServiceRegistLibFunction(int32_t funCode, int *fun) {

    return 0;
}

int32_t HksIpcServiceOnCreateRemoteIndex(const std::string &providerName, const CppParamSet& paramSet,
    std::string &outIndex) {
    HKS_LOG_I("===========HksIpcServiceOnCreateRemoteInde income");
    auto libInterface = GetExtLibInterfaceInstance();
    HKS_LOG_I("got libInterface instance");

    int32_t ret = libInterface->OnCreateRemoteIndex(providerName, paramSet, outIndex); 
    return ret;
}

int32_t HksIpcServiceOnCreateRemoteKeyHandle(const struct HksProcessInfo *processInfo, std::string index, 
    CppParamSet &paramSet, std::string &remoteHandleOut) {
    HKS_LOG_I("===========HksIpcServiceOnCreateRemoteInde income");
    auto libInterface = GetExtLibInterfaceInstance();
    HKS_LOG_I("got libInterface instance");

    int32_t ret = libInterface->OnOpenRemoteKeyHandle(*processInfo, index, paramSet, remoteHandleOut);
    return ret;
}

// int32_t HksIpcServiceOnFindRemoteKeyHandle(const struct HksProcessInfo *processInfo, std::string index, 
//     CppParamSet &paramSet, std::string &remoteHandleOut) {
//     HKS_LOG_I("===========HksIpcServiceOnCreateRemoteInde income");
//     auto libInterface = GetExtLibInterfaceInstance();
//     HKS_LOG_I("got libInterface instance");

//     int32_t ret = libInterface->OnFindRemoteKeyHandle(index, index); // TODO:参数对齐OnFindRemoteKeyHandle(const std::string &index, std::string &keyIndex)
//     return ret;
// }

int32_t HksIpcServiceOnCloseRemoteKeyHandle(const struct HksProcessInfo *processInfo, 
    std::string index, CppParamSet &paramSet) 
{
    HKS_LOG_I("===========HksIpcServiceOnCreateRemoteInde income");
    auto libInterface = GetExtLibInterfaceInstance();
    HKS_LOG_I("got libInterface instance");

    int32_t ret = libInterface->OnCloseRemoteKeyHandle(*processInfo, index, paramSet); // TODO:参数对齐OnCloseRemoteKeyHandle(const std::string &index, std::string &keyIndex)
    return ret;
}

// int32_t HksIpcServiceOnSigned(const struct HksProcessInfo *processInfo, std::string index, 
//     CppParamSet &paramSet, std::string srcData, std::string &signature) {
//     HKS_LOG_I("===========HksIpcServiceOnCreateRemoteInde income");
//     auto libInterface = GetExtLibInterfaceInstance();
//     HKS_LOG_I("got libInterface instance");
//     int32_t ret = 0;
//     // int32_t ret = libInterface->OnSigned(index, paramSet, srcData); // TODO:参数对齐OnSigned(const std::string &index, const CppParamSet& paramSet, std::vector<uint8_t> &outData)
//     return ret;
// }

// int HksIpcServiceOnVerify(const struct HksProcessInfo *processInfo, std::string index, 
//     CppParamSet &paramSet, std::string srcData, std::string &signature) {

//     return 0;
// }

// int32_t HksIpcServiceOnAuthUkeyPin(const std::string &index, const std::vector<uint8_t> &pinData,
//     bool outStatus, int32_t *retryCnt) {
//     HKS_LOG_I("===========HksIpcServiceOnCreateRemoteInde income");
//     auto libInterface = GetExtLibInterfaceInstance();
//     HKS_LOG_I("got libInterface instance");

//     int32_t ret = libInterface->OnAuthUkeyPin(processInfo, index, paramSet, authState, retryCnt);
//     return ret;
// }

// int32_t HksIpcServiceOnGetVerifyPinStatus(const HksProcessInfo &processInfo,
//     const std::string &index, const CppParamSet &paramSet, uint32_t &state) {
//     HKS_LOG_I("===========HksIpcServiceOnCreateRemoteInde income");
//     auto libInterface = GetExtLibInterfaceInstance();
//     HKS_LOG_I("got libInterface instance");

//     int32_t ret = libInterface->OnGetVerifyPinStatus(processInfo, index, paramSet, state);
//     return ret;
// }

// int32_t HksIpcServiceOnClearPinStatus(const std::string &index) {
//     HKS_LOG_I("===========HksIpcServiceOnCreateRemoteInde income");
//     auto libInterface = GetExtLibInterfaceInstance();
//     HKS_LOG_I("got libInterface instance");

//     int32_t ret = libInterface->OnClearPinStatus(index);
//     return ret;
// }
    
// void HksIpcServiceOnListProviders(std::vector<uint8_t> &providersOut) {
//     HKS_LOG_I("===========HksIpcServiceOnCreateRemoteInde income");
//     auto libInterface = GetExtLibInterfaceInstance();
//     HKS_LOG_I("got libInterface instance");

//     int32_t ret = libInterface->OnListProviders(providersOut);
//     HKS_IF_TRUE_LOGI_RETURN_VOID(ret != HKS_SUCCESS, "HksIpcServiceOnListProviders fail")
// }

// void HksIpcServiceOnFindProviderCertificate(const HksProcessInfo &processInfo, const std::string &index,
// const CppParamSet &paramSet, std::string &cetificatesOut) {
//     HKS_LOG_I("===========HksIpcServiceOnCreateRemoteInde income");
//     auto libInterface = GetExtLibInterfaceInstance();
//     HKS_LOG_I("got libInterface instance");

//     int32_t ret = libInterface->OnListProviderCertificate(index, cetificatesOut);
//     HKS_IF_TRUE_LOGI_RETURN_VOID(ret != HKS_SUCCESS, "HksIpcServiceOnFindProviderCertificate fail")
// }

// void HksIpcServiceOnListProviderAllCertificate(const HksProcessInfo &processInfo, const std::string &index,
// const CppParamSet &paramSet, std::string &cetificatesOut) {
//     HKS_LOG_I("===========HksIpcServiceOnCreateRemoteInde income");
//     auto libInterface = GetExtLibInterfaceInstance();
//     HKS_LOG_I("got libInterface instance");

//     int32_t ret = libInterface->OnListProviderAllCertificate(providerName, cetificatesOut);
//     HKS_IF_TRUE_LOGI_RETURN_VOID(ret != HKS_SUCCESS, "HksIpcServiceOnListProviderAllCertificate fail")
// }

}
}
}
