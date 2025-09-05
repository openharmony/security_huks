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

#ifndef HKS_PROVIDER_LIFE_CYCLE_MANAGER_H
#define HKS_PROVIDER_LIFE_CYCLE_MANAGER_H

#include <string>
#include <unordered_map>

#include "hks_cpp_paramset.h"
#include <mutex>
// #include "safe_map.h"

enum class PluginMethodEnum{
    FUNC_ON_REGISTER_PROVIDE,
    FUNC_ON_UN_REGISTER_PROVIDE,
    FUNC_ON_SIGNED,
    FUNC_ON_VERIFY_PIN,
    FUNC_ON_VERIFY_PIN_STATUS,
    FUNC_ON_CLEAR_PIN_STATUS,
    FUNC_ON_FIND_PROVIDER_LIST,
    FUNC_ON_FIND_PROVIDER_CERTIFICATE,
    FUNC_ON_FIND_PROVIDER_ALL_CERTIFICATE,
    FUNC_ON_GET_CONTAINER_INDEX,
    FUNC_ON_CREATE_REMOTE_KEY_HANDLE,
    FUNC_ON_FIND_REMOTE_KEY_HANDLE,
    FUNC_ON_CLOSE_REMOTE_KEY_HANDLE,
    FUNC_ON_ENCYPT_DATA,
    FUNC_ON_DECYPT_DATA,
    COUNT = 15,
};

static const std::map<PluginMethodEnum, std::string> m_pluginMethodNameMap = {
    {PluginMethodEnum::FUNC_ON_REGISTER_PROVIDE, "_ZN27HksProviderLifeCycleManager18OnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEERK11CppParamSet"},
    {PluginMethodEnum::FUNC_ON_UN_REGISTER_PROVIDE, ""},
    {PluginMethodEnum::FUNC_ON_SIGNED, ""},
    {PluginMethodEnum::FUNC_ON_VERIFY_PIN, ""},
    {PluginMethodEnum::FUNC_ON_VERIFY_PIN_STATUS, ""},
    {PluginMethodEnum::FUNC_ON_CLEAR_PIN_STATUS, ""},
    {PluginMethodEnum::FUNC_ON_FIND_PROVIDER_LIST, ""},
    {PluginMethodEnum::FUNC_ON_FIND_PROVIDER_CERTIFICATE, ""},
    {PluginMethodEnum::FUNC_ON_FIND_PROVIDER_ALL_CERTIFICATE, ""},
    {PluginMethodEnum::FUNC_ON_GET_CONTAINER_INDEX, ""},
    {PluginMethodEnum::FUNC_ON_CREATE_REMOTE_KEY_HANDLE, ""},
    {PluginMethodEnum::FUNC_ON_FIND_REMOTE_KEY_HANDLE, ""},
    {PluginMethodEnum::FUNC_ON_CLOSE_REMOTE_KEY_HANDLE, ""},
    {PluginMethodEnum::FUNC_ON_ENCYPT_DATA, ""},
    {PluginMethodEnum::FUNC_ON_DECYPT_DATA, ""}
};
// 在枚举里面去对应
std::string RegisterFunName = "_ZN27HksProviderLifeCycleManager18OnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEERK11CppParamSet";


using OnRegisterProviderFunc = int32_t (*)(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet);
using OnUnRegisterProviderFunc = int32_t (*)(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet);
using OnSignedFunc = int32_t (*)();
using OnVerifyPinFunc = int32_t (*)();
using OnVerifyPinStatusFunc = int32_t (*)();
using OnClearPinStatusFunc = int32_t (*)();
using OnFindProviderListFunc = int32_t (*)();
using OnFindProviderCertificateFunc = int32_t (*)();
using OnFindProviderAllCertificateFunc = int32_t (*)();
using OnGetContainerIndexFunc = int32_t (*)();
using OnCreateRemoteKeyHandleFunc = int32_t (*)();
using OnFindRemoteKeyHandleFunc = int32_t (*)();
using OnCloseRemoteKeyHandleFunc = int32_t (*)();
using OnEncryptDataFunc = int32_t (*)();
using OnDecryptDataFunc = int32_t (*)();

namespace OHOS {
namespace Security {
namespace Huks {
    class HuksExtensionPluginManager: private OHOS::DelayedSingleton<HuksExtensionPluginManager>{
public:
    std::unordered_map<PluginMethodEnum, void*> m_pluginProviderMap;
    static std::shared_ptr<HksProviderLifeCycleManager> GetInstanceWrapper();
    int32_t RegisterProvider(struct HksProcessInfo &info, const std::string &AbilityName,
    const CppParamSet& paramSet);
    int32_t UnRegisterProvider(struct HksProcessInfo &info, const std::string &AbilityName,
    const CppParamSet& paramSet);
    int32_t OnSigned(const std::string &index, const CppParamSet& paramSet, vector<uint8_t> &outData);
    int32_t OnVerifyPin(const std::string &index, vector<uint8_t> &pinData);
    int32_t OnVerifyPinStatus(const std::string &index);
    int32_t OnClearPinStatus(const std::string &index);
    int32_t OnFindProviderList(const std::string &index, vector<uint8_t> &providersOut);
    int32_t OnFindProviderCertificate(const std::string &index, vector<uint8_t> &cetificatesOut);
    int32_t OnFindProviderAllCertificate(const std::string &index, vector<uint8_t> &cetificatesOut);
    int32_t OnGetContainerIndex(vector<uint8_t> &providersOut, std::string &outIndex);
    int32_t OnCreateRemoteKeyHandle(const std::string &index, std::string &keyIndex);
    int32_t OnFindRemoteKeyHandle(const std::string &index, std::string &keyIndex);
    int32_t OnCloseRemoteKeyHandle(const std::string &index, std::string &keyIndex);
    int32_t OnEncryptData(const std::string &index, const CppParamSet& paramSet, vector<uint8_t> &outData);
    int32_t OnDecryptData(const std::string &index, const CppParamSet& paramSet);

private:
    void* m_pluginHandle = nullptr; // 存储 dlopen 返回的句柄
    std::atomic<int> m_refCount{0};
    int32_t LoadPlugins();
    static std::string GetMethodByEnum(PluginMethodEnum methodEnum);
};
}
}
}
