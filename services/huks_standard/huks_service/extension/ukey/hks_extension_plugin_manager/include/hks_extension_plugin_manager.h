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

};
// 在枚举里面去对应
std::string RegisterFunName = "_ZN27HksProviderLifeCycleManager18OnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEERK11CppParamSet";



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
    int32_t OnFindCertificate(const std::string &index, vector<uint8_t> &cetificatesOut);
    int32_t OnEncryptData(const std::string &index, const CppParamSet& paramSet, vector<uint8_t> &outData);
    int32_t OnDecryptData(const std::string &index, const CppParamSet& paramSet, vector<uint8_t> &outData);

public:
    int32_t RegisterProvider(struct HksProcessInfo &info, const std::string &AbilityName,
    const CppParamSet& paramSet);
};
}
}
}
