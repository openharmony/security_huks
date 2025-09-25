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

#ifndef HKS_LIB_INTERFACE_H
#define HKS_LIB_INTERFACE_H

#include <unordered_map>
#include <string>
#include <mutex>
#include <vector>
#include <memory>

#include "singleton.h"
#include "hks_template.h"
#include "hks_error_code.h"
#include "hks_funtion_types.h"

namespace OHOS {
namespace Security {
namespace Huks {
class HuksLibEntry : private OHOS::DelayedSingleton<HuksLibEntry> {
public:
    std::unordered_map<PluginMethodEnum, void*> pluginProviderMap;

    void initProviderMap(std::unordered_map<PluginMethodEnum, void*>& pluginProviderMap);
    static std::shared_ptr<HuksLibEntry> GetInstanceWrapper();
    static void ReleaseInstance();

    int32_t OnRegistProvider(const HksProcessInfo &processInfo, const std::string &providerName, const CppParamSet &paramSet); // TODO
    int32_t OnUnRegistProvider(const HksProcessInfo &processInfo, const std::string &providerName, const CppParamSet &paramSet);
    int32_t RegistLibFunction(int32_t funCode, void *fun); // TODO

    int32_t OnCreateRemoteIndex(const std::string &providerName, const CppParamSet& paramSet, std::string &outIndex);
    int32_t OnCreateRemoteKeyHandle(const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet, std::string &handle);
    int32_t OnFindRemoteKeyHandle(const std::string &index, std::string &keyIndex);
    int32_t OnCloseRemoteKeyHandle(const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet);
 
    int32_t OnSigned(const std::string &index, const CppParamSet& paramSet, std::vector<uint8_t> &outData);
    int32_t OnAuthUkeyPin(const HksProcessInfo &processInfo,
        const std::string &index, const CppParamSet &paramSet, int32_t& authState, uint32_t& retryCnt);
    int32_t OnGetVerifyPinStatus(const HksProcessInfo &processInfo,
        const std::string &index, const CppParamSet &paramSet, uint32_t &state);
    int32_t OnClearPinStatus(const std::string &index);
    
    int32_t OnListProviders(std::vector<uint8_t> &providersOut);
    int32_t OnFindProviderCertificate(const std::string &index, std::vector<uint8_t> &cetificatesOut); // 可能不需要
    int32_t OnListProviderAllCertificate(const std::string &providerName, std::string &cetificatesOut); // 这里证书会带上index

private:
    std::mutex mapMutex_;

};

}
}
}
#endif