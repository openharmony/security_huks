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

#include "singleton.h"
#include "hks_template.h"
#include "hks_error_code"

namespace OHOS {
namespace Security {
namespace Huks {
class HuksLibEntry : private OHOS::DelayedSingleton<HuksExtensionPluginManager> {
public:
    std::unordered_map<PluginMethodEnum, void*> pluginProviderMap;
    static void initProviderMap(std::unordered_map<PluginMethodEnum, void*>& pluginProviderMap);
    static std::shared_ptr<HksProviderLifeCycleManager> GetInstanceWrapper();
    static void ReleaseInstance();

    int32_t OnRegistProvider(); // TODO
    int32_t OnUnRegistProvider();
    int32_t RegistLibFunction(int32_t funCode, void *fun); // TODO

    int32_t OnCreateRemoteIndex(const std::string &providerName, const CppParamSet& paramSet, std::string &outIndex);
    int32_t OnCreateRemoteKeyHandle(const std::string &index);
    int32_t OnFindRemoteKeyHandle(const std::string &index, std::string &keyIndex);
    int32_t OnCloseRemoteKeyHandle(const std::string &index, std::string &keyIndex);

    int32_t OnSigned(const std::string &index, const CppParamSet& paramSet, vector<uint8_t> &outData);
    int32_t OnAuthUkeyPin(const std::string &index, const vector<uint8_t> &pinData, bool outStatus, int32_t retryCnt);
    int32_t OnGetVerifyPinStatus(const std::string &index, int32_t &pinStatus);
    int32_t OnClearPinStatus(const std::string &index);
    
    int32_t OnListProviders(vector<uint8_t> &providersOut);
    int32_t OnFindProviderCertificate(const std::string &index, vector<uint8_t> &cetificatesOut); // 可能不需要
    int32_t OnListProviderAllCertificate(const std::string &providerName, std::string &cetificatesOut); // 这里证书会带上index

private:
    std::mutex mapMutex_;
};
}
}
}
#endif