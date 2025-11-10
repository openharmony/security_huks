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
#include "hks_function_types.h"
#include "safe_map.h"

namespace OHOS {
namespace Security {
namespace Huks {

class HuksLibInterface : private OHOS::DelayedSingleton<HuksLibInterface> {
public:
    OHOS::SafeMap<PluginMethodEnum, void*> m_pluginProviderMap;

    void initProviderMap(OHOS::SafeMap<PluginMethodEnum, void*> &pluginProviderMap);
    static std::shared_ptr<HuksLibInterface> GetInstanceWrapper();
    static void ReleaseInstance();
    int32_t OnRegistProvider(const HksProcessInfo &processInfo,
        const std::string &providerName, const CppParamSet &paramSet);
    int32_t OnUnRegistProvider(const HksProcessInfo &processInfo,
        const std::string &providerName, const CppParamSet &paramSet);
    int32_t OnCreateRemoteKeyHandle(const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet, std::string &handle);
    int32_t OnCloseRemoteKeyHandle(const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet);
    int32_t OnAuthUkeyPin(const HksProcessInfo &processInfo,
        const std::string &index, const CppParamSet &paramSet, int32_t &authState, uint32_t &retryCnt);
    int32_t OnGetVerifyPinStatus(const HksProcessInfo &processInfo,
        const std::string &index, const CppParamSet &paramSet, int32_t &state);
    int32_t OnClearUkeyPinAuthStatus(const HksProcessInfo &processInfo, const std::string &index);
    int32_t OnGetRemoteProperty(const HksProcessInfo &processInfo, const std::string &index,
        const std::string &propertyId, const CppParamSet &paramSet, CppParamSet &outParams);
    int32_t OnExportCertificate(const HksProcessInfo &processInfo,
        const std::string &index, const CppParamSet &paramSet, std::string &certsJson);
    int32_t OnExportProviderAllCertificates(const HksProcessInfo &processInfo,
        const std::string &providerName, const CppParamSet &paramSet, std::string &certsJsonArr);
    int32_t OnInitSession (const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet, uint32_t &handle);
    int32_t OnUpdateSession (const HksProcessInfo &processInfo, const uint32_t &handle,
        const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData);
    int32_t OnFinishSession (const HksProcessInfo &processInfo, const uint32_t &handle,
        const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData);
    int32_t OnAbortSession(const HksProcessInfo &processInfo, const uint32_t &handle,
        const CppParamSet &paramSet);
private:
    std::mutex mapMutex_;
};

}
}
}
#endif