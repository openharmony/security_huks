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

#ifndef HKS_REMOTE_HANDLE_MANAGER_H
#define HKS_REMOTE_HANDLE_MANAGER_H

#include "hks_cpp_paramset.h"
#include "hks_plugin_def.h"
#include "hks_provider_life_cycle_manager.h"
#include "singleton.h"
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "safe_map.h"
#include "ihuks_access_ext_base.h"
#include "hks_json_wrapper.h"

namespace OHOS {
namespace Security {
namespace Huks {
class HksRemoteHandleManager : private OHOS::DelayedSingleton<HksRemoteHandleManager>,
    std::enable_shared_from_this<HksRemoteHandleManager> {
public:

    static std::shared_ptr<HksRemoteHandleManager> GetInstanceWrapper();
    static void ReleaseInstance();
    // handle manager
    int32_t CreateRemoteHandle(const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet);
    int32_t CloseRemoteHandle(const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet);
    // ukey PIN manager
    int32_t RemoteVerifyPin(const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet,
        int32_t &authState, uint32_t &retryCnt);
    int32_t RemoteVerifyPinStatus(const HksProcessInfo &processInfo,
        const std::string &index, const CppParamSet &paramSet, int32_t &state);
    int32_t RemoteClearPinStatus(const HksProcessInfo &processInfo, const std::string &index,
        const CppParamSet &paramSet);
    int32_t CheckAuthStateIsOk(const HksProcessInfo &processInfo, const std::string &index);
    //certificate query
    int32_t FindRemoteCertificate(const std::string &index,
        const CppParamSet &paramSet, std::string &certificatesOut);
    int32_t FindRemoteAllCertificate(const HksProcessInfo &processInfo,
        const std::string &providerName, const CppParamSet &paramSet, std::string &certificatesOut);
    int32_t MergeProviderCertificates(const ProviderInfo &providerInfo, const std::string &providerCertVec,
        CommJsonObject &combinedArray);
    //sign and verify
    int32_t RemoteHandleSign(const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet,
        const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData);
    int32_t RemoteHandleVerify(const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet,
        const std::vector<uint8_t> &plainText, std::vector<uint8_t> &signature);

    int32_t GetRemoteProperty(const HksProcessInfo &processInfo, const std::string& index,
        const std::string& propertyId, const CppParamSet& paramSet, CppParamSet& outParams);

    int32_t ClearRemoteHandleMap(const std::string &providerName, const std::string &abilityName,
        const uint32_t uid);
    static int32_t ParseIndexAndProviderInfo(const std::string &index,
        ProviderInfo &providerInfo, std::string &newIndex);
    void ClearAuthState(const HksProcessInfo &processInfo);
    int32_t ParseAndValidateIndex(const std::string &index, const uint32_t uid, ProviderInfo &providerInfo,
        std::string &handle);
    int32_t GetProviderProxy(const ProviderInfo &providerInfo, OHOS::sptr<IHuksAccessExtBase> &proxy);
    void ClearMapByHandle(const int32_t &ret, const std::string &handle);
    void ClearMapByUid(const uint32_t uid);
    
private:
    bool IsProviderNumExceedLimit(const ProviderInfo &providerInfo);

    OHOS::SafeMap<std::pair<uint32_t, std::string>, std::string> uidIndexToHandle_;
    OHOS::SafeMap<std::pair<uint32_t, std::string>, int32_t> uidIndexToAuthState_;
    OHOS::SafeMap<ProviderInfo, int32_t> providerInfoToNum_;
};
}
}
}
#endif