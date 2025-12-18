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
#include "hks_provider_life_cycle_manager.h"
#include "hks_cpp_paramset.h"
#include "hks_ukey_common.h"
#include "hks_error_code.h"
#include "hks_log.h"
#include "hks_template.h"
#include "huks_access_ext_base_stub.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include <string>
#include <tuple>
#include "hks_json_wrapper.h"
namespace OHOS::Security::Huks {

class HksCryptoExtStubImpl : public HuksAccessExtBaseStub {
public:
    explicit HksCryptoExtStubImpl() = default;
    ~HksCryptoExtStubImpl() {}

    ErrCode OpenRemoteHandle(
        const std::string& index,
        const CppParamSet& params,
        std::string& handle,
        int32_t& errcode) { return HKS_SUCCESS; };

    ErrCode CloseRemoteHandle(
        const std::string& handle,
        const CppParamSet& params,
        int32_t& errcode) { return HKS_SUCCESS; };

    ErrCode AuthUkeyPin(
        const std::string& handle,
        const CppParamSet& params,
        int32_t& errcode,
        int32_t& authState,
        uint32_t& retryCnt) { return HKS_SUCCESS; };

    ErrCode GetUkeyPinAuthState(
        const std::string& handle,
        const CppParamSet& params,
        int32_t& state,
        int32_t& errcode) { return HKS_SUCCESS; };

    ErrCode Sign(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& inData,
        std::vector<uint8_t>& outData,
        int32_t& errcode) { return HKS_SUCCESS; };

    ErrCode Verify(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& plainText,
        const std::vector<uint8_t>& signature,
        int32_t& errcode) { return HKS_SUCCESS; };

    ErrCode ExportCertificate(
    const std::string& index,
    const CppParamSet& params,
    std::string& certJsonArr,
    int32_t& errcode) 
{ 
    CommJsonObject certArray = CommJsonObject::CreateArray();
    if (certArray.IsNull()) {
        errcode = HKS_ERROR_MALLOC_FAIL;
        return ERR_OK;
    }

    CommJsonObject certObj = CommJsonObject::CreateObject();
    if (certObj.IsNull()) {
        errcode = HKS_ERROR_MALLOC_FAIL;
        return ERR_OK;
    }

    if (!certObj.SetValue("purpose", 1) ||
        !certObj.SetValue("index", std::string("test_cert_index")) ||
        !certObj.SetValue("cert", std::string("MIIBIjANBgkqh"))) {
        errcode = HKS_ERROR_JSON_SERIALIZE_FAILED;
        return ERR_OK;
    }

    if (!certArray.AppendElement(certObj)) {
        errcode = HKS_ERROR_JSON_SERIALIZE_FAILED;
        return ERR_OK;
    }

    certJsonArr = certArray.Serialize(false);
    errcode = HKS_SUCCESS;
    return ERR_OK; 
};

ErrCode ExportProviderCertificates(
    const CppParamSet& params,
    std::string& certJsonArr,
    int32_t& errcode) 
{ 
    CommJsonObject certArray = CommJsonObject::CreateArray();
    if (certArray.IsNull()) {
        errcode = HKS_ERROR_MALLOC_FAIL;
        return ERR_OK;
    }
    for (int i = 0; i < 3; i++) {
        CommJsonObject certObj = CommJsonObject::CreateObject();
        if (certObj.IsNull()) {
            errcode = HKS_ERROR_MALLOC_FAIL;
            return ERR_OK;
        }

        std::string indexStr = "cert_index_" + std::to_string(i);
        std::string certData = "MIIBIjANBgkqhkEAcertdata" + std::to_string(i);

        if (!certObj.SetValue("purpose", i + 1) ||
            !certObj.SetValue("index", indexStr) ||
            !certObj.SetValue("cert", certData)) {
            errcode = HKS_ERROR_JSON_SERIALIZE_FAILED;
            return ERR_OK;
        }
        if (!certArray.AppendElement(certObj)) {
            errcode = HKS_ERROR_JSON_SERIALIZE_FAILED;
            return ERR_OK;
        }
    }
    certJsonArr = certArray.Serialize(false);
    errcode = HKS_SUCCESS;
    return ERR_OK; 
};

    ErrCode InitSession(
        const std::string& index,
        const CppParamSet& params,
        std::string& handle,
        int32_t& errcode) { return HKS_SUCCESS; };

    ErrCode UpdateSession(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& inData,
        std::vector<uint8_t>& outData,
        int32_t& errcode) { return HKS_SUCCESS; };

    ErrCode FinishSession(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& inData,
        std::vector<uint8_t>& outData,
        int32_t& errcode) { return HKS_SUCCESS; };

    ErrCode GetProperty(
        const std::string& handle,
        const std::string& propertyId,
        const CppParamSet& params,
        CppParamSet& outParams,
        int32_t& errcode) { return HKS_SUCCESS; };
    
    ErrCode GetResourceId(
        const CppParamSet& params,
        std::string& resourceId,
        int32_t& errcode) { return HKS_SUCCESS; };
    
    ErrCode ClearUkeyPinAuthState(
        const std::string& handle,
        const CppParamSet& params,
        int32_t& errcode) { return HKS_SUCCESS; };
};

bool ProviderInfo::operator==(const ProviderInfo &other) const
{
    return m_bundleName == other.m_bundleName && m_providerName == other.m_providerName &&
        m_abilityName == other.m_abilityName;
}

bool ProviderInfo::operator<(const ProviderInfo &other) const
{
    return std::tie(m_bundleName, m_providerName, m_abilityName) <
        std::tie(other.m_bundleName, other.m_providerName, other.m_abilityName);
}

std::shared_ptr<HksProviderLifeCycleManager> HksProviderLifeCycleManager::GetInstanceWrapper()
{
    return HksProviderLifeCycleManager::GetInstance();
}

void HksProviderLifeCycleManager::ReleaseInstance()
{
    HksProviderLifeCycleManager::DestroyInstance();
}
void HksProviderLifeCycleManager::PrintRegisterProviders()
{
}

int32_t HksProviderLifeCycleManager::OnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::function<void(HksProcessInfo)> callback)
{
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::GetExtensionProxy(const ProviderInfo &providerInfo,
    sptr<IHuksAccessExtBase> &proxy)
{
    proxy = sptr<HuksAccessExtBaseStub>(new HksCryptoExtStubImpl());
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::HapGetAllConnectInfoByProviderName(const std::string &bundleName,
    const std::string &providerName,
    std::vector<std::pair<ProviderInfo, std::shared_ptr<HksExtAbilityConnectInfo>>> &providerInfos)
{
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::GetAllProviderInfosByProviderName(const std::string &providerName,
    std::vector<ProviderInfo> &providerInfos)
{
    ProviderInfo provider1;
    provider1.m_bundleName = "com.example.crypto.provider1";
    provider1.m_providerName = providerName;
    provider1.m_abilityName = "CryptoExtensionAbility";
    providerInfos.push_back(provider1);
    
    ProviderInfo provider2;
    provider2.m_bundleName = "com.example.security.provider2";
    provider2.m_providerName = providerName;
    provider2.m_abilityName = "SecurityExtensionAbility";
    providerInfos.push_back(provider2);
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::HksHapGetConnectInfos(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet,
    std::vector<std::pair<ProviderInfo, std::shared_ptr<HksExtAbilityConnectInfo>>> &connectionInfos)
{
    return HKS_SUCCESS;
}

int32_t HksProviderLifeCycleManager::OnUnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, [[maybe_unused]] const CppParamSet &paramSet, bool isdeath, int32_t &deleteCount)
{
    return HKS_SUCCESS;
}

int32_t HksGetProviderInfo(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, ProviderInfo &providerInfo)
{
    return HKS_SUCCESS;
}

}