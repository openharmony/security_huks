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

#include "hks_extension_connection.h"
#include "hks_log.h"
#include "hks_template.h"
#include "huks_access_ext_base_stub.h"
#include "iremote_object.h"
#include "hks_ext_cert_info.h"
#include "hks_ext_error_info.h"

namespace OHOS {
namespace Security {
namespace Huks {

class HksCryptoExtStubImpl : public HuksAccessExtBaseStub {
public:
    explicit HksCryptoExtStubImpl() = default;
    ~HksCryptoExtStubImpl() {}

    ErrCode OpenRemoteHandle(
        const std::string& index,
        const CppParamSet& params,
        std::string& handle,
        HksExternalErrorInfoIdl& errorInfo)
    {
        if (index.find("HksSessionMgrTest003") != std::string::npos) {
            handle = "HksSessionMgrTest003";
            errorInfo.errVal = 0;
            errorInfo.hasErrorInfo = false;
            return 0;
        }
        if (index.find("SessionMgrFullTest") != std::string::npos) {
            handle = "SessionMgrFullTest";
            errorInfo.errVal = 0;
            errorInfo.hasErrorInfo = false;
            return 0;
        }
        errorInfo.hasErrorInfo = false;
        return -1;
    };

    ErrCode CloseRemoteHandle(
        const std::string& handle,
        const CppParamSet& params,
        HksExternalErrorInfoIdl& errorInfo)
    {
        if (handle == "HksSessionMgrTest003" || handle == "SessionMgrFullTest") {
            errorInfo.errVal = 0;
            errorInfo.hasErrorInfo = false;
            return 0;
        }
        errorInfo.hasErrorInfo = false;
        return -1;
    };

    ErrCode AuthUkeyPin(
        const std::string& handle,
        const CppParamSet& params,
        HksExternalErrorInfoIdl& errorInfo,
        int32_t& authState,
        uint32_t& retryCnt)
    {
        if(handle == "HksSessionMgrTest003") {
            authState = 1;
            errorInfo.errVal = 0;
            errorInfo.hasErrorInfo = false;
            return 0;
        }
        errorInfo.hasErrorInfo = false;
        return 0;
    };

    ErrCode GetUkeyPinAuthState(
        const std::string& handle,
        const CppParamSet& params,
        int32_t& state,
        HksExternalErrorInfoIdl& errorInfo) { errorInfo.hasErrorInfo = false; return -1; };

    ErrCode Sign(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& inData,
        std::vector<uint8_t>& outData,
        HksExternalErrorInfoIdl& errorInfo) { errorInfo.hasErrorInfo = false; return -1; };

    ErrCode Verify(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& plainText,
        const std::vector<uint8_t>& signature,
        HksExternalErrorInfoIdl& errorInfo) { errorInfo.hasErrorInfo = false; return -1; };

    ErrCode ExportCertificate(
        const std::string& index,
        const CppParamSet& params,
        std::string& certJsonArr,
        HksExternalErrorInfoIdl& errorInfo) { errorInfo.hasErrorInfo = false; return -1; };

    ErrCode ExportProviderCertificates(
        const CppParamSet& params,
        std::string& certJsonArr,
        HksExternalErrorInfoIdl& errorInfo) { errorInfo.hasErrorInfo = false; return -1; };

    ErrCode InitSession(
        const std::string& index,
        const CppParamSet& params,
        std::string& handle,
        HksExternalErrorInfoIdl& errorInfo)
    {
        if (index == "HksSessionMgrTest003" || index == "SessionMgrFullTest") {
            handle = index;
            errorInfo.errVal = 0;
            errorInfo.hasErrorInfo = false;
            return 0;
        }
        errorInfo.hasErrorInfo = false;
        return -1;
    };

    ErrCode UpdateSession(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& inData,
        std::vector<uint8_t>& outData,
        HksExternalErrorInfoIdl& errorInfo)
    {
        if (handle == "HksSessionMgrTest003" || handle == "SessionMgrFullTest") {
            errorInfo.errVal = 0;
            errorInfo.hasErrorInfo = false;
            return 0;
        }
        errorInfo.hasErrorInfo = false;
        return -1;
    };

    ErrCode FinishSession(
        const std::string& handle,
        const CppParamSet& params,
        const std::vector<uint8_t>& inData,
        std::vector<uint8_t>& outData,
        HksExternalErrorInfoIdl& errorInfo)
    {
        if (handle == "HksSessionMgrTest003" || handle == "SessionMgrFullTest") {
            errorInfo.errVal = 0;
            errorInfo.hasErrorInfo = false;
            return 0;
        }
        errorInfo.hasErrorInfo = false;
        return -1;
    };

    ErrCode SetOrGetProperty(
        uint32_t operation,
        const std::string& handle,
        const std::string& propertyId,
        CppParamSet& params,
        HksExternalErrorInfoIdl& errorInfo) { errorInfo.hasErrorInfo = false; return -1; };
    
    ErrCode GetResourceId(
        const CppParamSet& params,
        std::string& resourceId,
        HksExternalErrorInfoIdl& errorInfo) { errorInfo.hasErrorInfo = false; return -1; };
    
    ErrCode ClearUkeyPinAuthState(
        const std::string& handle,
        const CppParamSet& params,
        HksExternalErrorInfoIdl& errorInfo)
    {
        if (handle == "HksSessionMgrTest003" || handle == "SessionMgrFullTest") {
            errorInfo.errVal = 0;
            errorInfo.hasErrorInfo = false;
            return 0;
        }
        errorInfo.hasErrorInfo = false;
        return -1;
    };
    
    ErrCode ImportWrappedKey(
        const std::string& index,
        const std::string& wrappingKeyIndex,
        const CppParamSet& params,
        const std::vector<uint8_t>& wrappedData,
        HksExternalErrorInfoIdl& errorInfo) { errorInfo.hasErrorInfo = false; return -1; };

    ErrCode ExportPublicKey(
        const std::string& index,
        const CppParamSet& params,
        std::vector<uint8_t>& outData,
        HksExternalErrorInfoIdl& errorInfo) { errorInfo.hasErrorInfo = false; return -1; };
    
    ErrCode ImportCertificate(
        const std::string& index,
        const HksExtCertInfoIdl& certInfo,
        const CppParamSet& params,
        HksExternalErrorInfoIdl& errorInfo) { errorInfo.hasErrorInfo = false; return -1; };

    ErrCode GenerateKey(
        const std::string& index,
        const CppParamSet& params,
        HksExternalErrorInfoIdl& errorInfo) { errorInfo.hasErrorInfo = false; return -1; };
};

sptr<IRemoteObject> CreateMockRemoteObject()
{
    return sptr<HuksAccessExtBaseStub>(new HksCryptoExtStubImpl());
}

void ExtensionConnection::OnAbilityConnectDone(const OHOS::AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    return;
}

int32_t ExtensionConnection::OnConnection(const AAFwk::Want &want, sptr<ExtensionConnection> &connect, int32_t userid)
{
    return HKS_SUCCESS;
}

void ExtensionConnection::OnDisconnect(sptr<ExtensionConnection> &connect)
{
    return;
}

void ExtensionConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode)
{
    return;
}

sptr<IRemoteObject> ExtensionConnection::GetRemoteObject()
{
    return sptr<HuksAccessExtBaseStub>(new HksCryptoExtStubImpl());
}

bool ExtensionConnection::IsConnected()
{
    return isConnected_.load();
}

void ExtensionConnection::AddExtDeathRecipient(const wptr<IRemoteObject>& token)
{
    return;
}

void ExtensionConnection::RemoveExtDeathRecipient(const wptr<IRemoteObject>& token)
{
    return;
}

void ExtensionConnection::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    return;
}

ExtensionConnection::ExtensionConnection(const HksProcessInfo& processInfo)
{
    return;
}

void ExtensionConnection::callBackFromPlugin(std::function<void(HksProcessInfo)> callback)
{
    return;
}

ExtensionDeathRecipient::ExtensionDeathRecipient(RemoteDiedHandler handler) : handler_(handler)
{
}

ExtensionDeathRecipient::~ExtensionDeathRecipient()
{
}

void ExtensionDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    return;
}

}
}
}