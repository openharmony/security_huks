/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include <string>
#include "hks_cpp_paramset.h"
#include "hks_plugin_def.h"
#include "hks_cfi.h"
#include "hks_external_error_info.h"
#include "hks_cpp_abilityinfo.h"
#include "hks_error_code.h"
#include "hks_extension_connection.h"
#include "huks_access_ext_base_stub.h"

// Mock HksGetBundleNameFromUid in global namespace (matches hks_bms_api_wrap.h declaration).
int32_t HksGetBundleNameFromUid(uint32_t uid, std::string &bundleName)
{
    bundleName = "com.huawei.extensionhap.test";
    return HKS_SUCCESS;
}

namespace OHOS {
namespace Security {
namespace Huks {

// Mock system adapter functions to avoid calling real BMS/OSAccount services in tests.
// These override the real implementations from libhuks_ukey_common_static.
int32_t HksGetFrontUserId(int32_t &outId)
{
    outId = 100;
    return HKS_SUCCESS;
}

int32_t VerifyCallerAndAdjustUidParam(const HksProcessInfo &processInfo, const CppParamSet &paramSet,
    CppParamSet &newParamSet)
{
    return HKS_SUCCESS;
}

// Mock ExtensionConnection to avoid calling real Ability Manager Service in tests.
// These override the real implementations from libhuks_ukey_plugin_extesnion_static.
class HksCryptoExtStubImpl : public HuksAccessExtBaseStub {
public:
    explicit HksCryptoExtStubImpl() = default;
    ~HksCryptoExtStubImpl() {}

    ErrCode OpenRemoteHandle(const std::string&, const CppParamSet&, std::string&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode CloseRemoteHandle(const std::string&, const CppParamSet&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode AuthUkeyPin(const std::string&, const CppParamSet&, HksExternalErrorInfoIdl&, int32_t&, uint32_t&) { return 0; }
    ErrCode GetUkeyPinAuthState(const std::string&, const CppParamSet&, int32_t&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode ExportCertificate(const std::string&, const CppParamSet&, std::string&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode ExportProviderCertificates(const CppParamSet&, std::string&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode InitSession(const std::string&, const CppParamSet&, std::string&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode UpdateSession(const std::string&, const CppParamSet&, const std::vector<uint8_t>&, std::vector<uint8_t>&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode FinishSession(const std::string&, const CppParamSet&, const std::vector<uint8_t>&, std::vector<uint8_t>&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode SetOrGetProperty(uint32_t, const std::string&, const std::string&, CppParamSet&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode GetResourceId(const CppParamSet&, std::string&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode ClearUkeyPinAuthState(const std::string&, const CppParamSet&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode ImportWrappedKey(const std::string&, const std::string&, const CppParamSet&, const std::vector<uint8_t>&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode ExportPublicKey(const std::string&, const CppParamSet&, std::vector<uint8_t>&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode ImportCertificate(const std::string&, const HksExtCertInfoIdl&, const CppParamSet&, HksExternalErrorInfoIdl&) { return 0; }
    ErrCode GenerateKey(const std::string&, const CppParamSet&, HksExternalErrorInfoIdl&) { return 0; }
};

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

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnRegisterProvider(
    const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, std::function<void(HksProcessInfo)> callback))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnUnRegisterProvider(
    const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, bool isdeath, int32_t &deleteCount))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnOpenRemoteHandle(
    const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet,
    struct HksExternalErrorInfo **errInfo))
{
    (void)errInfo;
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnCloseRemoteHandle(
    const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet,
    struct HksExternalErrorInfo **errInfo))
{
    (void)errInfo;
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnAuthUkeyPin(
    const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, struct HksExtAuthPinOutParam &authOutParam,
    struct HksExternalErrorInfo **errInfo))
{
    (void)errInfo;
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnGetUkeyPinAuthState(
    const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet,
    int32_t &state, struct HksExternalErrorInfo **errInfo))
{
    (void)errInfo;
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnExportCertificate(
    const HksProcessInfo &processInfo, const std::string &index, const CppParamSet &paramSet,
    std::string &certsJson, struct HksExternalErrorInfo **errInfo))
{
    (void)errInfo;
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnExportProviderCertificates(
    const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, std::string &certsJsonArr, struct HksExternalErrorInfo **errInfo))
{
    (void)errInfo;
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnInitSession(
    struct HksProcessWithErrorInfo &processAndError, const std::string &index, const CppParamSet &paramSet, uint32_t &handle))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnUpdateSession(
    struct HksProcessWithErrorInfo &processAndError, const uint32_t &handle, const CppParamSet &paramSet,
    const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnFinishSession(
    struct HksProcessWithErrorInfo &processAndError, const uint32_t &handle, const CppParamSet &paramSet,
    const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnAbortSession(
    struct HksProcessWithErrorInfo &processAndError, const uint32_t &handle, const CppParamSet &paramSet))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnClearUkeyPinAuthState(
    const HksProcessInfo &processInfo, const std::string &index, struct HksExternalErrorInfo **errInfo))
{
    (void)errInfo;
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnSetOrGetRemoteProperty(
    struct HksProcessWithErrorInfo &processAndError, enum HksExtPropertyOperation operation,
    const std::string &index, const std::string &propertyId, CppParamSet &paramSet))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnUnregisterAllObservers())
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnImportCertificate(
    const HksProcessInfo &processInfo, const std::string &index,
    const struct HksExtCertInfo &certInfo, const CppParamSet &paramSet,
    struct HksExternalErrorInfo **errInfo))
{
    (void)errInfo;
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnGenerateKey(
    struct HksProcessWithErrorInfo &processAndError, const std::string &index, const CppParamSet &paramSet))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnImportWrappedKey(
    struct HksProcessWithErrorInfo &processAndError, const std::string &index, const std::string &wrappingKeyIndex,
    const CppParamSet &paramSet, const std::vector<uint8_t> &wrappedData))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnExportPublicKey(
    struct HksProcessWithErrorInfo &processAndError, const std::string &index, const CppParamSet &paramSet, 
    std::vector<uint8_t> &outData))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnGetResourceId(
    const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, std::string &resourceId, struct HksExternalErrorInfo **errInfo))
{
    (void)errInfo;
    resourceId = "testResourceId";
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnQueryAbilityInfo(
    const HksProcessInfo &processInfo, std::string &resourceId, CppAbilityInfo &abilityInfo))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnSetExtensionProxy(
    const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, void *remoteObjectRaw))
{
    return 0;
}

extern "C" void *__wrap_dlopen(const char* filename, int flags)
{
    static int fakeHandle = 1;
    return &fakeHandle;
}

extern "C" int __wrap_dlclose(void* handle)
{
    return 0;
}

extern "C" void *__wrap_dlsym(void* handle, const char* symbol)
{
    static const struct {
        const char *name;
        void *fake;
    } kFakeSymbols[] = {
        {"_ZN4OHOS8Security4Huks30HksExtPluginOnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetNS5_8functionIFvS2_EEE", 
         (void*)Fake_HksExtPluginOnRegisterProvider},
        {"_ZN4OHOS8Security4Huks32HksExtPluginOnUnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetbRi",
         (void*)Fake_HksExtPluginOnUnRegisterProvider},
         {"_ZN4OHOS8Security4Huks30HksExtPluginOnOpenRemoteHandleERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetPP20HksExternalErrorInfo",
         (void*)Fake_HksExtPluginOnOpenRemoteHandle},
         {"_ZN4OHOS8Security4Huks31HksExtPluginOnCloseRemoteHandleERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetPP20HksExternalErrorInfo",
         (void*)Fake_HksExtPluginOnCloseRemoteHandle},
         {"_ZN4OHOS8Security4Huks25HksExtPluginOnAuthUkeyPinERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetR21HksExtAuthPinOutParamPP20HksExternalErrorInfo",
         (void*)Fake_HksExtPluginOnAuthUkeyPin},
         {"_ZN4OHOS8Security4Huks33HksExtPluginOnGetUkeyPinAuthStateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRiPP20HksExternalErrorInfo",
         (void*)Fake_HksExtPluginOnGetUkeyPinAuthState},
         {"_ZN4OHOS8Security4Huks35HksExtPluginOnClearUkeyPinAuthStateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEEPP20HksExternalErrorInfo",
         (void*)Fake_HksExtPluginOnClearUkeyPinAuthState},
         {"_ZN4OHOS8Security4Huks29HksExtPluginOnExportCerticateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_PP20HksExternalErrorInfo",
         (void*)Fake_HksExtPluginOnExportCertificate},
         {"_ZN4OHOS8Security4Huks38HksExtPluginOnExportProviderCerticatesERK14HksProcessInfo"
        "RKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_PP20HksExternalErrorInfo",
         (void*)Fake_HksExtPluginOnExportProviderCertificates},
         {"_ZN4OHOS8Security4Huks25HksExtPluginOnInitSessionER23HksProcessWithErrorInfoRKNSt3__h12basic_string"
        "IcNS4_11char_traitsIcEENS4_9allocatorIcEEEERK11CppParamSetRj",
         (void*)Fake_HksExtPluginOnInitSession},
         {"_ZN4OHOS8Security4Huks27HksExtPluginOnUpdateSessionER23HksProcessWithErrorInfoRKjRK11CppParamSet"
         "RKNSt3__h6vectorIhNS9_9allocatorIhEEEERSD_",
         (void*)Fake_HksExtPluginOnUpdateSession},
         {"_ZN4OHOS8Security4Huks27HksExtPluginOnFinishSessionER23HksProcessWithErrorInfoRKjRK11CppParamSet"
         "RKNSt3__h6vectorIhNS9_9allocatorIhEEEERSD_",
         (void*)Fake_HksExtPluginOnFinishSession},
         {"_ZN4OHOS8Security4Huks26HksExtPluginOnAbortSessionER23HksProcessWithErrorInfoRKjRK11CppParamSet",
         (void*)Fake_HksExtPluginOnAbortSession},
         {"_ZN4OHOS8Security4Huks31HksExtPluginOnImportCertificateERK14HksProcessInfoRKNSt3__h12basic_string"
         "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK14HksExtCertInfoRK11CppParamSetPP20HksExternalErrorInfo",
         (void*)Fake_HksExtPluginOnImportCertificate},
         {"_ZN4OHOS8Security4Huks25HksExtPluginOnGenerateKeyER23HksProcessWithErrorInfoRKNSt3__h12basic_string"
        "IcNS4_11char_traitsIcEENS4_9allocatorIcEEEERK11CppParamSet",
         (void*)Fake_HksExtPluginOnGenerateKey},
         {"_ZN4OHOS8Security4Huks30HksExtPluginOnImportWrappedKeyER23HksProcessWithErrorInfoRKNSt3__h12basic_string"
         "IcNS4_11char_traitsIcEENS4_9allocatorIcEEEESC_RK11CppParamSetRKNS4_6vectorIhNS8_IhEEEE",
         (void*)Fake_HksExtPluginOnImportWrappedKey},
         {"_ZN4OHOS8Security4Huks29HksExtPluginOnExportPublicKeyER23HksProcessWithErrorInfoRKNSt3__h12basic_string"
         "IcNS4_11char_traitsIcEENS4_9allocatorIcEEEERK11CppParamSetRNS4_6vectorIhNS8_IhEEEE",
         (void*)Fake_HksExtPluginOnExportPublicKey},
         {"_ZN4OHOS8Security4Huks27HksExtPluginOnGetResourceIdERK14HksProcessInfoRKNSt3__h12basic_string"
         "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_PP20HksExternalErrorInfo",
         (void*)Fake_HksExtPluginOnGetResourceId},
         {"_ZN4OHOS8Security4Huks30HksExtPluginOnQueryAbilityInfoERK14HksProcessInfoRNSt3__h12basic_stringIcNS5_11"
         "char_traitsIcEENS5_9allocatorIcEEEER14CppAbilityInfo",
         (void*)Fake_HksExtPluginOnQueryAbilityInfo},
         {"_ZN4OHOS8Security4Huks36HksExtPluginOnUnregisterAllObserversEv",
         (void*)Fake_HksExtPluginOnUnregisterAllObservers},
         {"_ZN4OHOS8Security4Huks36HksExtPluginOnSetOrGetRemotePropertyER23HksProcessWithErrorInfo"
         "23HksExtPropertyOperationRKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEESD_R11CppParamSet",
         (void*)Fake_HksExtPluginOnSetOrGetRemoteProperty},
         {"_ZN4OHOS8Security4Huks31HksExtPluginOnSetExtensionProxyERK14HksProcessInfoRKNSt3__h12basic_string"
         "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetPv",
         (void*)Fake_HksExtPluginOnSetExtensionProxy},
    };

    for (auto &item : kFakeSymbols) {
        if (strcmp(symbol, item.name) == 0) {
            return item.fake;
        }
    }

    void *real_sym = dlsym(handle, symbol);
    return real_sym;
}

}
}
}