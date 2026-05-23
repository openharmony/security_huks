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
#include "hks_cpp_abilityinfo.h"
#include "hks_plugin_def.h"
#include "hks_cfi.h"
#include "hks_external_error_info.h"
#include "hks_cpp_abilityinfo.h"

namespace OHOS {
namespace Security {
namespace Huks {
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
         "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRj",
         (void*)Fake_HksExtPluginOnInitSession},
         {"_ZN4OHOS8Security4Huks27HksExtPluginOnUpdateSessionER23HksProcessWithErrorInfoRKjRK11CppParamSet"
         "RKNSt3__h6vectorIhNSA_9allocatorIhEEEERSE_",
         (void*)Fake_HksExtPluginOnUpdateSession},
         {"_ZN4OHOS8Security4Huks27HksExtPluginOnFinishSessionER23HksProcessWithErrorInfoRKjRK11CppParamSet"
         "RKNSt3__h6vectorIhNSA_9allocatorIhEEEERSE_",
         (void*)Fake_HksExtPluginOnFinishSession},
         {"_ZN4OHOS8Security4Huks26HksExtPluginOnAbortSessionER23HksProcessWithErrorInfoRKjRK11CppParamSet",
         (void*)Fake_HksExtPluginOnAbortSession},
         {"_ZN4OHOS8Security4Huks31HksExtPluginOnImportCertificateERK14HksProcessInfoRKNSt3__h12basic_string"
         "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK14HksExtCertInfoRK11CppParamSetPP20HksExternalErrorInfo",
         (void*)Fake_HksExtPluginOnImportCertificate},
         {"_ZN4OHOS8Security4Huks25HksExtPluginOnGenerateKeyER23HksProcessWithErrorInfoRKNSt3__h12basic_string"
         "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSet",
         (void*)Fake_HksExtPluginOnGenerateKey},
         {"_ZN4OHOS8Security4Huks30HksExtPluginOnImportWrappedKeyER23HksProcessWithErrorInfoRKNSt3__h12basic_string"
         "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEESD_RK11CppParamSetRKNS5_6vectorIhNS9_IhEEEE",
         (void*)Fake_HksExtPluginOnImportWrappedKey},
         {"_ZN4OHOS8Security4Huks29HksExtPluginOnExportPublicKeyER23HksProcessWithErrorInfoRKNSt3__h12basic_string"
         "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRNS5_6vectorIhNS9_IhEEEE",
         (void*)Fake_HksExtPluginOnExportPublicKey},
         {"_ZN4OHOS8Security4Huks27HksExtPluginOnGetResourceIdERK14HksProcessInfoRKNSt3__h12basic_string"
         "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_PP20HksExternalErrorInfo",
         (void*)Fake_HksExtPluginOnGetResourceId},
         {"_ZN4OHOS8Security4Huks30HksExtPluginOnQueryAbilityInfoERK14HksProcessInfoRNSt3__h12basic_stringIcNS5_11"
         "char_traitsIcEENS5_9allocatorIcEEEER14CppAbilityInfo",
         (void*)Fake_HksExtPluginOnQueryAbilityInfo},
         {"_ZN4OHOS8Security4Huks27HksExtPluginOnUnregisterAllObserversEv",
         (void*)Fake_HksExtPluginOnUnregisterAllObservers},
         {"_ZN4OHOS8Security4Huks36HksExtPluginOnSetOrGetRemotePropertyER23HksProcessWithErrorInfo23HksExtPropertyOperationRKNSt3__h12basic_string"
         "IcNS6_11char_traitsIcEENS6_9allocatorIcEEEESE_R11CppParamSet",
         (void*)Fake_HksExtPluginOnSetOrGetRemoteProperty},
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