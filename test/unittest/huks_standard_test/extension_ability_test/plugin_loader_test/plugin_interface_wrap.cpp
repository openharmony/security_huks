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

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnRegisterProvider(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnUnRegisterProvider(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnCreateRemoteIndex(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, std::string &index))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnOpemRemoteHandle(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &handle))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnCloseRemoteHandle(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnAuthUkeyPin(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, int32_t &authState, uint32_t &retryCnt))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnGetUkeyPinAuthState(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, int32_t &state))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnExportCerticate(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &certsJson))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnExportProviderCerticates(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string &certsJsonArr))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnInitSession(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, uint32_t &handle))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnUpdateSession(const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksExtPluginOnFinishSession(const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksClearUkeyPinAuthState(const HksProcessInfo &processInfo, const std::string &index))
{
    return 0;
}

ENABLE_CFI(__attribute__((visibility("default"))) int32_t Fake_HksGetUkeyRemoteProperty(const HksProcessInfo &processInfo, const std::string &index,
    const std::string &propertyId, const CppParamSet &paramSet, CppParamSet &outParams))
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
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSet", 
         (void*)Fake_HksExtPluginOnRegisterProvider},
        {"_ZN4OHOS8Security4Huks32HksExtPluginOnUnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSet",
         (void*)Fake_HksExtPluginOnUnRegisterProvider},
         {"_ZN4OHOS8Security4Huks31HksExtPluginOnCreateRemoteIndexERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_",
         (void*)Fake_HksExtPluginOnCreateRemoteIndex},
         {"_ZN4OHOS8Security4Huks30HksExtPluginOnOpemRemoteHandleERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_",
         (void*)Fake_HksExtPluginOnOpemRemoteHandle},
         {"_ZN4OHOS8Security4Huks31HksExtPluginOnCloseRemoteHandleERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSet",
         (void*)Fake_HksExtPluginOnCloseRemoteHandle},
         {"_ZN4OHOS8Security4Huks25HksExtPluginOnAuthUkeyPinERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRiRj",
         (void*)Fake_HksExtPluginOnAuthUkeyPin},
         {"_ZN4OHOS8Security4Huks33HksExtPluginOnGetUkeyPinAuthStateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRi",
         (void*)Fake_HksExtPluginOnGetUkeyPinAuthState},
         {"_ZN4OHOS8Security4Huks24HksClearUkeyPinAuthStateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEE",
         (void*)Fake_HksClearUkeyPinAuthState},
         {"_ZN4OHOS8Security4Huks20HksGetRemotePropertyERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEESD_RK11CppParamSetRSE_",
         (void*)Fake_HksGetUkeyRemoteProperty},
         {"_ZN4OHOS8Security4Huks29HksExtPluginOnExportCerticateERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_",
         (void*)Fake_HksExtPluginOnExportCerticate},
         {"_ZN4OHOS8Security4Huks38HksExtPluginOnExportProviderCerticatesERK14HksProcessInfo"
        "RKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_",
         (void*)Fake_HksExtPluginOnExportProviderCerticates},
         {"_ZN4OHOS8Security4Huks25HksExtPluginOnInitSessionERK14HksProcessInfoRKNSt3__h12basic_string"
        "IcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRj",
         (void*)Fake_HksExtPluginOnInitSession},
         {"_ZN4OHOS8Security4Huks27HksExtPluginOnUpdateSessionERK14HksProcessInfoRKjRK11CppParamSet"
        "RKNSt3__h6vectorIhNSA_9allocatorIhEEEERSE_",
         (void*)Fake_HksExtPluginOnUpdateSession},
         {"_ZN4OHOS8Security4Huks27HksExtPluginOnFinishSessionERK14HksProcessInfoRKjRK11CppParamSet"
        "RKNSt3__h6vectorIhNSA_9allocatorIhEEEERSE_",
         (void*)Fake_HksExtPluginOnFinishSession},
    };

    for (auto &item : kFakeSymbols) {
        if (strcmp(symbol, item.name) == 0) {
            return item.fake;
        }
    }

    void *real_sym = dlsym(handle, symbol);
    return real_sym;
}