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

#ifndef HKS_FUNCTION_TYPES_H
#define HKS_FUNCTION_TYPES_H

#include <map>
#include <string>
#include "hks_plugin_def.h"
#include "hks_cpp_paramset.h"

namespace OHOS {
namespace Security {
namespace Huks {

enum class PluginMethodEnum{
    FUNC_ON_REGISTER_PROVIDER,
    FUNC_ON_UN_REGISTER_PROVIDER,

    FUNC_ON_CREATE_REMOTE_INDEX,
    FUNC_ON_CREATE_REMOTE_KEY_HANDLE,
    FUNC_ON_CLOSE_REMOTE_KEY_HANDLE,
    FUNC_ON_AUTH_UKEY_PIN,
    FUNC_ON_GET_VERIFY_PIN_STATUS,
    
    // FUNC_ON_FIND_REMOTE_KEY_HANDLE,
    // FUNC_ON_SIGNED,
    // FUNC_ON_CLEAR_PIN_STATUS,

    // FUNC_ON_LIST_PROVIDER,
    FUNC_ON_LIST_INDEX_CERTIFICATE,
    FUNC_ON_LIST_PROVIDER_ALL_CERTIFICATE,
    FUNC_ON_INIT_SESSION,
    FUNC_ON_UPDATE_SESSION,
    FUNC_ON_FINISH_SESSION,

    COUNT = 12,
};

static const std::map<PluginMethodEnum, std::string> m_pluginMethodNameMap = {
    {PluginMethodEnum::FUNC_ON_REGISTER_PROVIDER, "_ZN4OHOS8Security4Huks30HksExtPluginOnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSet"},
    {PluginMethodEnum::FUNC_ON_UN_REGISTER_PROVIDER, "_ZN4OHOS8Security4Huks32HksExtPluginOnUnRegisterProviderERK14HksProcessInfoRKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSet"},
    {PluginMethodEnum::FUNC_ON_CREATE_REMOTE_INDEX, "_ZN4OHOS8Security4Huks31HksExtPluginOnCreateRemoteIndexERK14HksProcessInfoRKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_"},
    {PluginMethodEnum::FUNC_ON_CREATE_REMOTE_KEY_HANDLE, "_ZN4OHOS8Security4Huks30HksExtPluginOnOpemRemoteHandleERK14HksProcessInfoRKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_"},
    {PluginMethodEnum::FUNC_ON_CLOSE_REMOTE_KEY_HANDLE, "_ZN4OHOS8Security4Huks31HksExtPluginOnCloseRemoteHandleERK14HksProcessInfoRKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSet"},
    {PluginMethodEnum::FUNC_ON_AUTH_UKEY_PIN, "_ZN4OHOS8Security4Huks25HksExtPluginOnAuthUkeyPinERK14HksProcessInfoRKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRiRj"},
    {PluginMethodEnum::FUNC_ON_GET_VERIFY_PIN_STATUS, "_ZN4OHOS8Security4Huks33HksExtPluginOnGetUkeyPinAuthStateERK14HksProcessInfoRKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRi"},
    // {PluginMethodEnum::FUNC_ON_FIND_REMOTE_KEY_HANDLE, ""},
    // {PluginMethodEnum::FUNC_ON_SIGNED, ""},
    // {PluginMethodEnum::FUNC_ON_CLEAR_PIN_STATUS, ""},
    // {PluginMethodEnum::FUNC_ON_LIST_PROVIDER, ""},
    {PluginMethodEnum::FUNC_ON_LIST_INDEX_CERTIFICATE, "_ZN4OHOS8Security4Huks29HksExtPluginOnExportCerticateERK14HksProcessInfoRKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_"},
    {PluginMethodEnum::FUNC_ON_LIST_PROVIDER_ALL_CERTIFICATE, "_ZN4OHOS8Security4Huks38HksExtPluginOnExportProviderCerticatesERK14HksProcessInfoRKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRSB_"},
    {PluginMethodEnum::FUNC_ON_INIT_SESSION, "_ZN4OHOS8Security4Huks25HksExtPluginOnInitSessionERK14HksProcessInfoRKNSt3__h12basic_stringIcNS5_11char_traitsIcEENS5_9allocatorIcEEEERK11CppParamSetRj"},
    {PluginMethodEnum::FUNC_ON_UPDATE_SESSION, "_ZN4OHOS8Security4Huks27HksExtPluginOnUpdateSessionERK14HksProcessInfoRKjRK11CppParamSetRKNSt3__h6vectorIhNSA_9allocatorIhEEEERSE_"},
    {PluginMethodEnum::FUNC_ON_FINISH_SESSION, "_ZN4OHOS8Security4Huks27HksExtPluginOnFinishSessionERK14HksProcessInfoRKjRK11CppParamSetRKNSt3__h6vectorIhNSA_9allocatorIhEEEERSE_"}
};

using OnRegisterProviderFunc = int32_t (*)(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet);
using OnUnRegisterProviderFunc = int32_t (*)(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet);
using OnCreateRemoteIndexFunc = int32_t (*)();
using OnCreateRemoteKeyHandleFunc = int32_t (*)(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &handle);
using OnFindRemoteKeyHandleFunc = int32_t (*)();
using OnCloseRemoteKeyHandleFunc = int32_t (*)(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet);
using OnSignedFunc = int32_t (*)();
using OnAuthUkeyPinFunc = int32_t (*)(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t& authState, uint32_t& retryCnt);
using OnGetVerifyPinStatusFunc = int32_t (*)(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, int32_t &state);
using OnClearPinStatusFunc = int32_t (*)();
using OnListProvidersFunc = int32_t (*)();
using OnListIndexCertificateFunc = int32_t (*)(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, std::string &certsJson);
using OnListProviderAllCertificateFunc = int32_t (*)(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet, std::string &certsJsonArr);
using OnInitSessionFunc = int32_t (*)(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, uint32_t &handle);
using OnUpdateSessionFunc = int32_t (*)(const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData);
using OnFinishSessionFunc = int32_t (*)(const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData);

}
}
}
#endif