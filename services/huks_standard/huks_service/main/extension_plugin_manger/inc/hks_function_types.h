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

enum class PluginMethodEnum {
    FUNC_ON_REGISTER_PROVIDER,
    FUNC_ON_UN_REGISTER_PROVIDER,

    FUNC_ON_CREATE_REMOTE_INDEX,
    FUNC_ON_CREATE_REMOTE_KEY_HANDLE,
    FUNC_ON_CLOSE_REMOTE_KEY_HANDLE,
    FUNC_ON_AUTH_UKEY_PIN,
    FUNC_ON_GET_VERIFY_PIN_STATUS,

    FUNC_ON_CLEAR_PIN_STATUS,
    FUNC_ON_GET_REMOTE_PROPERTY,

    FUNC_ON_LIST_INDEX_CERTIFICATE,
    FUNC_ON_LIST_PROVIDER_ALL_CERTIFICATE,
    FUNC_ON_INIT_SESSION,
    FUNC_ON_UPDATE_SESSION,
    FUNC_ON_FINISH_SESSION,

    COUNT = 14,
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
using OnClearUkeyPinAuthStatusFunc = int32_t (*)(const HksProcessInfo &processInfo, const std::string &index);
using OnGetRemotePropertyFunc = int32_t (*)(const HksProcessInfo &processInfo,
    const std::string &index, const std::string &propertyId, const CppParamSet &paramSet, CppParamSet &outParams);
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