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

#include <string>
#include "hks_plugin_def.h"
#include "hks_cpp_paramset.h"

extern "C" {

int32_t HksExtPluginOnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet)
{
    return 0;
}

int32_t HksExtPluginOnUnRegisterProvider(const HksProcessInfo &processInfo,
    const std::string &providerName, const CppParamSet &paramSet)
{
    return 0;
}

int32_t HksExtPluginOnCreateRemoteIndex(const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, std::string &index)
{
    return 0;
}

int32_t HksExtPluginOnOpemRemoteHandle(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &handle)
{
    return 0;
}

int32_t HksExtPluginOnCloseRemoteHandle(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet)
{
    return 0;
}

int32_t HksExtPluginOnAuthUkeyPin(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, int32_t &authState, uint32_t &retryCnt)
{
    return 0;
}

int32_t HksExtPluginOnGetUkeyPinAuthState(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, int32_t &state)
{
    return 0;
}

int32_t HksExtPluginOnExportCerticate(const HksProcessInfo &processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &certsJson)
{
    return 0;
}

int32_t HksExtPluginOnExportProviderCerticates(
    const HksProcessInfo &processInfo, const std::string &providerName,
    const CppParamSet &paramSet, std::string &certsJsonArr)
{
    return 0;
}

int32_t HksExtPluginOnInitSession(const HksProcessInfo &processInfo,
    const std::string &index, const CppParamSet &paramSet, uint32_t &handle)
{
    return 0;
}

int32_t HksExtPluginOnUpdateSession(const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData)
{
    return 0;
}

int32_t HksExtPluginOnFinishSession(const HksProcessInfo &processInfo, const uint32_t &handle,
    const CppParamSet &paramSet, const std::vector<uint8_t> &inData, std::vector<uint8_t> &outData)
{
    return 0;
}

int32_t HksClearUkeyPinAuthState(const HksProcessInfo &processInfo,
    const std::string &index)
{
    return 0;
}

int32_t HksGetRemoteProperty(const HksProcessInfo &processInfo,
    const std::string &index, const std::string &propertyId, const CppParamSet &paramSet, CppParamSet &outParams)
{
    return 0;
}

}

