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

#ifndef HKS_PLUGIN_MANAGER_TEST_H
#define HKS_PLUGIN_MANAGER_TEST_H

#include "hks_lib_interface.h"
#include "hks_plugin_lifecycle_manager.h"
#include "hks_plugin_loader.h"
#include "hks_function_types.h"
#include <gtest/gtest.h>
#include <map>

namespace OHOS {
namespace Security {
namespace Huks {

std::map<PluginMethodEnum, std::string> failMap {
    {PluginMethodEnum::FUNC_ON_REGISTER_PROVIDER, "_Z30HksExtPluginOnRegisterProviderRK14HksProcessInfoRKNSt3__h12basic_stringIcNS2_11char_traitsIcEENS2_9allocator"
        "IcEEEERK11CppParamSet"},
    {PluginMethodEnum::FUNC_ON_UN_REGISTER_PROVIDER, "_Z32HksExtPluginOnUnRegisterProviderRK14HksProcessInfoRKNSt3__h12basic_stringIcNS2_11char_traitsIc"
        "EENS2_9allocatorIcEEEERK11CppParamSet"},
    {PluginMethodEnum::FUNC_ON_CREATE_REMOTE_INDEX, "_Z31HksExtPluginOnCreateRemoteIndexRK14HksProcessInfoRKNSt3__h12basic_stringIcNS2_11char_traits"
        "IcEENS2_9allocatorIcEEEERK11CppParamSetRS8_"},
    {PluginMethodEnum::FUNC_ON_CREATE_REMOTE_KEY_HANDLE, "_Z31HksExtPluginOnCreateRemoteIndexRK14HksProcessInfoRKNSt3__h12basic_stringIcNS2_11char_traits"
        "IcEENS2_9allocatorIcEEEERK11CppParamSetRS8_"},
    {PluginMethodEnum::FUNC_ON_CLOSE_REMOTE_KEY_HANDLE, "_Z31HksExtPluginOnCloseRemoteHandleRK14HksProcessInfoRKNSt3__h12basic_stringIcNS2_11char_traitsIc"
        "EENS2_9allocatorIcEEEERK11CppParamSet"},
    {PluginMethodEnum::FUNC_ON_AUTH_UKEY_PIN, "_Z25HksExtPluginOnAuthUkeyPinRK14HksProcessInfoRKNSt3__h12basic_stringIcNS2_11char_traitsIcEE"
        "NS2_9allocatorIcEEEERK11CppParamSetRiRj"},
    {PluginMethodEnum::FUNC_ON_GET_VERIFY_PIN_STATUS, "_Z33HksExtPluginOnGetUkeyPinAuthStateRK14HksProcessInfoRKNSt3__h12basic_stringIcNS2_11char_traitsI"
        "cEENS2_9allocatorIcEEEERK11CppParamSetRi"},
    {PluginMethodEnum::FUNC_ON_CLEAR_PIN_STATUS, "_Z24HksClearUkeyPinAuthStateRK14HksProcessInfoRKNSt3__h12basic_stringIcNS2_11char_traits"
        "IcEENS2_9allocatorIcEEEE"},
    {PluginMethodEnum::FUNC_ON_GET_REMOTE_PROPERTY, "_Z24HksGetUkeyRemotePropertyRK14HksProcessInfoRKNSt3__h12basic_stringIcNS2_11char_traitsIcEENS2_9allocator"
        "IcEEEESA_RK11CppParamSetRSB_"},
    {PluginMethodEnum::FUNC_ON_LIST_INDEX_CERTIFICATE, "_Z29HksExtPluginOnExportCerticateRK14HksProcessInfoRKNSt3__h12basic_stringIcNS2_11char_traitsIc"
        "EENS2_9allocatorIcEEEERK11CppParamSetRS8_"},
    {PluginMethodEnum::FUNC_ON_LIST_PROVIDER_ALL_CERTIFICATE, "_Z38HksExtPluginOnExportProviderCerticatesRK14HksProcessInfoRKNSt3__h12basic_stringIcNS2_11char_traits"
        "IcEENS2_9allocatorIcEEEERK11CppParamSetRS8_"},
    {PluginMethodEnum::FUNC_ON_INIT_SESSION, "_Z25HksExtPluginOnInitSessionRK14HksProcessInfoRKNSt3__h12basic_stringIcNS2_11char_traitsIc"
        "EENS2_9allocatorIcEEEERK11CppParamSetRj"},
    {PluginMethodEnum::FUNC_ON_UPDATE_SESSION, "_Z27HksExtPluginOnUpdateSessionRK14HksProcessInfoRKjRK11CppParamSetRKNSt3__h6vector"
        "IhNS7_9allocatorIhEEEERSB_"},
    {PluginMethodEnum::FUNC_ON_FINISH_SESSION, "_Z27HksExtPluginOnFinishSessionRK14HksProcessInfoRKjRK11CppParamSetRKNSt3__h6vectorIhNS7_9allocatorIhEEEERSB_"}
};
    
class ExtensionPluginMgrTest : public testing::Test {
protected:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<HuksPluginLifeCycleMgr> pluginManager_;
    HksProcessInfo info_;
    std::string providerName_;
    CppParamSet paramSet_;
};



}
}
}

#endif