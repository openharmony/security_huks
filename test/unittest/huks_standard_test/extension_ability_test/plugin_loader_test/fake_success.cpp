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

int OnRegisterProvider(const HksProcessInfo &processInfo, const std::string &providerName, const CppParamSet &paramSet) {
    HKS_LOG_I("libfake_success.so coming OnRegisterProvider");
    return 0;
}
int OnUnRegisterProvider(const HksProcessInfo &processInfo, const std::string &providerName, const CppParamSet &paramSet) {
    HKS_LOG_I("libfake_success.so coming OnUnRegisterProvider");
    return 0;
}

}

