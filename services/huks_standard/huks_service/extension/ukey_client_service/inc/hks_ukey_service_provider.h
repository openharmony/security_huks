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

#ifndef HKS_IPC_SERVICE_PROVIDER_H
#define HKS_IPC_SERVICE_PROVIDER_H

#include "hks_type.h"
#include "hks_plugin_def.h"
#include "hks_service_ipc_serialization.h"
#include "hks_permission_check.h"
#include "hks_template.h"
#include "hks_response.h"
#include "hks_mem.h"
#include "hks_cpp_paramset.h"
#include "hks_plugin_lifecycle_manager.h"
#include <cstdint>
#include <string>
#include <vector>
#include <dlfcn.h>

namespace OHOS {
namespace Security {
namespace Huks {

int32_t HksIpcServiceProviderRegister(const struct HksProcessInfo *processInfo,
    std::string &name, CppParamSet &paramSet);
int32_t HksIpcServiceProviderUnRegister(const struct HksProcessInfo *processInfo,
    std::string &name, CppParamSet &paramSet);
int32_t HksIpcServiceOnCreateRemoteKeyHandle(const struct HksProcessInfo *processInfo, std::string &index,
    CppParamSet &paramSet, std::string &remoteHandleOut);
int32_t HksIpcServiceOnCloseRemoteKeyHandle(const struct HksProcessInfo *processInfo, std::string &index,
    CppParamSet &paramSet);
int32_t HksIpcServiceOnCreateRemoteIndex(const std::string &providerName,
    const CppParamSet& paramSet, std::string &outIndex);
int32_t HksIpcServiceOnAuthUkeyPin(const struct HksProcessInfo *processInfo, const std::string &index,
    CppParamSet &pinData, int32_t &authState, uint32_t &retryCnt);
int32_t HksIpcServiceOnGetVerifyPinStatus(const struct HksProcessInfo *processInfo, const std::string &index,
    const CppParamSet &paramSet, int32_t &state);
int32_t HksIpcServiceOnClearUkeyPinAuthStatus(const struct HksProcessInfo *processInfo, const std::string &index);
int32_t HksIpcServiceOnGetRemoteProperty(const HksProcessInfo *processInfo, const std::string &index,
    const std::string &propertyId, const CppParamSet &paramSet, CppParamSet &outParams);
int32_t HksIpcServiceOnExportCertificate(const struct HksProcessInfo *processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &certificatesOut);
int32_t HksIpcServiceOnExportProviderAllCertificates(const struct HksProcessInfo *processInfo, const std::string &index,
    const CppParamSet &paramSet, std::string &certificatesOut);

}
}
}

#endif