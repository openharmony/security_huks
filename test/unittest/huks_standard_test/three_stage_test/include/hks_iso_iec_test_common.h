/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef HKS_ISO_IEC_TEST_COMMON_H
#define HKS_ISO_IEC_TEST_COMMON_H

#include <string>
#include "device_manager_callback.h"

namespace Unittest::IsoIec {
static const std::string g_pkgName = "Hks_ISO_IEC_Test";

int32_t HksGetLocalDeviceType(int32_t &deviceType);

class DmInitCallbackTest : public OHOS::DistributedHardware::DmInitCallback {
public:
    DmInitCallbackTest() : DmInitCallback() {}
    virtual ~DmInitCallbackTest() {}
    void OnRemoteDied() override {}
};
} // namespace Unittest::IsoIec
#endif // HKS_ISO_IEC_TEST_COMMON_H
