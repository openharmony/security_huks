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

#include "hks_ukey_system_adapter.h"
#include "hks_error_code.h"
#include <string>

namespace OHOS::Security::Huks {

int32_t HksGetBundleNameFromUid(uint32_t uid, std::string &bundleName)
{
    bundleName = "com.huawei.extensionhap.test";
    return HKS_SUCCESS;
}

int32_t HksGetFrontUserId(int32_t &outId)
{
    outId = 100;
    return HKS_SUCCESS;
}

}
