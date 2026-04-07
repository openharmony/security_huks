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

#ifndef HKS_UKEY_CLIENT_SERVICE_TEST_H
#define HKS_UKEY_CLIENT_SERVICE_TEST_H

#include <gtest/gtest.h>
#include "hks_ukey_client_service.h"
#include "hks_ukey_service_provider_adapter.h"
#include "hks_ukey_service_provider.h"

namespace OHOS {
namespace Security {
namespace Huks {

class UkeyClientServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

} // namespace Huks
} // namespace Security
} // namespace OHOS

#endif // HKS_UKEY_CLIENT_SERVICE_TEST_H
