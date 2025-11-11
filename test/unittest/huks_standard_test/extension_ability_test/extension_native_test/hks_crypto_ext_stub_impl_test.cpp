/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "assistant.h"
#include "extension_context.h"
#include "hks_cpp_paramset.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "hks_crypto_ext_stub_impl.h"
#include "native_reference_mock.h"

namespace OHOS::Security::Huks {
using namespace testing;
using namespace testing::ext;

class CryptoExtAbilityStubTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
    }
    static void TearDownTestCase()
    {
    }
    void SetUp() {}
    void TearDown() {};
};

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0000, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    std::string index;
    CppParamSet params;
    std::string handle;
    int32_t errcode;
    hksCryptoExtStubImpl.OpenRemoteHandle(index, params, handle, errcode);
}
}