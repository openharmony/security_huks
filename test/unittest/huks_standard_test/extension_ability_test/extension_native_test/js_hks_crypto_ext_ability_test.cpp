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

#include "assistant.h"
#include "extension_context.h"
#include "js_hks_crypto_ext_ability.h"
#include "native_reference_mock.h"

namespace OHOS::Security::Huks {
class JsFileAccessExtAbilityTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        Assistant::ins_ = insMoc;
    }
    static void TearDownTestCase()
    {
        // impl = nullptr;
        insMoc = nullptr;
        ability = nullptr;
        jsRuntime = nullptr;
        Assistant::ins_ = nullptr;
    }
    void SetUp() {}
    void TearDown() {}
public:
    static inline std::shared_ptr<Security::Huks::AssistantMock> insMoc = std::make_shared<AssistantMock>();
    static inline std::unique_ptr<AbilityRuntime::JsRuntime> jsRuntime = std::make_unique<AbilityRuntime::JsRuntime>();
    static inline std::shared_ptr<JsHksCryptoExtAbility> ability = std::make_shared<JsHksCryptoExtAbility>(*jsRuntime);
    // static inline sptr<FileAccessServiceMock> impl = sptr<FileAccessServiceMock>(new FileAccessServiceMock());
    static inline napi_env env = reinterpret_cast<napi_env>(&(jsRuntime->GetNativeEngine()));
};

HWTEST_F(JsFileAccessExtAbilityTest, CallObjectMethod_0000, testing::ext::TestSize.Level0)
{
    EXPECT_NE(ability, nullptr);
    auto result = ability->CallObjectMethod(nullptr, nullptr, 0);
    EXPECT_TRUE(result == nullptr);
}
}