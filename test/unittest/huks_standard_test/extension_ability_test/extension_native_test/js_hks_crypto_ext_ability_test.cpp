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
#include "hks_cpp_paramset.h"
#include "hks_type.h"
#include "hks_type_enum.h"
#include "js_hks_crypto_ext_ability.h"
#include "native_reference_mock.h"

namespace OHOS::Security::Huks {
using namespace testing;
using namespace testing::ext;
// const int ARG_INDEX_FIRST = 1;
const int ARG_INDEX_SECOND = 2;
const int ARG_INDEX_THIRD = 3;
// const int ARG_INDEX_FOUR = 4;
const int ARG_INDEX_FIFTH = 5;

class JsCryptoExtAbilityTest : public testing::Test {
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
    static inline napi_env env = reinterpret_cast<napi_env>(&(jsRuntime->GetNativeEngine()));
};

HWTEST_F(JsCryptoExtAbilityTest, CallObjectMethod_0000, testing::ext::TestSize.Level0)
{
    EXPECT_NE(ability, nullptr);
    auto result = ability->CallObjectMethod(nullptr, nullptr, 0);
    EXPECT_TRUE(result == nullptr);

    auto ref = std::make_shared<NativeReferenceMock>();
    ability->jsObj_ = ref;
    EXPECT_CALL(*ref, GetNapiValue()).WillOnce(testing::Return(nullptr));
    result = ability->CallObjectMethod(nullptr, nullptr, 0);
    EXPECT_TRUE(result == nullptr);

    napi_value rslt = nullptr;
    EXPECT_CALL(*ref, GetNapiValue()).WillOnce(testing::Return(reinterpret_cast<napi_value>(&rslt)));
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _)).WillOnce(testing::Return(napi_ok));
    result = ability->CallObjectMethod(nullptr, nullptr, 0);
    EXPECT_TRUE(result == nullptr);

    EXPECT_CALL(*ref, GetNapiValue()).WillOnce(testing::Return(reinterpret_cast<napi_value>(&rslt)));
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_THIRD>(reinterpret_cast<napi_value>(&rslt)), testing::Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_call_function(_, _, _, _, _, _)).WillOnce(testing::Return(napi_invalid_arg));
    result = ability->CallObjectMethod(nullptr, nullptr, 0);
    EXPECT_TRUE(result == nullptr);

    EXPECT_CALL(*ref, GetNapiValue()).WillOnce(testing::Return(reinterpret_cast<napi_value>(&rslt)));
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_THIRD>(reinterpret_cast<napi_value>(&rslt)), testing::Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_call_function(_, _, _, _, _, _)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_escape_handle(_, _, _, _)).WillOnce(testing::Return(napi_ok));
    result = ability->CallObjectMethod(nullptr, nullptr, 0);
    EXPECT_TRUE(result == nullptr);
}

HWTEST_F(JsCryptoExtAbilityTest, CallJsMethod_0000, testing::ext::TestSize.Level0)
{
    EXPECT_NE(ability, nullptr);
    string funcNameIn;
    NativeReference *jsObj = nullptr;
    InputArgsParser argParser = [](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        return false;
    };
    ResultValueParser retParser = nullptr;
    EXPECT_CALL(*insMoc, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_invalid_arg));
    auto result = ability->CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, EINVAL);

    EXPECT_CALL(*insMoc, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_invalid_arg));
    result = ability->CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, EINVAL);

    EXPECT_CALL(*insMoc, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_ok));
    result = ability->CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, ERR_OK);
}

HWTEST_F(JsCryptoExtAbilityTest, DoCallJsMethod_0000, testing::ext::TestSize.Level0)
{
    EXPECT_NE(ability, nullptr);
    string funcNameIn;
    napi_value rslt = nullptr;
    NativeReference *jsObj = nullptr;
    InputArgsParser argParser = [](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        return false;
    };
    ResultValueParser retParser = nullptr;
    EXPECT_CALL(*insMoc, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_invalid_arg));
    auto result = ability->CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, EINVAL);
    argParser = nullptr;
    EXPECT_CALL(*insMoc, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_CALL(*insMoc, napi_get_reference_value(_, _, _)).WillOnce(Return(napi_ok));
    result = ability->CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, EINVAL);
    EXPECT_CALL(*insMoc, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_CALL(*insMoc, napi_get_reference_value(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _)).WillOnce(Return(napi_ok));
    result = ability->CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, EINVAL);
    EXPECT_CALL(*insMoc, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_CALL(*insMoc, napi_get_reference_value(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_THIRD>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    result = ability->CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, EINVAL);
}

HWTEST_F(JsCryptoExtAbilityTest, DoCallJsMethod_0001, testing::ext::TestSize.Level0)
{
    EXPECT_NE(ability, nullptr);
    string funcNameIn;
    napi_value rslt = nullptr;
    NativeReference *jsObj = nullptr;
    InputArgsParser argParser = nullptr;
    ResultValueParser retParser = [](napi_env&, napi_value) -> bool {
        return false;
    };
    EXPECT_CALL(*insMoc, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_CALL(*insMoc, napi_get_reference_value(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_THIRD>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_call_function(_, _, _, _, _, _)).WillOnce(Return(napi_ok));
    auto result = ability->CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, EINVAL);

    EXPECT_CALL(*insMoc, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_CALL(*insMoc, napi_get_reference_value(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_THIRD>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_call_function(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIFTH>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_escape_handle(_, _, _, _)).WillOnce(Return(napi_ok));
    result = ability->CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, EINVAL);
}

HWTEST_F(JsCryptoExtAbilityTest, OpenRemoteHandleFailed, testing::ext::TestSize.Level0)
{
    EXPECT_NE(ability, nullptr);
    std::string index = "test index";
    std::string pinStr = "123456";
    std::vector<HksParam> paramVec {};
    std::vector<std::uint8_t> u8Vec (pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = {
        .tag = HKS_EXT_CRYPTO_TAG_UKEY_PIN, .blob = {.size = u8Vec.size(), .data = u8Vec.data()} };
    paramVec.emplace_back(tmpParams);
    CppParamSet paramSet(paramVec);
    std::string handle;
    int32_t errcode = -1;
    // 模拟调用CallJsMethod失败
    EXPECT_CALL(*insMoc, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_invalid_arg));
    auto result = ability->OpenRemoteHandle(index, paramSet, handle, errcode);
    EXPECT_EQ(result, EINVAL);
}

}