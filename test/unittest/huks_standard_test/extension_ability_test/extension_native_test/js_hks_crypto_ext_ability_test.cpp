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
#include "../../../../../services/huks_standard/huks_service/extension/ability_native/src/js_hks_crypto_ext_ability.cpp"
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
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_invalid_arg));
    auto result = CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, HKS_ERROR_EXT_SEND_EVENT_FAILED);

    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_ok));
    result = CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, HKS_ERROR_EXT_PARSE_FUNC_FAILED);
}

HWTEST_F(JsCryptoExtAbilityTest, DoCallJsMethod_0000, testing::ext::TestSize.Level0)
{
    EXPECT_NE(ability, nullptr);
    string funcNameIn;
    napi_value rslt = nullptr;
    NativeReference *jsObj = nullptr;
    InputArgsParser argParserFalse = [](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        return false;
    };
    ResultValueParser retParser = nullptr;
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_invalid_arg));
    auto result = CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParserFalse, retParser);
    EXPECT_EQ(result, HKS_ERROR_EXT_SEND_EVENT_FAILED);
    InputArgsParser argParserTrue = [](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        return true;
    };
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_reference_value(_, _, _)).WillOnce(Return(napi_ok));
    result = CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParserTrue, retParser);
    EXPECT_EQ(result, HKS_ERROR_EXT_GET_VALUE_FAILED);

    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_reference_value(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _)).WillOnce(Return(napi_ok));
    result = CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParserTrue, retParser);
    EXPECT_EQ(result, HKS_ERROR_EXT_GET_NAME_PROPERTY_FAILED);

    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_reference_value(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_THIRD>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    result = CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParserTrue, retParser);
    EXPECT_EQ(result, HKS_ERROR_EXT_PARSE_FUNC_FAILED);
}

HWTEST_F(JsCryptoExtAbilityTest, DoCallJsMethod_0001, testing::ext::TestSize.Level0)
{
    EXPECT_NE(ability, nullptr);
    string funcNameIn;
    napi_value rslt = nullptr;
    NativeReference *jsObj = nullptr;
    InputArgsParser argParser = [](napi_env &env, napi_value *argv, size_t &argc) -> bool {
        return true;
    };
    ResultValueParser retParser = [](napi_env&, napi_value) -> bool {
        return true;
    };
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_reference_value(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_THIRD>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_call_function(_, _, _, _, _, _)).WillOnce(Return(napi_ok));
    auto result = CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, HKS_ERROR_EXT_CALL_FUNCTION_FAILED);

    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_reference_value(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_THIRD>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_call_function(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIFTH>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_escape_handle(_, _, _, _)).WillOnce(Return(napi_ok));
    result = CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParser);
    EXPECT_EQ(result, HKS_SUCCESS);

    ResultValueParser retParserFalse = [](napi_env&, napi_value) -> bool {
        return false;
    };
    EXPECT_CALL(*insMoc, napi_send_event(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_reference_value(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_THIRD>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_call_function(_, _, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIFTH>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_escape_handle(_, _, _, _)).WillOnce(Return(napi_ok));
    result = CallJsMethod(funcNameIn, *jsRuntime, jsObj, argParser, retParserFalse);
    EXPECT_EQ(result, HKS_ERROR_EXT_PARSE_FUNC_FAILED);
}
}