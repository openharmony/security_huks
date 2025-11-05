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
#include "../../../../../services/huks_standard/huks_service/extension/ability_native/src/hks_crypto_ext_ability.cpp"
#include "../../../../../security/huks/services/huks_standard/huks_service/extension/ability_native/src/hks_crypto_ext_stub_impl.cpp"
namespace OHOS::Security::Huks {
using namespace testing;
using namespace testing::ext;
const int ARG_INDEX_FIRST = 1;
const int ARG_INDEX_SECOND = 2;
const int ARG_INDEX_THIRD = 3;
const int ARG_INDEX_FOUR = 4;
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

HWTEST_F(JsCryptoExtAbilityTest, BlobToBase64String_0000, testing::ext::TestSize.Level0)
{
    HksBlob blob;
    string outStr = "";
    uint8_t arr[10] = { 1, 2, 3, 4, 5};
    EXPECT_EQ(BlobToBase64String(blob, outStr), HKS_ERROR_EXT_BASE64_FAILED);
    blob.size = 5;
    blob.data = nullptr;
    EXPECT_EQ(BlobToBase64String(blob, outStr), HKS_ERROR_EXT_BASE64_FAILED);
    blob.data = arr;
    EXPECT_EQ(BlobToBase64String(blob, outStr), HKS_SUCCESS);
}

HWTEST_F(JsCryptoExtAbilityTest, GenerateArrayBuffer_0000, testing::ext::TestSize.Level0)
{
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = { .tag = HKS_EXT_CRYPTO_TAG_UKEY_PIN,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    EXPECT_CALL(*insMoc, napi_create_arraybuffer(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    auto result = GenerateArrayBuffer(env, tmpParams.blob.data, tmpParams.blob.size);
    EXPECT_TRUE(result == nullptr);

    EXPECT_CALL(*insMoc, napi_create_arraybuffer(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_typedarray(_, _, _, _, _, _)).WillOnce(Return(napi_invalid_arg));
    result = GenerateArrayBuffer(env, tmpParams.blob.data, tmpParams.blob.size);
    EXPECT_TRUE(result == nullptr);
}

HWTEST_F(JsCryptoExtAbilityTest, GenerateHksParamValue_0000, testing::ext::TestSize.Level0)
{
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    napi_value value = nullptr;
    struct HksParam tmpParams = { .tag = HKS_EXT_CRYPTO_TAG_UKEY_PIN,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    EXPECT_CALL(*insMoc, napi_create_arraybuffer(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GenerateHksParamValue(env, tmpParams, value), HKS_ERROR_EXT_CREATE_VALUE_FAILED);
    tmpParams = { .tag = HKS_TAG_TYPE_INT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _)).WillOnce(Return(napi_invalid_arg));  
    EXPECT_EQ(GenerateHksParamValue(env, tmpParams, value), HKS_ERROR_EXT_CREATE_VALUE_FAILED);

    tmpParams = { .tag = HKS_TAG_TYPE_UINT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_invalid_arg));  
    EXPECT_EQ(GenerateHksParamValue(env, tmpParams, value), HKS_ERROR_EXT_CREATE_VALUE_FAILED);

    tmpParams = { .tag = HKS_TAG_TYPE_ULONG,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    EXPECT_CALL(*insMoc, napi_create_bigint_uint64(_, _, _)).WillOnce(Return(napi_invalid_arg));  
    EXPECT_EQ(GenerateHksParamValue(env, tmpParams, value), HKS_ERROR_EXT_CREATE_VALUE_FAILED);

    tmpParams = { .tag = HKS_TAG_TYPE_BOOL,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    EXPECT_CALL(*insMoc, napi_get_boolean(_, _, _)).WillOnce(Return(napi_invalid_arg));  
    EXPECT_EQ(GenerateHksParamValue(env, tmpParams, value), HKS_ERROR_EXT_CREATE_VALUE_FAILED);

    tmpParams = { .tag = HKS_TAG_TYPE_INVALID,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    EXPECT_EQ(GenerateHksParamValue(env, tmpParams, value), HKS_ERROR_EXT_TAG_UNDEFINED);

    napi_value rslt = nullptr;
    tmpParams = { .tag = HKS_TAG_TYPE_INT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_EQ(GenerateHksParamValue(env, tmpParams, value), HKS_SUCCESS);
}

HWTEST_F(JsCryptoExtAbilityTest, GenerateHksParam_0000, testing::ext::TestSize.Level0)
{
    napi_value outValue;
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = { .tag = HKS_EXT_CRYPTO_TAG_UKEY_PIN,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GenerateHksParam(env, tmpParams, outValue), HKS_ERROR_EXT_CREATE_VALUE_FAILED);

    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GenerateHksParam(env, tmpParams, outValue), HKS_ERROR_EXT_CREATE_VALUE_FAILED);

    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GenerateHksParam(env, tmpParams, outValue), HKS_ERROR_EXT_SET_NAME_PROPERTY_FAILED);
}

HWTEST_F(JsCryptoExtAbilityTest, GenerateHksParam_0001, testing::ext::TestSize.Level0)
{   
    napi_value outValue;
    std::string pinStr = "123456";
    napi_value rslt = nullptr;
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = { .tag = HKS_TAG_TYPE_INT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _)).WillOnce(Return(napi_ok));

    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GenerateHksParam(env, tmpParams, outValue), HKS_ERROR_EXT_CREATE_VALUE_FAILED);

    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_invalid_arg));
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_EQ(GenerateHksParam(env, tmpParams, outValue), HKS_ERROR_EXT_SET_NAME_PROPERTY_FAILED);

    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_EQ(GenerateHksParam(env, tmpParams, outValue), HKS_SUCCESS);
}

HWTEST_F(JsCryptoExtAbilityTest, GenerateHksParamArray_0000, testing::ext::TestSize.Level0)
{    
    napi_value rslt = nullptr;
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = { .tag = HKS_TAG_TYPE_INT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    std::vector<HksParam> paramsVec;
    paramsVec.emplace_back(tmpParams);
    CppParamSet paramSet(paramsVec);
    
    EXPECT_CALL(*insMoc, napi_create_array(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_TRUE(GenerateHksParamArray(env, *paramSet.GetParamSet()) == nullptr);

    EXPECT_CALL(*insMoc, napi_create_array(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_TRUE(GenerateHksParamArray(env, *paramSet.GetParamSet()) == nullptr);

    EXPECT_CALL(*insMoc, napi_create_array(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_set_element(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_TRUE(GenerateHksParamArray(env, *paramSet.GetParamSet()) == nullptr);

    EXPECT_CALL(*insMoc, napi_create_array(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_set_element(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_TRUE(GenerateHksParamArray(env, *paramSet.GetParamSet()) == nullptr);
}

HWTEST_F(JsCryptoExtAbilityTest, MakeJsNativeCppParamSet_0000, testing::ext::TestSize.Level0)
{
    napi_value outValue = nullptr;
    napi_value rslt = 0;
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = { .tag = HKS_TAG_TYPE_INT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    std::vector<HksParam> paramsVec;
    paramsVec.emplace_back(tmpParams);
    CppParamSet paramSet(paramsVec);

    EXPECT_CALL(*insMoc, napi_create_array(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(MakeJsNativeCppParamSet(env, paramSet, outValue));

    EXPECT_CALL(*insMoc, napi_create_array(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok)).WillOnce(Return(napi_invalid_arg));
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_set_element(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_FALSE(MakeJsNativeCppParamSet(env, paramSet, outValue));

    EXPECT_CALL(*insMoc, napi_create_array(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_set_element(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_TRUE(MakeJsNativeCppParamSet(env, paramSet, outValue));
}

HWTEST_F(JsCryptoExtAbilityTest, MakeJsNativeVectorInData_0000, testing::ext::TestSize.Level0)
{
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    napi_value value;
    EXPECT_CALL(*insMoc, napi_create_arraybuffer(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    auto result = MakeJsNativeVectorInData(env, u8Vec, value);
    EXPECT_FALSE(result);

    EXPECT_CALL(*insMoc, napi_create_arraybuffer(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_typedarray(_, _, _, _, _, _)).WillOnce(Return(napi_invalid_arg));
    result = MakeJsNativeVectorInData(env, u8Vec, value);
    EXPECT_FALSE(result);
}

HWTEST_F(JsCryptoExtAbilityTest, BuildHandleInfoParam_0000, testing::ext::TestSize.Level0)
{
    napi_value rslt = 0;
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = { .tag = HKS_TAG_TYPE_INT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    std::vector<HksParam> paramsVec;
    paramsVec.emplace_back(tmpParams);
    CppParamSet paramSet(paramsVec);
    HandleInfoParam param = { "test", paramSet };
    napi_value argv = 0;
    size_t argc;
    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildHandleInfoParam(env, param, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildHandleInfoParam(env, param, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_create_array(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildHandleInfoParam(env, param, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_TRUE(BuildHandleInfoParam(env, {}, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)))
        .WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_array(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_set_element(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_TRUE(BuildHandleInfoParam(env, param, &argv, argc));
}

HWTEST_F(JsCryptoExtAbilityTest, BuildIndexInfoParam_0000, testing::ext::TestSize.Level0)
{
    napi_value rslt = 0;
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = { .tag = HKS_TAG_TYPE_INT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    std::vector<HksParam> paramsVec;
    paramsVec.emplace_back(tmpParams);
    CppParamSet paramSet(paramsVec);
    IndexInfoParam param = { "test", paramSet };
    napi_value argv = 0;
    size_t argc;
    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildIndexInfoParam(env, param, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildIndexInfoParam(env, param, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_create_array(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildIndexInfoParam(env, param, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_TRUE(BuildIndexInfoParam(env, {}, &argv, argc));
    
    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)))
        .WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_array(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_set_element(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_TRUE(BuildIndexInfoParam(env, param, &argv, argc));
}

HWTEST_F(JsCryptoExtAbilityTest, BuildIndexInfoParamWithHuksOption_0000, testing::ext::TestSize.Level0)
{
    napi_value rslt = 0;
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = { .tag = HKS_TAG_TYPE_INT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    std::vector<HksParam> paramsVec;
    paramsVec.emplace_back(tmpParams);
    CppParamSet paramSet(paramsVec);
    IndexInfoParam param = { "test", paramSet };
    napi_value argv = 0;
    size_t argc;
    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildIndexInfoParamWithHuksOption(env, param, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildIndexInfoParamWithHuksOption(env, param, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_create_array(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildIndexInfoParamWithHuksOption(env, param, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_TRUE(BuildIndexInfoParamWithHuksOption(env, {}, &argv, argc));
    
    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)))
        .WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_array(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_set_element(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_TRUE(BuildIndexInfoParamWithHuksOption(env, param, &argv, argc));
}

HWTEST_F(JsCryptoExtAbilityTest, BuildHandleWithInData_0000, testing::ext::TestSize.Level0)
{
    napi_value rslt = 0;
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = { .tag = HKS_TAG_TYPE_INT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    std::vector<HksParam> paramsVec;
    paramsVec.emplace_back(tmpParams);
    CppParamSet paramSet(paramsVec);
    HandleInfoParam param = { "test", paramSet };
    napi_value argv = 0;
    size_t argc;
    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildHandleWithInData(env, param, u8Vec, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildHandleWithInData(env, param, u8Vec, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_create_array(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildHandleWithInData(env, param, u8Vec, &argv, argc));
}

HWTEST_F(JsCryptoExtAbilityTest, BuildHandleWithInData_0001, testing::ext::TestSize.Level0)
{
    napi_value rslt = 0;
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = { .tag = HKS_TAG_TYPE_INT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    std::vector<HksParam> paramsVec;
    paramsVec.emplace_back(tmpParams);
    CppParamSet paramSet(paramsVec);
    HandleInfoParam param = { "test", paramSet };
    napi_value argv = 0;
    size_t argc;
    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_arraybuffer(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildHandleWithInData(env, {}, u8Vec, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)))
        .WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_array(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_set_element(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_arraybuffer(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildHandleWithInData(env, param, u8Vec, &argv, argc));
}

HWTEST_F(JsCryptoExtAbilityTest, BuildPropertyData_0000, testing::ext::TestSize.Level0)
{
    std::string propertyId = "test";
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = { .tag = HKS_TAG_TYPE_INT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    std::vector<HksParam> paramsVec;
    paramsVec.emplace_back(tmpParams);
    CppParamSet paramSet(paramsVec);
    HandleInfoParam param = { "test", paramSet };
    napi_value argv = 0;
    size_t argc;
    
    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildPropertyData(env, propertyId, param, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildPropertyData(env, propertyId, param, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_FALSE(BuildPropertyData(env, propertyId, param, &argv, argc));
    
    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_TRUE(BuildPropertyData(env, propertyId, {}, &argv, argc));
}

HWTEST_F(JsCryptoExtAbilityTest, BuildPropertyData_0001, testing::ext::TestSize.Level0)
{
    std::string propertyId = "test";
    std::string pinStr = "123456";
    std::vector<std::uint8_t> u8Vec(pinStr.begin(), pinStr.end());
    u8Vec.push_back('\0');
    struct HksParam tmpParams = { .tag = HKS_TAG_TYPE_INT,
        .blob = { .size = u8Vec.size(), .data = u8Vec.data() }};
    std::vector<HksParam> paramsVec;
    paramsVec.emplace_back(tmpParams);
    CppParamSet paramSet(paramsVec);
    HandleInfoParam param = { "test", paramSet };
    napi_value rslt = 0;
    napi_value argv = 0;
    size_t argc;
    
    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)))
        .WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_array(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_set_element(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_TRUE(BuildPropertyData(env, propertyId, param, &argv, argc));

    EXPECT_CALL(*insMoc, napi_create_string_utf8(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_object(_, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)))
        .WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_array(_, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_uint32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_set_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_create_int32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(reinterpret_cast<napi_value>(&rslt)), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_set_element(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_FALSE(BuildPropertyData(env, propertyId, param, &argv, argc));
}

HWTEST_F(JsCryptoExtAbilityTest, GetStringValue_0000, testing::ext::TestSize.Level0)
{
    napi_value value = nullptr;
    std::string result = "";

    EXPECT_CALL(*insMoc, napi_get_value_string_utf8(_, _, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GetStringValue(env, value, result), HKS_ERROR_EXT_GET_VALUE_FAILED);

    EXPECT_CALL(*insMoc, napi_get_value_string_utf8(_, _, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GetStringValue(env, value, result), HKS_ERROR_EXT_GET_VALUE_FAILED);

    EXPECT_CALL(*insMoc, napi_get_value_string_utf8(_, _, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_EQ(GetStringValue(env, value, result), HKS_SUCCESS);

    for (auto i = 0; i < MAX_CERT_SIZE * 2; ++i) {
        result += "0";
    }
    EXPECT_CALL(*insMoc, napi_get_value_string_utf8(_, _, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_FOUR>(MAX_CERT_SIZE * 2), Return(napi_ok)));
    EXPECT_EQ(GetStringValue(env, value, result), HKS_ERROR_EXT_EXCEED_MAX_SIZE);
}

HWTEST_F(JsCryptoExtAbilityTest, GetUint8ArrayValue_0000, testing::ext::TestSize.Level0)
{
    napi_value value = nullptr;
    HksBlob result;

    EXPECT_CALL(*insMoc, napi_get_typedarray_info(_, _, _, _, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GetUint8ArrayValue(env, value, result), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_typedarray_info(_, _, _, _, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_arraybuffer_info(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GetUint8ArrayValue(env, value, result), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_typedarray_info(_, _, _, _, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_arraybuffer_info(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_EQ(GetUint8ArrayValue(env, value, result), napi_ok);
}

HWTEST_F(JsCryptoExtAbilityTest, GetHksCertInfoValue_0000, testing::ext::TestSize.Level0)
{
    HksCertInfo certInfo;
    napi_value value = nullptr;
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GetHksCertInfoValue(env, value, certInfo), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_int32(_, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GetHksCertInfoValue(env, value, certInfo), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_invalid_arg));
    EXPECT_CALL(*insMoc, napi_get_value_int32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_EQ(GetHksCertInfoValue(env, value, certInfo), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_int32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_string_utf8(_, _, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GetHksCertInfoValue(env, value, certInfo), HKS_ERROR_EXT_GET_VALUE_FAILED);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok)).WillOnce(Return(napi_invalid_arg));
    EXPECT_CALL(*insMoc, napi_get_value_int32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_string_utf8(_, _, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_EQ(GetHksCertInfoValue(env, value, certInfo), napi_invalid_arg);
}

HWTEST_F(JsCryptoExtAbilityTest, GetHksCertInfoValue_0001, testing::ext::TestSize.Level0)
{
    HksCertInfo certInfo;
    napi_value value = nullptr;
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_int32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_string_utf8(_, _, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_typedarray_info(_, _, _, _, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GetHksCertInfoValue(env, value, certInfo), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_int32(_, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_string_utf8(_, _, _, _, _))
        .WillOnce(Return(napi_ok)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_typedarray_info(_, _, _, _, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_arraybuffer_info(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_EQ(GetHksCertInfoValue(env, value, certInfo), napi_ok);
}

HWTEST_F(JsCryptoExtAbilityTest, GetHksParamsfromValue_0000, testing::ext::TestSize.Level0)
{
    HksParam param;
    napi_value value = nullptr;
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _)).WillOnce(testing::Return(napi_invalid_arg));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _)).WillOnce(testing::Return(napi_invalid_arg));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_invalid_arg);
    
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_invalid_arg));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _)).WillOnce(testing::Return(napi_ok));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(HKS_TAG_TYPE_INVALID), Return(napi_ok)));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_ok);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(HKS_TAG_TYPE_INT), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_value_int32(_, _, _)).WillOnce(testing::Return(napi_invalid_arg));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(HKS_TAG_TYPE_INT), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_value_int32(_, _, _)).WillOnce(testing::Return(napi_ok));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_ok);
}

HWTEST_F(JsCryptoExtAbilityTest, GetHksParamsfromValue_0001, testing::ext::TestSize.Level0)
{
    HksParam param;
    napi_value value = nullptr;
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(HKS_TAG_TYPE_UINT), Return(napi_ok)))
        .WillOnce(testing::Return(napi_invalid_arg));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(HKS_TAG_TYPE_UINT), Return(napi_ok)))
        .WillOnce(testing::Return(napi_ok));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_ok);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(HKS_TAG_TYPE_ULONG), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_value_bigint_uint64(_, _, _, _)).WillOnce(testing::Return(napi_ok));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_ok);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(HKS_TAG_TYPE_ULONG), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_value_bigint_uint64(_, _, _, _)).WillOnce(testing::Return(napi_invalid_arg));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(HKS_TAG_TYPE_ULONG), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_value_bigint_uint64(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_THIRD>(true), Return(napi_ok)));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_ok);
}

HWTEST_F(JsCryptoExtAbilityTest, GetHksParamsfromValue_0002, testing::ext::TestSize.Level0)
{
    HksParam param;
    napi_value value = nullptr;
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(HKS_TAG_TYPE_BOOL), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_value_bool(_, _, _)).WillOnce(testing::Return(napi_invalid_arg));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(HKS_TAG_TYPE_BOOL), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_value_bool(_, _, _)).WillOnce(testing::Return(napi_ok));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_ok);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(HKS_TAG_TYPE_BYTES), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_typedarray_info(_, _, _, _, _, _, _)).WillOnce(Return(napi_invalid_arg));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_invalid_arg);

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _))
        .WillOnce(testing::Return(napi_ok)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_uint32(_, _, _))
        .WillOnce(DoAll(SetArgPointee<ARG_INDEX_SECOND>(HKS_TAG_TYPE_BYTES), Return(napi_ok)));
    EXPECT_CALL(*insMoc, napi_get_typedarray_info(_, _, _, _, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_arraybuffer_info(_, _, _, _)).WillOnce(Return(napi_ok));
    EXPECT_EQ(GetHksParamsfromValue(env, value, param), napi_ok);
}

HWTEST_F(JsCryptoExtAbilityTest, GetOpenRemoteHandleParams_0000, testing::ext::TestSize.Level0)
{
    CryptoResultParam resultParams;
    napi_value value = nullptr;
    GetOpenRemoteHandleParams(env, value, resultParams);
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _)).WillOnce(testing::Return(napi_invalid_arg));
    EXPECT_EQ(resultParams.handle, "");

    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_string_utf8(_, _, _, _, _))
        .WillOnce(testing::Return(napi_invalid_arg));
    EXPECT_EQ(resultParams.handle, "");

    char expected_buffer[] = "test_string";
    EXPECT_CALL(*insMoc, napi_get_named_property(_, _, _, _)).WillOnce(testing::Return(napi_ok));
    EXPECT_CALL(*insMoc, napi_get_value_string_utf8(_, _, _, _, _))
        .WillOnce(testing::Return(napi_ok))
        .WillOnce(DoAll(testing::SetArrayArgument<2>(
            expected_buffer, expected_buffer + strlen(expected_buffer) + 1), Return(napi_ok)));
    EXPECT_EQ(resultParams.handle, "test_string");
}
}