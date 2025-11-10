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

class CryptoExtAbilityTest : public testing::Test {
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

HWTEST_F(CryptoExtAbilityTest, HksCryptoExtAbilityTest_0000, testing::ext::TestSize.Level0)
{
    CreatorFunc creator;
    HksCryptoExtAbility hksCryptoExtAbility;
    hksCryptoExtAbility.SetCreator(creator);
}

HWTEST_F(CryptoExtAbilityTest, HksCryptoExtAbilityTestAbilityTest_0000, testing::ext::TestSize.Level0)
{
    std::string index;
    CppParamSet params;
    std::string handle;
    std::string certJsonArr;
    int32_t errcode;
    int32_t authState;
    uint32_t retryCnt;
    std::vector<uint8_t> inData;
    std::vector<uint8_t> outData;
    CppParamSet outParams;
    std::string propertyId;
    HksCryptoExtAbility HksAbility;
    EXPECT_EQ(HksAbility.OpenRemoteHandle(index, params, handle, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    EXPECT_EQ(HksAbility.CloseRemoteHandle(handle, params, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    EXPECT_EQ(HksAbility.AuthUkeyPin(handle, params, errcode, authState, retryCnt), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    EXPECT_EQ(HksAbility.GetUkeyPinAuthState(handle, params, authState, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    EXPECT_EQ(HksAbility.ExportCertificate(index, params, certJsonArr, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    EXPECT_EQ(HksAbility.ExportProviderCertificates(params, certJsonArr, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    EXPECT_EQ(HksAbility.InitSession(index, params, handle, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    EXPECT_EQ(HksAbility.UpdateSession(handle, params, inData, outData, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    EXPECT_EQ(HksAbility.FinishSession(handle, params, inData, outData, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    EXPECT_EQ(HksAbility.GetProperty(handle, propertyId, params, outParams, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    EXPECT_EQ(HksAbility.ClearUkeyPinAuthState(handle, params, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
}
}