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
    EXPECT_EQ(hksCryptoExtStubImpl.OpenRemoteHandle(index, params, handle, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.OpenRemoteHandle(index, params, handle, errcode), HKS_ERROR_EXT_NULLPTR);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0001, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    std::string handle;
    CppParamSet params;
    int32_t errcode;
    EXPECT_EQ(hksCryptoExtStubImpl.CloseRemoteHandle(handle, params, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.CloseRemoteHandle(handle, params, errcode), HKS_ERROR_EXT_NULLPTR);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0002, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    std::string index;
    CppParamSet params;
    std::string handle;
    int32_t errcode;
    int32_t authState;
    uint32_t retryCnt;
    EXPECT_EQ(hksCryptoExtStubImpl.AuthUkeyPin(
        handle, params, errcode, authState, retryCnt), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.AuthUkeyPin(
        handle, params, errcode, authState, retryCnt), HKS_ERROR_EXT_NULLPTR);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0003, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    CppParamSet params;
    std::string handle;
    int32_t state;
    int32_t errcode;
    EXPECT_EQ(hksCryptoExtStubImpl.GetUkeyPinAuthState(handle, params, state, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.GetUkeyPinAuthState(handle, params, state, errcode), HKS_ERROR_EXT_NULLPTR);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0004, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    CppParamSet params;
    std::string handle;
    int32_t errcode;
    const std::vector<uint8_t> inData;
    std::vector<uint8_t> outData;
    EXPECT_EQ(hksCryptoExtStubImpl.Sign(handle, params, inData, outData, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.Sign(handle, params, inData, outData, errcode), ERR_OK);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0005, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    CppParamSet params;
    std::string handle;
    int32_t errcode;
    std::vector<uint8_t> plainText;
    std::vector<uint8_t> signature;
    EXPECT_EQ(hksCryptoExtStubImpl.Verify(
        handle, params, plainText, signature, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.Verify(
        handle, params, plainText, signature, errcode), ERR_OK);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0006, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    std::string index;
    CppParamSet params;
    std::string certJsonArr;
    int32_t errcode;
    EXPECT_EQ(hksCryptoExtStubImpl.ExportCertificate(
        index, params, certJsonArr, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.ExportCertificate(index, params, certJsonArr, errcode), HKS_ERROR_EXT_NULLPTR);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0007, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    CppParamSet params;
    std::string certJsonArr;
    int32_t errcode;
    EXPECT_EQ(hksCryptoExtStubImpl.ExportProviderCertificates(
        params, certJsonArr, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.ExportProviderCertificates(
        params, certJsonArr, errcode), HKS_ERROR_EXT_NULLPTR);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0008, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    std::string index;
    CppParamSet params;
    std::string handle;
    int32_t errcode;
    EXPECT_EQ(hksCryptoExtStubImpl.InitSession(index, params, handle, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.InitSession(index, params, handle, errcode), HKS_ERROR_EXT_NULLPTR);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0009, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    CppParamSet params;
    std::string handle;
    int32_t errcode;
    std::vector<uint8_t> inData;
    std::vector<uint8_t> outData;
    EXPECT_EQ(hksCryptoExtStubImpl.UpdateSession(
        handle, params, inData, outData, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.UpdateSession(
        handle, params, inData, outData, errcode), HKS_ERROR_EXT_NULLPTR);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0010, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    CppParamSet params;
    std::string handle;
    std::vector<uint8_t> inData;
    std::vector<uint8_t> outData;
    int32_t errcode;
    EXPECT_EQ(hksCryptoExtStubImpl.FinishSession(
        handle, params, inData, outData, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.FinishSession(
        handle, params, inData, outData, errcode), HKS_ERROR_EXT_NULLPTR);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0011, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    CppParamSet params;
    std::string handle;
    std::string propertyId;
    CppParamSet outParams;
    int32_t errcode;
    EXPECT_EQ(hksCryptoExtStubImpl.GetProperty(
        handle, propertyId, params, outParams, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.GetProperty(
        handle, propertyId, params, outParams, errcode), HKS_ERROR_EXT_NULLPTR);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0012, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    CppParamSet params;
    std::string resourceId;
    int32_t errcode;
    EXPECT_EQ(hksCryptoExtStubImpl.GetResourceId(
        params, resourceId, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.GetResourceId(
        params, resourceId, errcode), ERR_OK);
}

HWTEST_F(CryptoExtAbilityStubTest, HksCryptoExtStubTestAbilityTest_0013, testing::ext::TestSize.Level0)
{
    std::shared_ptr<HksCryptoExtAbility> extension = std::make_shared<HksCryptoExtAbility>();
    HksCryptoExtStubImpl hksCryptoExtStubImpl(extension);
    CppParamSet params;
    std::string handle;
    int32_t errcode;
    EXPECT_EQ(hksCryptoExtStubImpl.ClearUkeyPinAuthState(handle, params, errcode), HKS_ERROR_EXT_UNDEFINED_OPERATION);
    HksCryptoExtStubImpl hksCryptoExtStubImplNullptr(nullptr);
    EXPECT_EQ(hksCryptoExtStubImplNullptr.ClearUkeyPinAuthState(handle, params, errcode), HKS_ERROR_EXT_NULLPTR);
}
}