/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "hks_ukey_test.h"

#include "file_ex.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_adapt_for_de.h"
#include "hks_test_api_performance.h"
#include "hks_test_common.h"
#include "hks_test_log.h"

using namespace testing::ext;
namespace {
class HksUKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    // 工具函数：构造 HksBlob
    static int32_t ConstructTestBlob(struct HksBlob **name, const HksTestGenKeyParams &params)
    {
        return TestConstuctBlob(name,
            params.keyAliasParams.blobExist,
            params.keyAliasParams.blobSize,
            params.keyAliasParams.blobDataExist,
            params.keyAliasParams.blobDataSize);
    }

    // 工具函数：构造 HksParamSet
    static int32_t ConstructTestParamSet(struct HksParamSet **paramSet, const HksTestGenKeyParams &params)
    {
        struct GenerateKeyParamSetStructure paramStruct = { paramSet,
            params.paramSetParams.paramSetExist,
            params.paramSetParams.setAlg, params.paramSetParams.alg,
            params.paramSetParams.setKeySize, params.paramSetParams.keySize,
            params.paramSetParams.setPurpose, params.paramSetParams.purpose,
            params.paramSetParams.setDigest, params.paramSetParams.digest,
            params.paramSetParams.setPadding, params.paramSetParams.padding,
            params.paramSetParams.setBlockMode, params.paramSetParams.mode,
            params.paramSetParams.setKeyStorageFlag, params.paramSetParams.keyStorageFlag };
        return TestConstructGenerateKeyParamSet(&paramStruct);
    }
};

void HksUKeyTest::SetUpTestCase(void)
{
}

void HksUKeyTest::TearDownTestCase(void)
{
}

void HksUKeyTest::SetUp()
{
}

void HksUKeyTest::TearDown()
{
}

const int DEFAULT_X25519_PARAM_SET_OUT = 120;

static const struct HksTestGenKeyParams g_testGenKeyParams[] = {
    /* x25519: ree sign/verify */
    { 0, HKS_SUCCESS, { true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE }, {
        true,
        true, HKS_ALG_X25519,
        true, HKS_CURVE25519_KEY_SIZE_256,
        true, HKS_KEY_PURPOSE_SIGN | HKS_KEY_PURPOSE_VERIFY,
        false, 0,
        false, 0,
        false, 0,
        true, HKS_STORAGE_TEMP },
        { true, DEFAULT_X25519_PARAM_SET_OUT },
    },
};

/**
 * @tc.name: HksUKeyTest.HksRegisterProviderTest
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksUKeyTest, HksRegisterProviderTest, TestSize.Level0)
{
    uint32_t times = 1;
    uint32_t index = 0;
    const HksTestGenKeyParams &testParams = g_testGenKeyParams[index];
    struct HksBlob *name = NULL;
    int32_t ret = ConstructTestBlob(&name, testParams);
    EXPECT_TRUE(ret == 0);

    struct HksParamSet *paramSet = NULL;
    ret = ConstructTestParamSet(&paramSet, testParams);
    EXPECT_TRUE(ret == 0);

    ret = HksRegisterProvider(name, paramSet);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, ret[%u] = %d", testParams.testId, ret);
    }
    EXPECT_TRUE(ret == 0);

    TestFreeBlob(&name);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("[%u]TestRegisterProvider, Testcase_RegisterProvider_[%03u] pass!", times, testParams.testId);
    ASSERT_TRUE(ret == 0);
}

HWTEST_F(HksUKeyTest, HksRegisterProviderWithoutNameTest, TestSize.Level0)
{
    uint32_t times = 1;
    uint32_t index = 0;
    const HksTestGenKeyParams &testParams = g_testGenKeyParams[index];
    struct HksBlob *name = NULL;
    struct HksParamSet *paramSet = NULL;
    int ret = ConstructTestParamSet(&paramSet, testParams);
    EXPECT_TRUE(ret == 0);

    ret = HksRegisterProvider(name, paramSet);
    if (ret != HKS_ERROR_NULL_POINTER) {
        HKS_TEST_LOG_I("failed, ret[%u] = %d", testParams.testId, ret);
    }
    EXPECT_TRUE(ret == HKS_ERROR_NULL_POINTER);

    TestFreeBlob(&name);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("[%u]TestRegisterProvider, Testcase_RegisterProvider_[%03u] pass!", times, testParams.testId);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}


HWTEST_F(HksUKeyTest, HksUnregisterProvider, TestSize.Level0)
{
    uint32_t times = 1;
    uint32_t index = 0;
    const HksTestGenKeyParams &testParams = g_testGenKeyParams[index];
    struct HksBlob *name = NULL;
    int32_t ret = ConstructTestBlob(&name, testParams);
    EXPECT_TRUE(ret == 0);

    struct HksParamSet *paramSet = NULL;
    ret = ConstructTestParamSet(&paramSet, testParams);
    EXPECT_TRUE(ret == 0);

    ret = HksUnregisterProvider(name, paramSet);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, ret[%u] = %d", testParams.testId, ret);
    }
    EXPECT_TRUE(ret == 0);

    TestFreeBlob(&name);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("[%u]TestRegisterProvider, Testcase_RegisterProvider_[%03u] pass!", times, testParams.testId);
    ASSERT_TRUE(ret == 0);
}

HWTEST_F(HksUKeyTest, HksUnregisterProviderWithoutNameTest, TestSize.Level0)
{
    uint32_t times = 1;
    uint32_t index = 0;
    const HksTestGenKeyParams &testParams = g_testGenKeyParams[index];
    struct HksBlob *name = NULL;
    struct HksParamSet *paramSet = NULL;
    int ret = ConstructTestParamSet(&paramSet, testParams);
    EXPECT_TRUE(ret == 0);

    ret = HksUnregisterProvider(name, paramSet);
    if (ret != HKS_ERROR_NULL_POINTER) {
        HKS_TEST_LOG_I("failed, ret[%u] = %d", testParams.testId, ret);
    }
    EXPECT_TRUE(ret == HKS_ERROR_NULL_POINTER);

    TestFreeBlob(&name);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("[%u]TestRegisterProvider, Testcase_RegisterProvider_[%03u] pass!", times, testParams.testId);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}

HWTEST_F(HksUKeyTest, HksAuthUkeyPin, TestSize.Level0)
{
    uint32_t times = 1;
    uint32_t index = 0;
    const HksTestGenKeyParams &testParams = g_testGenKeyParams[index];
    struct HksBlob *resourceId = NULL;
    int32_t ret = ConstructTestBlob(&resourceId, testParams);
    EXPECT_TRUE(ret == 0);

    struct HksParamSet *paramSet = NULL;
    ret = ConstructTestParamSet(&paramSet, testParams);
    EXPECT_TRUE(ret == 0);

    uint32_t retryCount = 0;

    ret = HksAuthUkeyPin(resourceId, paramSet, &retryCount);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, ret[%u] = %d", testParams.testId, ret);
    }
    EXPECT_TRUE(ret == 0);

    TestFreeBlob(&resourceId);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("[%u]TestRegisterProvider, Testcase_RegisterProvider_[%03u] pass!", times, testParams.testId);
    ASSERT_TRUE(ret == 0);
}

HWTEST_F(HksUKeyTest, HksGetUkeyPinAuthState, TestSize.Level0)
{
    uint32_t times = 1;
    uint32_t index = 0;
    const HksTestGenKeyParams &testParams = g_testGenKeyParams[index];
    struct HksBlob *resourceId = NULL;
    int32_t ret = ConstructTestBlob(&resourceId, testParams);
    EXPECT_TRUE(ret == 0);

    struct HksParamSet *paramSet = NULL;
    ret = ConstructTestParamSet(&paramSet, testParams);
    EXPECT_TRUE(ret == 0);
    
    int32_t status = 0;

    ret = HksGetUkeyPinAuthState(resourceId, paramSet, &status);
    if (ret != 0) {
        HKS_TEST_LOG_I("failed, ret[%u] = %d", testParams.testId, ret);
    }
    EXPECT_TRUE(ret == 0);

    TestFreeBlob(&resourceId);
    HksFreeParamSet(&paramSet);
    HKS_TEST_LOG_I("[%u]TestRegisterProvider, Testcase_RegisterProvider_[%03u] pass!", times, testParams.testId);
    ASSERT_TRUE(ret == 0);
}

HWTEST_F(HksUKeyTest, HksOpenRemoteHandle, TestSize.Level0)
{

}

HWTEST_F(HksUKeyTest, HksGetRemoteHandle, TestSize.Level0)
{

}

HWTEST_F(HksUKeyTest, HksGetPinAuthState, TestSize.Level0)
{

}

HWTEST_F(HksUKeyTest, HksClearPinAuthState, TestSize.Level0)
{

}

HWTEST_F(HksUKeyTest, HksUkeySign, TestSize.Level0)
{

}

}