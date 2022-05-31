/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hks_check_pur1_test.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace Unittest::HksCheckPurposeTest {
class HksCheckPurposeTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCheckPurposeTest::SetUpTestCase(void)
{
}

void HksCheckPurposeTest::TearDownTestCase(void)
{
}

void HksCheckPurposeTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), 0);
}

void HksCheckPurposeTest::TearDown()
{
}

/* 001: gen rsa for encrypt; init for sign */
const TestPurposeCaseParams HKS_PURPOE_TEST_001_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_4096 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_OAEP },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
        },
    .initResult = HKS_ERROR_INVALID_ARGUMENT
};

/* 002: gen hmac for hmac; init for sign */
const TestPurposeCaseParams HKS_PURPOE_TEST_002_PARAMS = {
    .genParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initParams =
        {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_SIGN },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_CURVE25519_KEY_SIZE_256 },
            { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA1 },
            { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
            { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_CBC },
        },
    .initResult = HKS_ERROR_INVALID_ALGORITHM
};

/**
 * @tc.name: HksCheckPurposeTest.HksCheckPurposeTest001
 * @tc.desc: alg-RSA gen-pur-Encrypt init-pur-Sign.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ARGUMENT
 */
HWTEST_F(HksCheckPurposeTest, HksCheckPurposeTest001, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, HKS_PURPOE_TEST_001_PARAMS.genParams.data(),
        HKS_PURPOE_TEST_001_PARAMS.genParams.size());
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    uint8_t alias[] = "testCheckPurpose001";
    struct HksBlob keyAlias = { sizeof(alias), alias };
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *initParamSet = nullptr;
    ret = InitParamSet(&initParamSet, HKS_PURPOE_TEST_001_PARAMS.initParams.data(),
        HKS_PURPOE_TEST_001_PARAMS.initParams.size());
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init) failed.";

    uint64_t handle = 0;
    struct HksBlob handleBlob = { sizeof(handle), (uint8_t *)handle };
    ret = HksInit(&keyAlias, initParamSet, &handleBlob);
    EXPECT_EQ(ret, HKS_PURPOE_TEST_001_PARAMS.initResult) << "Check pur failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&initParamSet);
    (void)HksDeleteKey(&keyAlias, nullptr);
}

/**
 * @tc.name: HksAuthPartTest.HksCheckPurposeTest002
 * @tc.desc: alg-HMAC gen-pur-Mac init-pur-Sign.
 * @tc.type: FUNC
 * @tc.result:HKS_ERROR_INVALID_ALGORITHM
 */
HWTEST_F(HksCheckPurposeTest, HksCheckPurposeTest002, TestSize.Level0)
{
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitParamSet(&genParamSet, HKS_PURPOE_TEST_002_PARAMS.genParams.data(),
        HKS_PURPOE_TEST_002_PARAMS.genParams.size());
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(gen) failed.";

    uint8_t alias[] = "testCheckPurpose002";
    struct HksBlob keyAlias = { sizeof(alias), alias };
    ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksGenerateKey failed.";

    struct HksParamSet *initParamSet = nullptr;
    ret = InitParamSet(&initParamSet, HKS_PURPOE_TEST_002_PARAMS.initParams.data(),
        HKS_PURPOE_TEST_002_PARAMS.initParams.size());
    EXPECT_EQ(ret, HKS_SUCCESS) << "InitParamSet(init) failed.";

    uint64_t handle = 0;
    struct HksBlob handleBlob = { sizeof(handle), (uint8_t *)handle };
    ret = HksInit(&keyAlias, initParamSet, &handleBlob);
    EXPECT_EQ(ret, HKS_PURPOE_TEST_002_PARAMS.initResult) << "Check pur failed.";

    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&initParamSet);
    (void)HksDeleteKey(&keyAlias, nullptr);
}
}
