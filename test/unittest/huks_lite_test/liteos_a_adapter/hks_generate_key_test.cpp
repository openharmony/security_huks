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
#include <map>

#include "hks_generate_key_test.h"

#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_adapt_for_de.h"
#include "hks_test_api_performance.h"
#include "hks_test_common.h"
#include "hks_test_log.h"

using namespace testing::ext;
namespace {
#ifndef _CUT_AUTHENTICATE_
class HksGenerateKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksGenerateKeyTest::SetUpTestCase(void)
{
}

void HksGenerateKeyTest::TearDownTestCase(void)
{
}

void HksGenerateKeyTest::SetUp()
{
    EXPECT_EQ(HksInitialize(), HKS_SUCCESS);
}

void HksGenerateKeyTest::TearDown()
{
}

const int DEFAULT_X25519_PARAM_SET_OUT = 104;

const struct HksTestGenKeyParams g_testGenKeyParams[] = {
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
        { true,
          DEFAULT_X25519_PARAM_SET_OUT },
    },
};

struct HksTestGenKeyParams g_testHmacGenKeyParams = {
    /* hmac */
    0,
    HKS_SUCCESS,
    {
        true, DEFAULT_KEY_ALIAS_SIZE, true, DEFAULT_KEY_ALIAS_SIZE
    },
    {
        true,
        true, HKS_ALG_HMAC,
        true, 0,
        true, HKS_KEY_PURPOSE_MAC,
        false, 0,
        false, 0,
        false, 0,
        true, HKS_STORAGE_TEMP
    },
    {
        true, 1024
    },
};

void TestGenerateKey(const struct HksTestGenKeyParams &params)
{
    uint32_t performTimes = 1;
    uint32_t times = 1;
    struct HksBlob *keyAlias = nullptr;
    int32_t ret = TestConstuctBlob(&keyAlias,
        params.keyAliasParams.blobExist, params.keyAliasParams.blobSize,
        params.keyAliasParams.blobDataExist, params.keyAliasParams.blobDataSize);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *paramSet = nullptr;
    struct GenerateKeyParamSetStructure paramStruct = {
        &paramSet,
        params.paramSetParams.paramSetExist,
        params.paramSetParams.setAlg, params.paramSetParams.alg,
        params.paramSetParams.setKeySize, params.paramSetParams.keySize,
        params.paramSetParams.setPurpose, params.paramSetParams.purpose,
        params.paramSetParams.setDigest, params.paramSetParams.digest,
        params.paramSetParams.setPadding, params.paramSetParams.padding,
        params.paramSetParams.setBlockMode,
        params.paramSetParams.mode,
        params.paramSetParams.setKeyStorageFlag,
        params.paramSetParams.keyStorageFlag
    };
    ret = TestConstructGenerateKeyParamSet(&paramStruct);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksParamSet *paramSetOut = nullptr;
    ret = TestConstructGenerateKeyParamSetOut(&paramSetOut,
        params.paramSetParamsOut.paramSetExist,
        params.paramSetParamsOut.paramSetSize);
    EXPECT_EQ(ret, HKS_SUCCESS);

    ret = HksGenerateKeyRun(keyAlias, paramSet, paramSetOut, performTimes);
    if (ret != params.expectResult) {
        HKS_TEST_LOG_I("failed, ret[%u] = %d", params.testId, ret);
    }
    EXPECT_EQ(ret, params.expectResult);

    if ((ret == HKS_SUCCESS) && !(params.paramSetParams.setKeyStorageFlag) &&
        (params.paramSetParams.keyStorageFlag == HKS_STORAGE_TEMP)) {
        EXPECT_EQ(HksDeleteKeyForDe(keyAlias, nullptr), HKS_SUCCESS);
    }
    TestFreeBlob(&keyAlias);
    HksFreeParamSet(&paramSet);
    HksFreeParamSet(&paramSetOut);
    HKS_TEST_LOG_I("[%u]TestGenerateKey, Testcase_GenerateKey_[%03u] pass!", times, params.testId);
    ASSERT_EQ(ret, params.expectResult);
}

/**
 * @tc.name: HksGenerateKeyTest.HksGenerateKeyTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksGenerateKeyTest, HksGenerateKeyTest001, TestSize.Level0)
{
    TestGenerateKey(g_testGenKeyParams[0]);
}

/**
 * @tc.name: HksGenerateKeyTest.HksGenerateKeyTest002
 * @tc.desc: test generate key --- HKS_ALG_HMAC;
 * @tc.type: FUNC
 */
HWTEST_F(HksGenerateKeyTest, HksGenerateKeyTest002, TestSize.Level0)
{
    std::map<uint32_t, int32_t> testKeyLen = {
        {0, HKS_ERROR_INVALID_ARGUMENT},
        {1, HKS_ERROR_INVALID_ARGUMENT},
        {8, HKS_SUCCESS},
        {9, HKS_ERROR_INVALID_ARGUMENT},
        {10, HKS_ERROR_INVALID_ARGUMENT},
        {16, HKS_SUCCESS},
        {24, HKS_SUCCESS},
        {1008, HKS_SUCCESS},
        {1024, HKS_SUCCESS},
        {1040, HKS_SUCCESS},
    };

    for (auto &[keyLen, ret] : testKeyLen) {
        HKS_TEST_LOG_I("test generate %u length hamc key", keyLen);
        g_testHmacGenKeyParams.expectResult = ret;
        g_testHmacGenKeyParams.paramSetParams.keySize = keyLen;
        TestGenerateKey(g_testHmacGenKeyParams);
    }
}

#endif /* _CUT_AUTHENTICATE_ */
}