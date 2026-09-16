/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "hks_client_service_adapter_common_test.h"

#include <gtest/gtest.h>
#include <string>

#include "base/security/huks/utils/crypto_adapter/hks_client_service_adapter_common.c"
#include "file_ex.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_three_stage_test_common.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksClientServiceAdapterCommonTest {
class HksClientServiceAdapterCommonTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksClientServiceAdapterCommonTest::SetUpTestCase(void)
{
}

void HksClientServiceAdapterCommonTest::TearDownTestCase(void)
{
}

void HksClientServiceAdapterCommonTest::SetUp()
{
}

void HksClientServiceAdapterCommonTest::TearDown()
{
}

/**
 * @tc.name: HksClientServiceAdapterCommonTest.HksClientServiceAdapterCommonTest001
 * @tc.desc: tdd HksClientServiceAdapterCommonTest001, function is CopyToInnerKey
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceAdapterCommonTest, HksClientServiceAdapterCommonTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceAdapterCommonTest001");
    HksBlob key = {
        .size = 0,
        .data = nullptr,
    };
    int32_t ret = CopyToInnerKey(&key, HKS_ALG_AES, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterCommonTest001 failed, ret = " << ret;

    key.size = MAX_KEY_SIZE + 1;
    ret = CopyToInnerKey(&key, HKS_ALG_AES, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterCommonTest001 failed, ret = " << ret;
}

/**
 * @tc.name: HksClientServiceAdapterCommonTest.HksClientServiceAdapterCommonTest002
 * @tc.desc: tdd HksClientServiceAdapterCommonTest002, function is TranslateToInnerCurve25519Format
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceAdapterCommonTest, HksClientServiceAdapterCommonTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceAdapterCommonTest002");
    HksBlob key = {
        .size = 0,
        .data = nullptr,
    };
    int32_t ret = TranslateToInnerCurve25519Format(HKS_ALG_RSA, &key, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksClientServiceAdapterCommonTest002 failed, ret = " << ret;
}

/**
 * @tc.name: HksClientServiceAdapterCommonTest.HksClientServiceAdapterCommonTest003
 * @tc.desc: tdd HksClientServiceAdapterCommonTest003, function is GetHksPubKeyInnerFormat
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceAdapterCommonTest, HksClientServiceAdapterCommonTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceAdapterCommonTest003");
    int32_t ret = GetHksPubKeyInnerFormat(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterCommonTest003 failed, ret = " << ret;
    HksBlob key = {
        .size = sizeof(HksBlob),
        .data = reinterpret_cast<uint8_t *>(HksMalloc(sizeof(HksBlob))),
    };
    ret = GetHksPubKeyInnerFormat(nullptr, &key, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterCommonTest003 failed, ret = " << ret;
    HKS_FREE(key.data);
}

/**
 * @tc.name: HksClientServiceAdapterCommonTest.HksClientServiceAdapterCommonTest004
 * @tc.desc: tdd HksClientServiceAdapterCommonTest004, function is GetHksPubKeyInnerFormat
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceAdapterCommonTest, HksClientServiceAdapterCommonTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceAdapterCommonTest004");
    struct HksParam params[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HKDF }
    };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret= InitParamSet(&paramSet, params, sizeof(params) / sizeof(params[0]));
    ASSERT_EQ(ret, HKS_SUCCESS);
    HksBlob key = {
        .size = sizeof(HksBlob),
        .data = reinterpret_cast<uint8_t *>(HksMalloc(sizeof(HksBlob))),
    };
    HksBlob outKey = { .size = 0, .data = nullptr };
    ret = GetHksPubKeyInnerFormat(paramSet, &key, &outKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ALGORITHM) << "HksClientServiceAdapterCommonTest004 failed, ret = " << ret;
    HksFreeParamSet(&paramSet);
    HKS_FREE(key.data);
}

#ifdef HKS_SUPPORT_ML_DSA_C
/**
 * @tc.name: HksClientServiceAdapterCommonTest.HksClientServiceAdapterCommonTest005
 * @tc.desc: tdd HksClientServiceAdapterCommonTest005, function is CopyToInnerKey with ML_DSA key
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceAdapterCommonTest, HksClientServiceAdapterCommonTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceAdapterCommonTest005");
    uint8_t *keyData = (uint8_t *)HksMalloc(ML_DSA_MAX_KEY_SIZE + 1);
    ASSERT_NE(keyData, nullptr);
    (void)memset_s(keyData, ML_DSA_MAX_KEY_SIZE + 1, 0xAB, ML_DSA_MAX_KEY_SIZE + 1);

    /* key size exceeds ML_DSA_MAX_KEY_SIZE, expect failed */
    HksBlob key = { ML_DSA_MAX_KEY_SIZE + 1, keyData };
    HksBlob outKey = { 0, nullptr };
    int32_t ret = CopyToInnerKey(&key, HKS_ALG_ML_DSA, &outKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterCommonTest005 failed, ret = " << ret;

    /* key size between MAX_KEY_SIZE and ML_DSA_MAX_KEY_SIZE, expect success */
    key.size = MAX_KEY_SIZE + 1;
    ret = CopyToInnerKey(&key, HKS_ALG_ML_DSA, &outKey);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksClientServiceAdapterCommonTest005 failed, ret = " << ret;
    EXPECT_EQ(outKey.size, key.size);
    EXPECT_EQ(memcmp(outKey.data, keyData, key.size), 0);
    HKS_FREE_BLOB(outKey);

    /* key size equals ML_DSA_MAX_KEY_SIZE, expect success */
    key.size = ML_DSA_MAX_KEY_SIZE;
    ret = CopyToInnerKey(&key, HKS_ALG_ML_DSA, &outKey);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksClientServiceAdapterCommonTest005 failed, ret = " << ret;
    EXPECT_EQ(outKey.size, ML_DSA_MAX_KEY_SIZE);
    EXPECT_EQ(memcmp(outKey.data, keyData, ML_DSA_MAX_KEY_SIZE), 0);
    HKS_FREE_BLOB(outKey);

    HKS_FREE(keyData);
}
#endif

#ifdef HKS_SUPPORT_ML_KEM_C
/**
 * @tc.name: HksClientServiceAdapterCommonTest.HksClientServiceAdapterCommonTest006
 * @tc.desc: tdd HksClientServiceAdapterCommonTest006, function is CopyToInnerKey with ML_KEM key
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceAdapterCommonTest, HksClientServiceAdapterCommonTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceAdapterCommonTest006");
    uint8_t *keyData = (uint8_t *)HksMalloc(ML_KEM_MAX_KEY_SIZE + 1);
    ASSERT_NE(keyData, nullptr);
    (void)memset_s(keyData, ML_KEM_MAX_KEY_SIZE + 1, 0xAB, ML_KEM_MAX_KEY_SIZE + 1);

    /* key size exceeds ML_KEM_MAX_KEY_SIZE, expect failed */
    HksBlob key = { ML_KEM_MAX_KEY_SIZE + 1, keyData };
    HksBlob outKey = { 0, nullptr };
    int32_t ret = CopyToInnerKey(&key, HKS_ALG_ML_KEM, &outKey);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterCommonTest006 failed, ret = " << ret;

    /* key size between MAX_KEY_SIZE and ML_KEM_MAX_KEY_SIZE, expect success */
    key.size = MAX_KEY_SIZE + 1;
    ret = CopyToInnerKey(&key, HKS_ALG_ML_KEM, &outKey);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksClientServiceAdapterCommonTest006 failed, ret = " << ret;
    EXPECT_EQ(outKey.size, key.size);
    EXPECT_EQ(memcmp(outKey.data, keyData, key.size), 0);
    HKS_FREE_BLOB(outKey);

    /* key size equals ML_KEM_MAX_KEY_SIZE, expect success */
    key.size = ML_KEM_MAX_KEY_SIZE;
    ret = CopyToInnerKey(&key, HKS_ALG_ML_KEM, &outKey);
    ASSERT_EQ(ret, HKS_SUCCESS) << "HksClientServiceAdapterCommonTest006 failed, ret = " << ret;
    EXPECT_EQ(outKey.size, ML_KEM_MAX_KEY_SIZE);
    EXPECT_EQ(memcmp(outKey.data, keyData, ML_KEM_MAX_KEY_SIZE), 0);
    HKS_FREE_BLOB(outKey);

    HKS_FREE(keyData);
}
#endif

}