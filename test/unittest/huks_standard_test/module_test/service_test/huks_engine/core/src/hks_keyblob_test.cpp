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

#include "hks_keyblob_test.h"

#include <gtest/gtest.h>
#include <string>

#include "base/security/huks/services/huks_standard/huks_engine/main/core/src/hks_keyblob.c"

#include "file_ex.h"
#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksKeyBlobTest {
class HksKeyBlobTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksKeyBlobTest::SetUpTestCase(void)
{
}

void HksKeyBlobTest::TearDownTestCase(void)
{
}

void HksKeyBlobTest::SetUp()
{
}

void HksKeyBlobTest::TearDown()
{
}

#ifdef HKS_ENABLE_UPGRADE_KEY
/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest001
 * @tc.desc: tdd HksBuildKeyBlobWithOutAddKeyParam, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest001");
    uint32_t exceedCnt = HKS_DEFAULT_PARAM_CNT + 1;
    struct HksParamSet paramSet = { .paramSetSize = 0, .paramsCnt = exceedCnt, .params = {} };
    int32_t ret = HksBuildKeyBlobWithOutAddKeyParam(&paramSet, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest002
 * @tc.desc: tdd HksBuildKeyBlob2, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest002");
    int32_t ret = HksBuildKeyBlob2(nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest003
 * @tc.desc: tdd HksBuildKeyBlob2, expect HKS_ERROR_INVALID_KEY_INFO
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest003");
    uint8_t blobArray[] = { 0 };
    struct HksParam keyParam = { .tag = HKS_TAG_KEY, .blob = { .size = HKS_ARRAY_SIZE(blobArray), .data = blobArray } };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(paramSet, &keyParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildKeyBlob2(paramSet, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);
    HksFreeParamSet(&paramSet);
}
#endif

/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest004
 * @tc.desc: tdd CleanKey, expect not crash
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest004");
    int32_t ret = HksInitialize();
    ASSERT_EQ(ret, HKS_SUCCESS);
    CleanKey(nullptr);
}

/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest005
 * @tc.desc: tdd GetSalt, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest005");
    uint32_t exceedProcessNameLen = HKS_MAX_PROCESS_NAME_LEN + 1;
    uint8_t name[] = { 0 };
    struct HksParam processNameParam = { .tag = HKS_TAG_PROCESS_NAME,
        .blob = { .size = exceedProcessNameLen, .data = (uint8_t *)name } };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(paramSet, &processNameParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = GetSalt(paramSet, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest006
 * @tc.desc: tdd EncryptAndDecryptKeyBlob, expect HKS_ERROR_INVALID_KEY_INFO
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest006");
    uint8_t keyBlobData[] = { 0 };
    struct HksParam keyParam = { .tag = HKS_TAG_KEY,
        .blob = { .size = HKS_ARRAY_SIZE(keyBlobData), .data = (uint8_t *)keyBlobData } };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(paramSet, &keyParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = EncryptAndDecryptKeyBlob(nullptr, paramSet, true);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest007
 * @tc.desc: tdd HksGenerateKeyNode, expect nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest007");
    struct HksBlob keyBlob = { .size = MAX_KEY_SIZE, .data = nullptr };
    struct HksKeyNode *keyNode = HksGenerateKeyNode(&keyBlob);
    ASSERT_EQ(keyNode, nullptr);
}

/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest008
 * @tc.desc: tdd HksGetRawKey, expect HKS_ERROR_INVALID_KEY_INFO
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest008");
    uint8_t keyBlobData[] = { 0 };
    struct HksParam keyParam = { .tag = HKS_TAG_KEY,
        .blob = { .size = HKS_ARRAY_SIZE(keyBlobData), .data = (uint8_t *)keyBlobData } };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(paramSet, &keyParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksGetRawKey(paramSet, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);

    HksFreeParamSet(&paramSet);
}

#ifdef HKS_CHANGE_DERIVE_KEY_ALG_TO_HKDF
/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest009
 * @tc.desc: tdd GetDeriveKeyAlg, expect default derive algorithm
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest009");
    uint32_t alg;
    GetDeriveKeyAlg(nullptr, &alg);
    ASSERT_EQ(alg, HKS_ALG_HKDF);
}

/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest010
 * @tc.desc: tdd GetDeriveKeyAlg, expect old derive algorithm
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest010");
    struct HksParam keyVersion = { .tag = HKS_TAG_KEY_VERSION, .uint32Param = 1 };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(paramSet, &keyVersion, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint32_t alg;
    GetDeriveKeyAlg(paramSet, &alg);
    ASSERT_EQ(alg, HKS_ALG_PBKDF2);

    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest011
 * @tc.desc: tdd GetDeriveKeyAlg, expect new derive algorithm
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest011");
    struct HksParam keyVersion = { .tag = HKS_TAG_KEY_VERSION, .uint32Param = 3 };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(paramSet, &keyVersion, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint32_t alg;
    GetDeriveKeyAlg(paramSet, &alg);
    ASSERT_EQ(alg, HKS_ALG_HKDF);

    HksFreeParamSet(&paramSet);
}
#endif
}