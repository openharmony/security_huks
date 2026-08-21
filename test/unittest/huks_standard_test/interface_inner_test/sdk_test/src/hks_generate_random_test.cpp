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

#include "hks_generate_random_test.h"

#include "file_ex.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_api_performance.h"
#include "hks_test_common.h"
#include "hks_test_log.h"
#include "hks_type.h"

using namespace testing::ext;
namespace {
class HksGenerateRandomTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksGenerateRandomTest::SetUpTestCase(void)
{
}

void HksGenerateRandomTest::TearDownTestCase(void)
{
}

void HksGenerateRandomTest::SetUp()
{
}

void HksGenerateRandomTest::TearDown()
{
}

static const struct HksTestGenRandomParams g_testGenRandomParams[] = {
    /* normal case */
    { 0, HKS_SUCCESS, { true, HKS_MAX_RANDOM_LEN, true, HKS_MAX_RANDOM_LEN } },
};
/**
 * @tc.name: HksGenerateRandomTest.HksGenerateRandomTest001
 * @tc.desc: The static function will return true;
 * @tc.type: FUNC
 */
HWTEST_F(HksGenerateRandomTest, HksGenerateRandomTest001, TestSize.Level0)
{
    int32_t ret;
    struct HksBlob *random = NULL;

    ret = TestConstructBlobOut(&random,
        g_testGenRandomParams[0].randomParams.blobExist,
        g_testGenRandomParams[0].randomParams.blobSize,
        g_testGenRandomParams[0].randomParams.blobDataExist,
        g_testGenRandomParams[0].randomParams.blobDataSize);
    EXPECT_TRUE(ret == 0);

    ret = HksGenerateRandomRun(random, 1);
    if (ret != g_testGenRandomParams[0].expectResult) {
        HKS_TEST_LOG_I("HksGenerateRandomRun failed, ret[%u] = %d", g_testGenRandomParams[0].testId, ret);
    }
    EXPECT_TRUE(ret == g_testGenRandomParams[0].expectResult);

    TestFreeBlob(&random);
    ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: HksGenerateRandomTest.HksGenerateRandomTest002
 * @tc.desc: HksGenerateRandom with null random blob (param check fails).
 * @tc.type: FUNC
 */
HWTEST_F(HksGenerateRandomTest, HksGenerateRandomTest002, TestSize.Level0)
{
    int32_t ret = HksGenerateRandomRun(NULL, 1);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksGenerateRandomTest.HksGenerateRandomTest003
 * @tc.desc: HksGenerateRandom with random.data null (param check fails).
 * @tc.type: FUNC
 */
HWTEST_F(HksGenerateRandomTest, HksGenerateRandomTest003, TestSize.Level0)
{
    struct HksBlob random = { .size = HKS_MAX_RANDOM_LEN, .data = NULL };
    int32_t ret = HksGenerateRandom(NULL, &random);
    EXPECT_NE(ret, HKS_SUCCESS);
}

/**
 * @tc.name: HksGenerateRandomTest.HksGenerateRandomTest004
 * @tc.desc: HksGenerateRandom with random.size 0 (param check fails).
 * @tc.type: FUNC
 */
HWTEST_F(HksGenerateRandomTest, HksGenerateRandomTest004, TestSize.Level0)
{
    uint8_t buf[HKS_MAX_RANDOM_LEN] = {0};
    struct HksBlob random = { .size = 0, .data = buf };
    int32_t ret = HksGenerateRandom(NULL, &random);
    EXPECT_NE(ret, HKS_SUCCESS);
}
}