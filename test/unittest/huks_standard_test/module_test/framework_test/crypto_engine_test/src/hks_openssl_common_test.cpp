/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hks_openssl_common_test.h"

#include <gtest/gtest.h>

#include "hks_openssl_common.h"

#include "file_ex.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"

#include <cstring>

using namespace testing::ext;
namespace Unittest::HksFrameworkOpensslCommonTest {
class HksFrameworkOpensslCommonTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksFrameworkOpensslCommonTest::SetUpTestCase(void)
{
}

void HksFrameworkOpensslCommonTest::TearDownTestCase(void)
{
}

void HksFrameworkOpensslCommonTest::SetUp()
{
}

void HksFrameworkOpensslCommonTest::TearDown()
{
}

/**
 * @tc.name: HksFrameworkOpensslCommonTest.HksFrameworkOpensslCommonTest001
 * @tc.desc: test HksOpensslFillRandom with 1 buffer, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslCommonTest, HksFrameworkOpensslCommonTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslCommonTest001");
    const uint32_t dataSize = 1;
    uint8_t data[dataSize] = { 0 };
    struct HksBlob blob = { .size = dataSize, .data = data };
    int32_t ret = HksOpensslFillRandom(&blob);
    ASSERT_TRUE(ret == HKS_SUCCESS);
}

/**
 * @tc.name: HksFrameworkOpensslCommonTest.HksFrameworkOpensslCommonTest002
 * @tc.desc: test HksOpensslFillPrivRandom with 1 buffer, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslCommonTest, HksFrameworkOpensslCommonTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslCommonTest002");
    const uint32_t dataSize = 1;
    uint8_t data[dataSize] = { 0 };
    struct HksBlob blob = { .size = dataSize, .data = data };
    int32_t ret = HksOpensslFillPrivRandom(&blob);
    ASSERT_TRUE(ret == HKS_SUCCESS);
}

/**
 * @tc.name: HksFrameworkOpensslCommonTest.HksFrameworkOpensslCommonTest003
 * @tc.desc: test HksOpensslFillPrivRandom with multi-buffer, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksFrameworkOpensslCommonTest, HksFrameworkOpensslCommonTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksFrameworkOpensslCommonTest003");
    const uint32_t dataSize = 16;
    uint8_t data[dataSize] = { 0 };
    struct HksBlob blob = { .size = dataSize, .data = data };
    int32_t ret = HksOpensslFillPrivRandom(&blob);
    ASSERT_TRUE(ret == HKS_SUCCESS);
}
}
