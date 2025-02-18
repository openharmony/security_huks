/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hks_get_hash_test.h"

#include <cstdint>
#include <gtest/gtest.h>

#include "hks_report_common.h"
#include "hks_type.h"

using namespace testing::ext;
namespace Unittest::HksGetHashTest {
class HksGetHashTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksGetHashTest::SetUpTestCase(void)
{
}

void HksGetHashTest::TearDownTestCase(void)
{
}

void HksGetHashTest::SetUp()
{
}

void HksGetHashTest::TearDown()
{
}

/**
 * @tc.name: HksGetHashTest.HksGetHashTest001
 * @tc.desc: tdd HksGetHashTest
 * @tc.type: FUNC
 */
HWTEST_F(HksGetHashTest, HksGetHashTest001, TestSize.Level0)
{
    uint32_t hash = HksGetHash(nullptr);
    EXPECT_EQ(hash, 0) << "HksGetHashTest001 failed, hash = " << hash;

    HksBlob blob = { .size = 0, .data = nullptr };
    hash = HksGetHash(&blob);
    EXPECT_EQ(hash, 0) << "HksGetHashTest001 failed, hash = " << hash;
}

/**
 * @tc.name: HksGetHashTest.HksGetHashTest002
 * @tc.desc: tdd HksGetHashTest
 * @tc.type: FUNC
 */
HWTEST_F(HksGetHashTest, HksGetHashTest002, TestSize.Level0)
{
    uint8_t data[1] = {1};
    HksBlob blob = { .size = sizeof(data), .data = data };

    uint32_t hash = HksGetHash(&blob);
    uint32_t localHash = 1772448071;
    EXPECT_EQ(hash, localHash) << "HksGetHashTest002 failed, hash = " << hash;
}

/**
 * @tc.name: HksGetHashTest.HksGetHashTest003
 * @tc.desc: tdd HksGetHashTest
 * @tc.type: FUNC
 */
HWTEST_F(HksGetHashTest, HksGetHashTest003, TestSize.Level0)
{
    uint8_t data[2] = {0, 1};
    HksBlob blob = { .size = sizeof(data), .data = data };

    uint32_t hash = HksGetHash(&blob);
    uint32_t localHash = 3225178584;
    EXPECT_EQ(hash, localHash) << "HksGetHashTest003 failed, hash = " << hash;
}

/**
 * @tc.name: HksGetHashTest.HksGetHashTest004
 * @tc.desc: tdd HksGetHashTest
 * @tc.type: FUNC
 */
HWTEST_F(HksGetHashTest, HksGetHashTest004, TestSize.Level0)
{
    uint8_t data[3] = {1, 1, 1};
    HksBlob blob = { .size = sizeof(data), .data = data };

    uint32_t hash = HksGetHash(&blob);
    uint32_t localHash = 762152528;
    EXPECT_EQ(hash, localHash) << "HksGetHashTest004 failed, hash = " << hash;
}

/**
 * @tc.name: HksGetHashTest.HksGetHashTest005
 * @tc.desc: tdd HksGetHashTest
 * @tc.type: FUNC
 */
HWTEST_F(HksGetHashTest, HksGetHashTest005, TestSize.Level0)
{
    uint8_t data[3] = {1, 0, 1};
    HksBlob blob = { .size = sizeof(data), .data = data };

    uint32_t hash = HksGetHash(&blob);
    uint32_t localHash = 1782346923;
    EXPECT_EQ(hash, localHash) << "HksGetHashTest005 failed, hash = " << hash;
}
}
