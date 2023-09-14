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

#include "hks_double_list_test.h"

#include <gtest/gtest.h>

#include "hks_double_list.h"

#include "file_ex.h"
#include "hks_log.h"
#include "hks_type.h"

using namespace testing::ext;
namespace Unittest::HksDoubleListTest {
class HksDoubleListTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksDoubleListTest::SetUpTestCase(void)
{
}

void HksDoubleListTest::TearDownTestCase(void)
{
}

void HksDoubleListTest::SetUp()
{
}

void HksDoubleListTest::TearDown()
{
}

/**
 * @tc.name: HksDoubleListTest.HksDoubleListTest001
 * @tc.desc: tdd InitializeDoubleList
 * @tc.type: FUNC
 */
HWTEST_F(HksDoubleListTest, HksDoubleListTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksDoubleListTest001");
    struct DoubleList *nullNode = nullptr;
    struct DoubleList node = { 0 };
    InitializeDoubleList(nullNode);
    InitializeDoubleList(&node);
    ASSERT_TRUE(node.prev == &node);
}

/**
 * @tc.name: HksDoubleListTest.HksDoubleListTest002
 * @tc.desc: tdd AddNodeAfterDoubleListHead
 * @tc.type: FUNC
 */
HWTEST_F(HksDoubleListTest, HksDoubleListTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksDoubleListTest002");
    struct DoubleList head = { .prev = nullptr, .next = nullptr };
    struct DoubleList node = { 0 };
    AddNodeAfterDoubleListHead(nullptr, nullptr);
    AddNodeAfterDoubleListHead(&head, &node);
    ASSERT_TRUE(head.next == &node);
}

/**
 * @tc.name: HksDoubleListTest.HksDoubleListTest003
 * @tc.desc: tdd AddNodeAtDoubleListTail
 * @tc.type: FUNC
 */
HWTEST_F(HksDoubleListTest, HksDoubleListTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksDoubleListTest003");
    struct DoubleList head = { .prev = nullptr, .next = nullptr };
    struct DoubleList node = { 0 };
    AddNodeAtDoubleListTail(nullptr, nullptr);
    AddNodeAtDoubleListTail(&head, &node);
    ASSERT_TRUE(head.prev == &node);
}

/**
 * @tc.name: HksDoubleListTest.HksDoubleListTest004
 * @tc.desc: tdd RemoveDoubleListNode
 * @tc.type: FUNC
 */
HWTEST_F(HksDoubleListTest, HksDoubleListTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksDoubleListTest004");
    struct DoubleList head = { .prev = nullptr, .next = nullptr };
    RemoveDoubleListNode(nullptr);
    RemoveDoubleListNode(&head);
    EXPECT_EQ(head.next == nullptr, true);
    EXPECT_EQ(head.prev == nullptr, true);
}
}
