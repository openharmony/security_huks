/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "hks_storage_test.h"

#include <gtest/gtest.h>
#include <cstring>

#include "file_ex.h"
#include "hks_log.h"
#include "hks_type_inner.h"
#include "hks_param.h"

#include "base/security/huks/services/huks_standard/huks_service/main/core/src/hks_storage_utils.c"

using namespace testing::ext;
namespace Unittest::HksStorageTest {
class HksStorageTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksStorageTest::SetUpTestCase(void)
{
}

void HksStorageTest::TearDownTestCase(void)
{
}

void HksStorageTest::SetUp()
{
}

void HksStorageTest::TearDown()
{
}

/**
 * @tc.name: HksStorageTest.HksStorageTest001
 * @tc.desc: tdd ResumeInvalidCharacter with #
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest001");
    const char input = '#';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
    ASSERT_EQ(outPut, ':');
}

/**
 * @tc.name: HksStorageTest.HksStorageTest002
 * @tc.desc: tdd ResumeInvalidCharacter with $
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest002");
    const char input = '$';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
    ASSERT_EQ(outPut, '<');
}

/**
 * @tc.name: HksStorageTest.HksStorageTest003
 * @tc.desc: tdd ResumeInvalidCharacter with %
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest003");
    const char input = '%';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
    ASSERT_EQ(outPut, '>');
}

/**
 * @tc.name: HksStorageTest.HksStorageTest004
 * @tc.desc: tdd ResumeInvalidCharacter with &
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest004");
    const char input = '&';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
    ASSERT_EQ(outPut, '?');
}

/**
 * @tc.name: HksStorageTest.HksStorageTest005
 * @tc.desc: tdd ResumeInvalidCharacter with (
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest005");
    const char input = '(';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
    ASSERT_EQ(outPut, '\\');
}

/**
 * @tc.name: HksStorageTest.HksStorageTest006
 * @tc.desc: tdd ResumeInvalidCharacter with )
 * @tc.type: FUNC
 */
HWTEST_F(HksStorageTest, HksStorageTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksStorageTest006");
    const char input = ')';
    char outPut;
    ResumeInvalidCharacter(input, &outPut);
    ASSERT_EQ(outPut, '|');
}
}
