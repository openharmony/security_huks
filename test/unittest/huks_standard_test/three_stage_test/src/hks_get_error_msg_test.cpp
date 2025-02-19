/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <iostream>
#include <string>

#include "hks_api.h"
#include "hks_param.h"
#include "hks_test_common.h"
#include "hks_test_log.h"
#include "hks_type.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
using namespace testing::ext;
namespace {
class HksGetErrorMsgTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksGetErrorMsgTest::SetUpTestCase(void)
{
}

void HksGetErrorMsgTest::TearDownTestCase(void)
{
}

void HksGetErrorMsgTest::SetUp()
{
}

void HksGetErrorMsgTest::TearDown()
{
}

/**
 * @tc.name: HksGetErrorMsgTest.HksGetErrorMsgTest001
 * @tc.desc: call HksGetErrorMsg;
 * @tc.type: FUNC
 */
HWTEST_F(HksGetErrorMsgTest, HksGetErrorMsgTest001, TestSize.Level0)
{
    const char *errorMsg = HksGetErrorMsg();
    EXPECT_NE(errorMsg, nullptr) << "HksGetErrorMsg ret is nullptr";
}

/**
 * @tc.name: HksGetErrorMsgTest.HksGetErrorMsgTest002
 * @tc.desc: call HksGetErrorMsg;
 * @tc.type: FUNC
 */
HWTEST_F(HksGetErrorMsgTest, HksGetErrorMsgTest002, TestSize.Level0)
{
    HksClearThreadErrorMsg();
    static std::string info = std::string(__func__) + "[" + std::to_string(__LINE__ + 3) + "]: ";
    std::string generateStr = std::string(10, 'a');
    const char* testStr = generateStr.c_str();
    HKS_LOG_E_IMPORTANT("%" LOG_PUBLIC "s", testStr);
    EXPECT_EQ(HksGetThreadErrorMsgLen(), info.length() + 10) << "errMsg len is not expected";
}

/**
 * @tc.name: HksGetErrorMsgTest.HksGetErrorMsgTest003
 * @tc.desc: call HksGetErrorMsg;
 * @tc.type: FUNC
 */
HWTEST_F(HksGetErrorMsgTest, HksGetErrorMsgTest003, TestSize.Level0)
{
    HksClearThreadErrorMsg();
    static std::string info = std::string(__func__) + "[" + std::to_string(__LINE__ + 3) + "]: ";
    std::string generateStr = std::string(MAX_ERROR_MESSAGE_LEN - info.length() - 1, 'a');
    const char* testStr = generateStr.c_str();
    HKS_LOG_E_IMPORTANT("%" LOG_PUBLIC "s", testStr);
    EXPECT_EQ(HksGetThreadErrorMsgLen(), MAX_ERROR_MESSAGE_LEN - 1) << "errMsg len is not MAX_ERROR_MESSAGE_LEN - 1";
}

/**
 * @tc.name: HksGetErrorMsgTest.HksGetErrorMsgTest004
 * @tc.desc: call HksGetErrorMsg;
 * @tc.type: FUNC
 */
HWTEST_F(HksGetErrorMsgTest, HksGetErrorMsgTest004, TestSize.Level0)
{
    HksClearThreadErrorMsg();
    static std::string info = std::string(__func__) + "[" + std::to_string(__LINE__ + 3) + "]: ";
    std::string generateStr = std::string(MAX_ERROR_MESSAGE_LEN - info.length(), 'a');
    const char* testStr = generateStr.c_str();
    HKS_LOG_E_IMPORTANT("%" LOG_PUBLIC "s", testStr);
    EXPECT_EQ(HksGetThreadErrorMsgLen(), 0) << "errMsg len is not 0";
}

/**
 * @tc.name: HksGetErrorMsgTest.HksGetErrorMsgTest005
 * @tc.desc: call HksGetErrorMsg;
 * @tc.type: FUNC
 */
HWTEST_F(HksGetErrorMsgTest, HksGetErrorMsgTest005, TestSize.Level0)
{
    HksClearThreadErrorMsg();
    static std::string info = std::string(__func__) + "[" + std::to_string(__LINE__ + 3) + "]: ";
    std::string generateStr = std::string(MAX_ERROR_MESSAGE_LEN - info.length() - 1 - 476, 'a');
    const char* testStr = generateStr.c_str();
    HKS_LOG_E_IMPORTANT( \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "123456" \
        "%" LOG_PUBLIC "s", testStr);
    EXPECT_EQ(HksGetThreadErrorMsgLen(), MAX_ERROR_MESSAGE_LEN - 1) << "errMsg len is not MAX_ERROR_MESSAGE_LEN - 1";
}

/**
 * @tc.name: HksGetErrorMsgTest.HksGetErrorMsgTest006
 * @tc.desc: call HksGetErrorMsg;
 * @tc.type: FUNC
 */
HWTEST_F(HksGetErrorMsgTest, HksGetErrorMsgTest006, TestSize.Level0)
{
    HksClearThreadErrorMsg();
    static std::string info = std::string(__func__) + "[" + std::to_string(__LINE__ + 3) + "]: ";
    std::string generateStr = std::string(MAX_ERROR_MESSAGE_LEN - info.length() - 476, 'a');
    const char* testStr = generateStr.c_str();
    HKS_LOG_E_IMPORTANT( \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "123456" \
        "%" LOG_PUBLIC "s", testStr);
    EXPECT_EQ(HksGetThreadErrorMsgLen(), 0) << "errMsg len is not 0";
}

/**
 * @tc.name: HksGetErrorMsgTest.HksGetErrorMsgTest007
 * @tc.desc: call HksGetErrorMsg;
 * @tc.type: FUNC
 */
HWTEST_F(HksGetErrorMsgTest, HksGetErrorMsgTest007, TestSize.Level0)
{
    HksClearThreadErrorMsg();
    static std::string info = std::string(__func__) + "[" + std::to_string(__LINE__ + 3) + "]: ";
    std::string generateStr = std::string(MAX_ERROR_MESSAGE_LEN - info.length() - 1 - 477, 'a');
    const char* testStr = generateStr.c_str();
    HKS_LOG_E_IMPORTANT( \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" \
        "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567890" "1234567" \
        "%" LOG_PUBLIC "s", testStr);
    EXPECT_EQ(HksGetThreadErrorMsgLen(), 0) << "errMsg len is not 0";
}

}