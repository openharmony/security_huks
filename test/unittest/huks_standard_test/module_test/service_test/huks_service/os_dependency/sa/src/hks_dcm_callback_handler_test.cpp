/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "message_parcel.h"

#include "hks_dcm_callback_handler.h"
#include "hks_log.h"
#include "hks_mem.h"

using namespace testing::ext;
namespace Unittest::HksDcmCallbackHandlerTest {
class HksDcmCallbackHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksDcmCallbackHandlerTest::SetUpTestCase(void)
{
}

void HksDcmCallbackHandlerTest::TearDownTestCase(void)
{
}

void HksDcmCallbackHandlerTest::SetUp()
{
}

void HksDcmCallbackHandlerTest::TearDown()
{
}

/**
 * @tc.name: HksDcmCallbackHandlerTest.HksDcmCallbackHandlerTest001
 * @tc.desc: tdd HksOpenDcmFunction and HksDcmCallbackHandlerGetMapMutex
 * @tc.type: FUNC
 */
HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest001");
    HksOpenDcmFunction();
    std::lock_guard<std::mutex> lockGuard(HksDcmCallbackHandlerGetMapMutex());
}

/**
 * @tc.name: HksDcmCallbackHandlerTest.HksDcmCallbackHandlerTest002
 * @tc.desc: tdd HksDcmCallback
 * @tc.type: FUNC
 */
HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest002");
    HksDcmCallback(nullptr);

    DcmAnonymousResponse response1 = {
        .requestId = 0,
        .errCode = 1
    };
    HksDcmCallback(&response1);

    DcmAnonymousResponse response2 = {
        .requestId = 1,
        .errCode = 0
    };
    HksDcmCallback(&response2);
}

/**
 * @tc.name: HksDcmCallbackHandlerTest.HksDcmCallbackHandlerTest003
 * @tc.desc: tdd HksCloseDcmFunction
 * @tc.type: FUNC
 */
HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest003");
    HksCloseDcmFunction();
}
}
