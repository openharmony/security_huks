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
    ASSERT_NE(HksGetDcmFunction<AttestFunction>("DcmAnonymousAttestKey"), nullptr);
    std::lock_guard<std::mutex> lockGuard(HksDcmCallbackHandlerGetMapMutex());
    HksCloseDcmFunction();
}

/**
 * @tc.name: HksDcmCallbackHandlerTest.HksDcmCallbackHandlerTest002
 * @tc.desc: tdd HksDcmCallback
 * @tc.type: FUNC
 */
HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest002");
    ASSERT_NE(HksGetDcmFunction<AttestFunction>("DcmAnonymousAttestKey"), nullptr);
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
 * @tc.name: HksDcmCallbackHandlerTest.HksDcmCallbackHandlerTest002
 * @tc.desc: tdd HksDcmCallback
 * @tc.type: FUNC
 */
HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest003");
    ASSERT_NE(HksGetDcmFunction<AttestFunction>("DcmLocalApplyAnonymousAttestKey"), nullptr);
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
 * @tc.name: HksDcmCallbackHandlerTest.HksDcmCallbackHandlerTest002
 * @tc.desc: tdd HksDcmCallback
 * @tc.type: FUNC
 */
HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest004");
    ASSERT_NE(HksGetDcmFunction<AttestFunction>("DcmLocalApplyAnonymousAttestKey"), nullptr);
    HksDcmCallback(nullptr);

    DcmAnonymousResponse response0 = {
        .requestId = 0,
        .errCode = DCM_ERROR_NETWORK_UNAVALIABLE
    };
    HksDcmCallback(&response0);

    DcmAnonymousResponse response1 = {
        .requestId = 1,
        .errCode = DCM_ERROR_SERVICE_TIME_OUT
    };
    HksDcmCallback(&response1);

    DcmAnonymousResponse response2 = {
        .requestId = 2,
        .errCode = -1
    };
    HksDcmCallback(&response2);

    DcmAnonymousResponse response3 = {
        .requestId = 3,
        .errCode = DCM_ERROR_INVALID_PRIVACY_KEY,
        .errInfo = {.data = NULL, .size = 0}
    };
    HksDcmCallback(&response3);

    uint8_t normalInfo[] = "test1";
    DcmBlob erroInfo = {.data = normalInfo, .size = sizeof(normalInfo)};
    DcmAnonymousResponse response4 = {
        .requestId = 4,
        .errCode = DCM_ERROR_INVALID_PRIVACY_KEY,
        .errInfo = erroInfo
    };
    HksDcmCallback(&response4);

    uint8_t listInfo[] = {'t','e','s','t'};
    DcmBlob listErroInfo = {.data = listInfo, .size = 4};
    DcmAnonymousResponse response5 = {
        .requestId = 5,
        .errCode = DCM_ERROR_INVALID_PRIVACY_KEY,
        .errInfo = listErroInfo
    };
    HksDcmCallback(&response5);
}

HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest005");
    ASSERT_NE(HksGetDcmFunction<AttestFunction>("DcmAnonymousAttestKey"), nullptr);
    
    HksDcmOfflineCallback(nullptr);
    
    DcmAnonymousResponse response1 = {
        .requestId = 100,
        .errCode = DCM_SUCCESS
    };
    HksDcmOfflineCallback(&response1);
    
    DcmAnonymousResponse response2 = {
        .requestId = 101,
        .errCode = DCM_ERROR_NETWORK_UNAVALIABLE
    };
    HksDcmOfflineCallback(&response2);
}

HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest006");
    ASSERT_NE(HksGetDcmFunction<LocalAttestFunction>("DcmLocalApplyAnonymousAttestKey"), nullptr);
    
    HksDcmOfflineCallback(nullptr);
}

HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest007");
    ASSERT_NE(HksGetDcmFunction<AttestFunction>("DcmAnonymousAttestKey"), nullptr);
    
    DcmAnonymousResponse response = {
        .requestId = 200,
        .errCode = DCM_ERROR_SERVICE_TIME_OUT
    };
    HksDcmOfflineCallback(&response);
}

HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest008");
    ASSERT_NE(HksGetDcmFunction<AttestFunction>("DcmAnonymousAttestKey"), nullptr);
    
    uint8_t errInfoData[] = "test error info";
    DcmBlob errInfo = {.data = errInfoData, .size = sizeof(errInfoData)};
    
    DcmAnonymousResponse response = {
        .requestId = 201,
        .errCode = DCM_ERROR_INVALID_PRIVACY_KEY,
        .errInfo = errInfo
    };
    HksDcmOfflineCallback(&response);
}

HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest009 - multiple function calls");
    
    auto func1 = HksGetDcmFunction<AttestFunction>("DcmAnonymousAttestKey");
    ASSERT_NE(func1, nullptr);
    
    auto func2 = HksGetDcmFunction<AttestFunction>("DcmAnonymousAttestKey");
    ASSERT_NE(func2, nullptr);
    
    auto func3 = HksGetDcmFunction<LocalAttestFunction>("DcmLocalApplyAnonymousAttestKey");
    ASSERT_NE(func3, nullptr);
}

HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest010 - close and reopen");
    HksCloseDcmFunction();
    
    auto func = HksGetDcmFunction<AttestFunction>("DcmAnonymousAttestKey");
    ASSERT_NE(func, nullptr);
    
    HksCloseDcmFunction();
}

HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest011 - null functionName");
    auto func = HksGetDcmFunction<AttestFunction>(nullptr);
    ASSERT_EQ(func, nullptr);
}

HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest012 - empty functionName");
    auto func = HksGetDcmFunction<AttestFunction>("");
    ASSERT_EQ(func, nullptr);
}

HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest013, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest013");
    ASSERT_NE(HksGetDcmFunction<AttestFunction>("DcmAnonymousAttestKey"), nullptr);
    
    DcmAnonymousResponse response = {
        .requestId = 300,
        .errCode = -999
    };
    HksDcmCallback(&response);
}

HWTEST_F(HksDcmCallbackHandlerTest, HksDcmCallbackHandlerTest014, TestSize.Level0)
{
    HKS_LOG_I("enter HksDcmCallbackHandlerTest014 - offline callback default error");
    ASSERT_NE(HksGetDcmFunction<AttestFunction>("DcmAnonymousAttestKey"), nullptr);
    
    DcmAnonymousResponse response = {
        .requestId = 301,
        .errCode = -999
    };
    HksDcmOfflineCallback(&response);
}
}
