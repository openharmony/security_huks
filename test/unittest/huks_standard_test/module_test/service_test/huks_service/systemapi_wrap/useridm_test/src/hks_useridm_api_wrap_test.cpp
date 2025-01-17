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

#include "hks_useridm_api_wrap_test.h"

#include <thread>

#include <gtest/gtest.h>

#include "file_ex.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_type.h"
#include "hks_type_inner.h"
#include "hks_useridm_api_wrap.h"
#include "user_idm_client.h"

constexpr int WAIT_THREADS_COUNT = HUKS_IPC_THREAD_WITH_CALLBACK_ASYNC_TO_SYNC_WAIT_NUM_LIMIT + 10;
constexpr int WAIT_BEFORE_CALLBACK_MILL_SECONDS = 200;
constexpr int WAIT_AFTER_CALLBACK_MILL_SECONDS = 200;

using namespace testing::ext;
using namespace OHOS::UserIam::UserAuth;
namespace Unittest::HksServiceUseridmWrapTest {
class HksUseridmWrapTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksUseridmWrapTest::SetUpTestCase(void)
{
}

void HksUseridmWrapTest::TearDownTestCase(void)
{
}

void HksUseridmWrapTest::SetUp()
{
}

void HksUseridmWrapTest::TearDown()
{
}

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest001
 * @tc.desc: tdd HksUserIdmGetSecInfo, with nullptr input, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksUseridmWrapTest001");
    int32_t ret = HksUserIdmGetSecInfo(0, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksUseridmWrapTest001 failed, ret = " << ret;
}

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest002
 * @tc.desc: tdd HksUserIdmGetSecInfo, with user id 0, expecting HKS_ERROR_GET_USERIAM_SECINFO_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksUseridmWrapTest002");
    struct SecInfoWrap *secInfoWrap = nullptr;
    int32_t ret = HksUserIdmGetSecInfo(0, &secInfoWrap);
    EXPECT_EQ(ret, HKS_ERROR_GET_USERIAM_SECINFO_FAILED) << "HksUseridmWrapTest002 failed, ret = " << ret;
}

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest003
 * @tc.desc: tdd HksUserIdmGetAuthInfoNum, with nullptr input, expecting HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksUseridmWrapTest003");
    int32_t ret = HksUserIdmGetAuthInfoNum(0, (enum HksUserAuthType)HKS_USER_AUTH_TYPE_FINGERPRINT, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksUseridmWrapTest003 failed, ret = " << ret;
}

static constexpr uint32_t USERIAM_PIN = 1;
static constexpr uint32_t USERIAM_FACE = 2;
static constexpr uint32_t USERIAM_FINGER_PRINT = 4;

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest004
 * @tc.desc: tdd HksConvertUserIamTypeToHksType, expecting HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksUseridmWrapTest004");
    uint32_t hksValue = 0;
    int32_t ret = HksConvertUserIamTypeToHksType(HKS_AUTH_TYPE, USERIAM_PIN, &hksValue);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksUseridmWrapTest004 failed, ret = " << ret;
    EXPECT_EQ(hksValue, HKS_USER_AUTH_TYPE_PIN) << "HksConvertUserIamTypeToHksType failed, hksValue = " << hksValue;
}

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest005
 * @tc.desc: tdd HksUserIdmGetAuthInfoNum, expecting HKS_ERROR_GET_USERIAM_AUTHINFO_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksUseridmWrapTest005");
    uint32_t num = 0;
    int32_t ret = HksUserIdmGetAuthInfoNum(0, HKS_USER_AUTH_TYPE_FINGERPRINT, &num);
    EXPECT_EQ(ret, HKS_ERROR_GET_USERIAM_AUTHINFO_FAILED) << "HksUseridmWrapTest005 failed, ret = " << ret;
}

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest006
 * @tc.desc: tdd HksConvertUserIamTypeToHksType, expecting HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksUseridmWrapTest006");
    uint32_t hksValue = 0;
    int32_t ret = HksConvertUserIamTypeToHksType(HKS_AUTH_TYPE, USERIAM_FACE, &hksValue);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksUseridmWrapTest006 failed, ret = " << ret;
    EXPECT_EQ(hksValue, HKS_USER_AUTH_TYPE_FACE) << "HksConvertUserIamTypeToHksType failed, hksValue = " << hksValue;
}

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest007
 * @tc.desc: tdd HksConvertUserIamTypeToHksType, expecting HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksUseridmWrapTest007");
    uint32_t hksValue = 0;
    int32_t ret = HksConvertUserIamTypeToHksType(HKS_AUTH_TYPE, USERIAM_FINGER_PRINT, &hksValue);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksUseridmWrapTest007 failed, ret = " << ret;
    EXPECT_EQ(hksValue, HKS_USER_AUTH_TYPE_FINGERPRINT) <<
        "HksConvertUserIamTypeToHksType failed, hksValue = " << hksValue;
}

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest008
 * @tc.desc: tdd HksUserIdmGetAuthInfoNum, expecting HKS_ERROR_GET_USERIAM_AUTHINFO_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksUseridmWrapTest008");
    uint32_t num = 0;
    int32_t ret = HksUserIdmGetAuthInfoNum(0, HKS_USER_AUTH_TYPE_PIN, &num);
    EXPECT_EQ(ret, HKS_ERROR_GET_USERIAM_AUTHINFO_FAILED) << "HksUseridmWrapTest008 failed, ret = " << ret;
}

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest009
 * @tc.desc: tdd HksUserIdmGetAuthInfoNum, expecting HKS_ERROR_GET_USERIAM_AUTHINFO_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksUseridmWrapTest009");
    uint32_t num = 0;
    int32_t ret = HksUserIdmGetAuthInfoNum(0, HKS_USER_AUTH_TYPE_FACE, &num);
    EXPECT_EQ(ret, HKS_ERROR_GET_USERIAM_AUTHINFO_FAILED) << "HksUseridmWrapTest009 failed, ret = " << ret;
}

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest010
 * @tc.desc: tdd HksUserIdmGetAuthInfoNum, expecting HKS_SUCCESS and num > 0
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest010, TestSize.Level0)
{
    HKS_LOG_I("enter HksUseridmWrapTest010");
    ChangeGetCredentialInfoReturn(true);
    uint32_t num = 0;
    int32_t ret = HksUserIdmGetAuthInfoNum(1, (enum HksUserAuthType)HKS_USER_AUTH_TYPE_FINGERPRINT, &num);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksUseridmWrapTest010 HksUserIdmGetAuthInfoNum failed, ret = " << ret;
    EXPECT_EQ(num > 0, true) << "HksUseridmWrapTest010 HksUserIdmGetAuthInfoNum failed, num = " << num;
}

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest011
 * @tc.desc: tdd HksUserIdmGetAuthInfoNum, expecting HKS_SUCCESS and num == 0
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest011, TestSize.Level0)
{
    HKS_LOG_I("enter HksUseridmWrapTest011");
    ChangeGetCredentialInfoReturn(false);
    uint32_t num = 0;
    int32_t ret = HksUserIdmGetAuthInfoNum(1, (enum HksUserAuthType)HKS_USER_AUTH_TYPE_FINGERPRINT, &num);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksUseridmWrapTest011 HksUserIdmGetAuthInfoNum failed, ret = " << ret;
    EXPECT_EQ(num == 0, true) << "HksUseridmWrapTest011 HksUserIdmGetAuthInfoNum failed, num = " << num;
}

static constexpr uint32_t ENROLLED_ID_FOR_PIN = 1;

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest012
 * @tc.desc: tdd HksUserIdmGetSecInfo, expecting HKS_SUCCESS and num > 0
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest012, TestSize.Level0)
{
    HKS_LOG_I("enter HksUseridmWrapTest012");
    ChangeGetSecUserInfoReturn(true);
    struct SecInfoWrap *secInfo = nullptr;
    int32_t ret = HksUserIdmGetSecInfo(1, &secInfo);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksUseridmWrapTest012 HksUserIdmGetSecInfo failed, ret = " << ret;
    EXPECT_EQ(secInfo->enrolledInfoLen > 0, true);
    EXPECT_EQ(secInfo->enrolledInfo[0].authType, HKS_USER_AUTH_TYPE_PIN);
    EXPECT_EQ(secInfo->enrolledInfo[0].enrolledId, ENROLLED_ID_FOR_PIN);
    if (secInfo != nullptr) {
        HKS_FREE(secInfo->enrolledInfo);
        HKS_FREE(secInfo);
    }
}

/**
 * @tc.name: HksUseridmWrapTest.HksUseridmWrapTest013
 * @tc.desc: tdd HksIpcCounter, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksUseridmWrapTest, HksUseridmWrapTest013, TestSize.Level0)
{
    std::atomic_uint32_t successCnt{};
    std::atomic_uint32_t failCnt{};
    auto waitFunc = [&successCnt, &failCnt](int waitBeforeCallbackMilliSeconds, int waitAfterCallbackMilliSeconds) {
        OHOS::Security::Hks::HksIpcCounter cntr{};
        std::this_thread::sleep_for(std::chrono::milliseconds(waitBeforeCallbackMilliSeconds));
        {
            int32_t ret = cntr.Wait();
            if (ret == HKS_SUCCESS) {
                std::this_thread::sleep_for(std::chrono::milliseconds(waitAfterCallbackMilliSeconds));
                ++successCnt;
            } else {
                EXPECT_EQ(ret, HKS_ERROR_SESSION_REACHED_LIMIT);
                ++failCnt;
            }
        }
    };
    std::vector<std::thread> waitThreads(WAIT_THREADS_COUNT);
    for (int i = 0; i < WAIT_THREADS_COUNT; ++i) {
        waitThreads[i] = std::thread(waitFunc, WAIT_BEFORE_CALLBACK_MILL_SECONDS, WAIT_AFTER_CALLBACK_MILL_SECONDS);
    }
    for (auto &thrd : waitThreads) {
        thrd.join();
    }
    EXPECT_EQ(successCnt, HUKS_IPC_THREAD_WITH_CALLBACK_ASYNC_TO_SYNC_WAIT_NUM_LIMIT);
    EXPECT_EQ(failCnt, WAIT_THREADS_COUNT - HUKS_IPC_THREAD_WITH_CALLBACK_ASYNC_TO_SYNC_WAIT_NUM_LIMIT);
}
}
