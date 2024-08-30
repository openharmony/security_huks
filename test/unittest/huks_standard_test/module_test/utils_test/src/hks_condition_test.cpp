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

#include <algorithm>
#include <gtest/gtest.h>
#include <iterator>
#include <pthread.h>
#include <random>
#include <rwlock.h>
#include <thread>
#include <unistd.h>

#include "hks_api.h"
#include "hks_condition.h"
#include "hks_log.h"

using namespace testing::ext;
namespace Unittest::HksUtilsConditionTest {
class HksConditionTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksConditionTest::SetUpTestCase(void)
{
}

void HksConditionTest::TearDownTestCase(void)
{
}

void HksConditionTest::SetUp()
{
}

void HksConditionTest::TearDown()
{
}

/**
 * @tc.name: HksConditionTest.HksConditionTest001
 * @tc.desc: tdd HksConditionWait, with nullptr input, expect -1
 * @tc.type: FUNC
 */
HWTEST_F(HksConditionTest, HksConditionTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksConditionTest001");
    int32_t ret = HksConditionWait(nullptr);
    EXPECT_EQ(ret, -1) << "HksConditionTest001 failed, ret = " << ret;
}

void NotifyCondition(HksCondition *condition)
{
    sleep(1);
    int32_t ret = HksConditionNotify(condition);
    if (ret != HKS_SUCCESS) {
        HKS_LOG_E("HksConditionNotify failed, ret = %" LOG_PUBLIC "d", ret);
    }
}

/**
 * @tc.name: HksConditionTest.HksConditionTest002
 * @tc.desc: tdd HksConditionWait, with notified false, expecting HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksConditionTest, HksConditionTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksConditionTest002");
    HksCondition *condition = HksConditionCreate();
    EXPECT_NE(condition, nullptr) << "HksConditionCreate failed";
    std::thread thObj(NotifyCondition, condition);
    int32_t ret = HksConditionWait(condition);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksConditionTest002 failed, ret = " << ret;
    HksConditionDestroy(condition);
    thObj.join();
}

/**
 * @tc.name: HksConditionTest.HksConditionTest003
 * @tc.desc: tdd HksConditionWait, with notified true, expecting HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksConditionTest, HksConditionTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksConditionTest003");
    HksCondition *condition = HksConditionCreate();
    int32_t ret = HksConditionNotify(condition);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksConditionTest003 failed, ret = " << ret;
    ret = HksConditionWait(condition);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksConditionTest003 failed, ret = " << ret;
    HksConditionDestroy(condition);
}

/**
 * @tc.name: HksConditionTest.HksConditionTest004
 * @tc.desc: tdd HksConditionNotify, with waited false, expecting HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksConditionTest, HksConditionTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksConditionTest004");
    HksCondition *condition = HksConditionCreate();
    int32_t ret = HksConditionNotify(condition);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksConditionTest004 failed, ret = " << ret;
    ret = HksConditionNotify(condition);
    EXPECT_EQ(ret, HKS_SUCCESS) << "HksConditionTest004 failed, ret = " << ret;
    HksConditionDestroy(condition);
}

/**
 * @tc.name: HksConditionTest.HksConditionTest005
 * @tc.desc: tdd HksConditionDestroy, with nullptr input
 * @tc.type: FUNC
 */
HWTEST_F(HksConditionTest, HksConditionTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksConditionTest005");
    HksConditionDestroy(nullptr);
    int32_t ret = HksInitialize();
    EXPECT_EQ(ret, HKS_SUCCESS);
}

static void *WaitThread(void *p)
{
    EXPECT_EQ(HksConditionWait(static_cast<HksCondition *>(p)), HKS_SUCCESS);
    return nullptr;
}

/**
 * @tc.name: HksConditionTest.HksConditionTest006
 * @tc.desc: case fail if stuck
 * @tc.type: FUNC
 */
HWTEST_F(HksConditionTest, HksConditionTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksConditionTest006");
    enum {
        TSET_THREADS_COUNT = 10,
        TEST_TIMES = 100,
    };
    for (int no = 0; no < TEST_TIMES; ++no) {
        HksCondition *condition = HksConditionCreate();
        EXPECT_NE(condition, nullptr);
        pthread_t threads[TSET_THREADS_COUNT] {};
        for (int i = 0; i < TSET_THREADS_COUNT; ++i) {
            EXPECT_EQ(pthread_create(&threads[i], nullptr, WaitThread, condition), 0);
        }
        EXPECT_EQ(HksConditionNotifyAll(condition), HKS_SUCCESS);
        for (int i = 0; i < TSET_THREADS_COUNT; ++i) {
            EXPECT_EQ(pthread_join(threads[i], nullptr), 0);
        }
        HksConditionDestroy(condition);
    }
}

uint64_t Fib(uint64_t n)
{
    if (n < 1) {
        return 0;
    }
    enum {
        FIB_START_INDEX = 2,
    };
    if (n <= FIB_START_INDEX) {
        return 1;
    }
    int current = 1;
    int previous = 0;
    for (uint64_t i = 1; i < n; ++i) {
        int next = current + previous;
        previous = current;
        current = next;
    }
    return current;
}

static uint64_t TimeConsumingWork(uint64_t repeatTimes, uint64_t fibNumber)
{
    uint64_t sum = 0;
    for (uint64_t i = 0; i < repeatTimes; ++i) {
        sum += Fib(fibNumber);
    }
    if (repeatTimes == 0) {
        return Fib(fibNumber);
    }
    // avoid divisor zero
    return sum / repeatTimes;
}

static OHOS::Utils::RWLock g_rwLock(true);

static void *OnStartTest(void *p)
{
    {
        OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> writeGuard(g_rwLock);
        enum {
            CALC_FIB_TIMES = 10'000'000,
            CALC_FIB_NUMBER = 40,
        };
        // huks sa service start, upgrade keys
        EXPECT_EQ(TimeConsumingWork(CALC_FIB_TIMES, CALC_FIB_NUMBER), Fib(CALC_FIB_NUMBER));
    }
    EXPECT_EQ(HksConditionNotifyAll(static_cast<HksCondition *>(p)), HKS_SUCCESS);
    return nullptr;
}

static void HksUpgradeOnUserUnlockTest()
{
    g_rwLock.UnLockRead();

    {
        OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> writeGuard(g_rwLock);
        enum {
            CALC_FIB_TIMES = 10'000'000,
            CALC_FIB_NUMBER = 40,
        };
        // upgrade keys in case that user unlocked, or first time someone using credential-encrypted level key.
        EXPECT_EQ(TimeConsumingWork(CALC_FIB_TIMES, CALC_FIB_NUMBER), Fib(CALC_FIB_NUMBER));
    }

    g_rwLock.LockRead();
}

static volatile std::atomic_bool g_isCeUpgradeSucc = false;

static void *OnRemoteRequestTest(void *p)
{
    EXPECT_EQ(HksConditionWait(static_cast<HksCondition *>(p)), HKS_SUCCESS);
    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> readGuard(g_rwLock);
    enum {
        CALC_FIB_TIMES = 1'000'000,
        CALC_FIB_NUMBER = 40,
    };
    // someone is invoking huks
    EXPECT_EQ(TimeConsumingWork(CALC_FIB_TIMES, CALC_FIB_NUMBER), Fib(CALC_FIB_NUMBER));

    enum {
        IF_STORAGE_LEVEL_IS_CE = 2,
    };
    // someone is invoking huks for credential-encrypted level key
    if (std::rand() % IF_STORAGE_LEVEL_IS_CE) {
        bool flag = false;
        if (std::atomic_compare_exchange_strong(&g_isCeUpgradeSucc, &flag, true)) {
            HksUpgradeOnUserUnlockTest();
        }
    }
    return nullptr;
}

static void *OnReceiveEventTest(void *p)
{
    EXPECT_EQ(HksConditionWait(static_cast<HksCondition *>(p)), HKS_SUCCESS);
    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> readGuard(g_rwLock);
    HksUpgradeOnUserUnlockTest();
    return nullptr;
}

/**
 * @tc.name: HksConditionTest.HksConditionTest007
 * @tc.desc: case fail if stuck
 * @tc.type: FUNC
 */
HWTEST_F(HksConditionTest, HksConditionTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksConditionTest007");
    enum {
        TEST_THREADS_COUNT = 20,
        TEST_TIMES = 100,
        TEST_ON_RECEIVE_EVENT_THREADS_COUNT = 5,
    };
    for (int no = 0; no < TEST_TIMES; ++no) {
        HksCondition *condition = HksConditionCreate();
        EXPECT_NE(condition, nullptr);

        void *(*functions[TEST_THREADS_COUNT])(void *) {};
        // 1 :> OnStartTest, TEST_ON_RECEIVE_EVENT_THREADS_COUNT :> OnReceiveEventTest, others :> OnRemoteRequestTest
        std::fill(std::begin(functions), std::end(functions), OnRemoteRequestTest);
        std::fill_n(std::begin(functions), TEST_ON_RECEIVE_EVENT_THREADS_COUNT, OnReceiveEventTest);
        functions[TEST_THREADS_COUNT - 1] = OnStartTest;

        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(std::begin(functions), std::end(functions), g);

        pthread_t threads[TEST_THREADS_COUNT] {};
        for (int i = 0; i < TEST_THREADS_COUNT; ++i) {
            EXPECT_EQ(pthread_create(&threads[i], nullptr, functions[i], condition), 0);
        }

        for (int i = 0; i < TEST_THREADS_COUNT; ++i) {
            EXPECT_EQ(pthread_join(threads[i], nullptr), 0);
        }
        HksConditionDestroy(condition);
    }
}
}
