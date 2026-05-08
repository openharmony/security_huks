/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <mutex>
#include <securec.h>
#include <thread>
#include <vector>

#include "hks_api.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_se_session_manager.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace {

class HksSeSessionManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HksSeSessionManagerTest::SetUpTestCase(void) {}

void HksSeSessionManagerTest::TearDownTestCase(void) {}

void HksSeSessionManagerTest::SetUp() {}

void HksSeSessionManagerTest::TearDown() {}

static int32_t BuildParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramCount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    ret = HksAddParams(*paramSet, params, paramCount);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(paramSet);
        return ret;
    }
    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(paramSet);
        return ret;
    }
    return HKS_SUCCESS;
}

static void BuildProcessInfo(struct HksProcessInfo *processInfo, uint32_t userIdInt, uint32_t uidInt)
{
    uint8_t userIdData[] = "test_user";
    uint8_t processNameData[] = "test_process";

    processInfo->userIdInt = userIdInt;
    processInfo->uidInt = uidInt;
    processInfo->userId.size = sizeof(userIdData);
    processInfo->userId.data = (uint8_t *)HksMalloc(sizeof(userIdData));
    if (processInfo->userId.data != nullptr) {
        (void)memcpy_s(processInfo->userId.data, sizeof(userIdData), userIdData, sizeof(userIdData));
    }
    processInfo->processName.size = sizeof(processNameData);
    processInfo->processName.data = (uint8_t *)HksMalloc(sizeof(processNameData));
    if (processInfo->processName.data != nullptr) {
        (void)memcpy_s(processInfo->processName.data, sizeof(processNameData), processNameData, sizeof(processNameData));
    }
    processInfo->accessTokenId = 0;
    processInfo->pid = 0;
}

static void FreeProcessInfo(struct HksProcessInfo *processInfo)
{
    if (processInfo != nullptr) {
        HKS_FREE_BLOB(processInfo->userId);
        HKS_FREE_BLOB(processInfo->processName);
    }
}

static uint64_t BuildSeHandle(uint64_t baseHandle)
{
    return baseHandle | (1ULL << HKS_SE_HANDLE_MASK_BIT);
}

static void CreateAndCleanSeOperation(struct HksProcessInfo *processInfo, struct HksParamSet *paramSet, uint64_t handle)
{
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handle };
    (void)HksCreateSeOperation(processInfo, paramSet, &operationHandle);
    struct HksSeOperation *op = HksQuerySeOperationAndMarkInUse(processInfo, &operationHandle);
    if (op != nullptr) {
        HksMarkSeOperationUnUse(op);
    }
    HksDeleteSeOperation(&operationHandle);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerCreateSeOperation001, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_NE(operation, nullptr);
    if (operation != nullptr) {
        ASSERT_EQ(operation->handle, handleValue);
        EXPECT_TRUE(operation->isInUse);
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerCreateSeOperation002, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksCreateSeOperation(&processInfo, paramSet, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerCreateSeOperation003, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t smallData[4] = {0};
    struct HksBlob smallHandle = { 4, smallData };

    ret = HksCreateSeOperation(&processInfo, paramSet, &smallHandle);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerCreateSeOperation004, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t nonSeHandle = 12345;
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&nonSeHandle };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerCreateSeOperation006, TestSize.Level0)
{
    struct HksProcessInfo processInfo1;
    BuildProcessInfo(&processInfo1, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handle1 = BuildSeHandle(11111);
    struct HksBlob operationHandle1 = { sizeof(uint64_t), (uint8_t *)&handle1 };

    ret = HksCreateSeOperation(&processInfo1, paramSet, &operationHandle1);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksProcessInfo processInfo2;
    BuildProcessInfo(&processInfo2, 100, 201);

    uint64_t handle2 = BuildSeHandle(22222);
    struct HksBlob operationHandle2 = { sizeof(uint64_t), (uint8_t *)&handle2 };

    ret = HksCreateSeOperation(&processInfo2, paramSet, &operationHandle2);
    ASSERT_EQ(ret, HKS_ERROR_SESSION_REACHED_LIMIT);

    HksDeleteSeOperation(&operationHandle1);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo1);
    FreeProcessInfo(&processInfo2);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerQuerySeOperation001, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_NE(operation, nullptr);
    if (operation != nullptr) {
        EXPECT_TRUE(operation->isInUse);
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerQuerySeOperation002, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, nullptr);
    ASSERT_EQ(operation, nullptr);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerQuerySeOperation003, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    uint64_t nonSeHandle = 12345;
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&nonSeHandle };

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_EQ(operation, nullptr);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerQuerySeOperation004, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    uint64_t handleValue = BuildSeHandle(99999);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_EQ(operation, nullptr);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerQuerySeOperation005, TestSize.Level0)
{
    struct HksProcessInfo processInfo1;
    BuildProcessInfo(&processInfo1, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo1, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksProcessInfo processInfo2;
    BuildProcessInfo(&processInfo2, 200, 200);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo2, &operationHandle);
    ASSERT_EQ(operation, nullptr);

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo1);
    FreeProcessInfo(&processInfo2);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerQuerySeOperation006, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation1 = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_NE(operation1, nullptr);

    struct HksSeOperation *operation2 = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_EQ(operation2, nullptr);

    if (operation1 != nullptr) {
        HksMarkSeOperationUnUse(operation1);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerQuerySeOperation007, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation1 = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_NE(operation1, nullptr);
    if (operation1 != nullptr) {
        HksMarkSeOperationUnUse(operation1);
    }

    struct HksSeOperation *operation2 = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_NE(operation2, nullptr);
    if (operation2 != nullptr) {
        HksMarkSeOperationUnUse(operation2);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerMarkUnUse001, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_NE(operation, nullptr);
    EXPECT_TRUE(operation->isInUse);

    HksMarkSeOperationUnUse(operation);

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerMarkUnUse002, TestSize.Level0)
{
    HksMarkSeOperationUnUse(nullptr);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerMarkUnUse003, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_NE(operation, nullptr);

    HksMarkSeOperationUnUse(operation);
    HksMarkSeOperationUnUse(operation);

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteSeOperation001, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_NE(operation, nullptr);
    HksMarkSeOperationUnUse(operation);

    HksDeleteSeOperation(&operationHandle);

    operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_EQ(operation, nullptr);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteSeOperation002, TestSize.Level0)
{
    HksDeleteSeOperation(nullptr);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteSeOperation003, TestSize.Level0)
{
    uint64_t nonSeHandle = 12345;
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&nonSeHandle };

    HksDeleteSeOperation(&operationHandle);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteSeOperation004, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    uint64_t handleValue = BuildSeHandle(99999);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    HksDeleteSeOperation(&operationHandle);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteSeOperation005, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_NE(operation, nullptr);

    HksDeleteSeOperation(&operationHandle);

    struct HksSeOperation *operationAfterDelete = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_EQ(operationAfterDelete, nullptr);

    HksMarkSeOperationUnUse(operation);
    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteSeOperation006, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handle1 = BuildSeHandle(11111);
    struct HksBlob operationHandle1 = { sizeof(uint64_t), (uint8_t *)&handle1 };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle1);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle1);
    ASSERT_NE(operation, nullptr);
    HksMarkSeOperationUnUse(operation);

    HksDeleteSeOperation(&operationHandle1);

    uint64_t handle2 = BuildSeHandle(22222);
    struct HksBlob operationHandle2 = { sizeof(uint64_t), (uint8_t *)&handle2 };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle2);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksDeleteSeOperation(&operationHandle2);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteByProcessInfo001, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_NE(operation, nullptr);
    HksMarkSeOperationUnUse(operation);

    HksDeleteSeSessionByProcessInfo(&processInfo);

    operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_EQ(operation, nullptr);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteByProcessInfo002, TestSize.Level0)
{
    struct HksProcessInfo processInfo1;
    BuildProcessInfo(&processInfo1, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo1, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksProcessInfo processInfo2;
    BuildProcessInfo(&processInfo2, 200, 300);

    HksDeleteSeSessionByProcessInfo(&processInfo2);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo1, &operationHandle);
    EXPECT_NE(operation, nullptr);
    if (operation != nullptr) {
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo1);
    FreeProcessInfo(&processInfo2);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteByProcessInfo003, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_NE(operation, nullptr);

    HksDeleteSeSessionByProcessInfo(&processInfo);

    struct HksSeOperation *operationAfterDelete = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_EQ(operationAfterDelete, nullptr);

    HksMarkSeOperationUnUse(operation);
    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteByProcessInfo004, TestSize.Level0)
{
    struct HksProcessInfo processInfo1;
    BuildProcessInfo(&processInfo1, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo1, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksProcessInfo processInfo2;
    BuildProcessInfo(&processInfo2, 100, 300);

    HksDeleteSeSessionByProcessInfo(&processInfo2);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo1, &operationHandle);
    EXPECT_NE(operation, nullptr);
    if (operation != nullptr) {
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo1);
    FreeProcessInfo(&processInfo2);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerLifeCycleTest001, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_NE(operation, nullptr);
    ASSERT_EQ(operation->handle, handleValue);
    EXPECT_TRUE(operation->isInUse);

    HksMarkSeOperationUnUse(operation);

    operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_NE(operation, nullptr);
    HksMarkSeOperationUnUse(operation);

    HksDeleteSeOperation(&operationHandle);

    operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    ASSERT_EQ(operation, nullptr);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

static constexpr uint32_t CONCURRENT_THREAD_NUM = 4;
static constexpr uint32_t CONCURRENT_TEST_ROUND = 10;

static void ConcurrentCreateAndQuery(struct HksProcessInfo *processInfo, struct HksParamSet *paramSet,
    uint64_t baseHandle, uint32_t threadId)
{
    for (uint32_t i = 0; i < CONCURRENT_TEST_ROUND; ++i) {
        uint64_t handle = BuildSeHandle(baseHandle + threadId * 1000 + i);
        struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handle };

        int32_t ret = HksCreateSeOperation(processInfo, paramSet, &operationHandle);
        if (ret == HKS_SUCCESS) {
            struct HksSeOperation *op = HksQuerySeOperationAndMarkInUse(processInfo, &operationHandle);
            if (op != nullptr) {
                HksMarkSeOperationUnUse(op);
            }
            HksDeleteSeOperation(&operationHandle);
        }
    }
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerConcurrentTest001, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    std::thread threads[CONCURRENT_THREAD_NUM];
    for (uint32_t i = 0; i < CONCURRENT_THREAD_NUM; ++i) {
        threads[i] = std::thread(ConcurrentCreateAndQuery, &processInfo, paramSet, 10000, i);
    }

    for (uint32_t i = 0; i < CONCURRENT_THREAD_NUM; ++i) {
        threads[i].join();
    }

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerConcurrentTest002, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handle = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handle };

    std::mutex mtx;
    std::condition_variable cv;
    bool ready = false;
    int32_t successCount = 0;

    std::thread threads[CONCURRENT_THREAD_NUM];
    for (uint32_t i = 0; i < CONCURRENT_THREAD_NUM; ++i) {
        threads[i] = std::thread([&]() {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [&]() { return ready; });
            lock.unlock();

            int32_t createRet = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
            if (createRet == HKS_SUCCESS) {
                successCount++;
            }

            struct HksSeOperation *op = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
            if (op != nullptr) {
                HksMarkSeOperationUnUse(op);
            }

            HksDeleteSeOperation(&operationHandle);
        });
    }

    {
        std::lock_guard<std::mutex> lock(mtx);
        ready = true;
    }
    cv.notify_all();

    for (uint32_t i = 0; i < CONCURRENT_THREAD_NUM; ++i) {
        threads[i].join();
    }

    EXPECT_LE(successCount, 1);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerSmallHandleSizeTest001, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t smallData[2] = {0};
    struct HksBlob smallHandle = { 2, smallData };

    ret = HksCreateSeOperation(&processInfo, paramSet, &smallHandle);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerQuerySmallHandleSizeTest001, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    uint8_t smallData[2] = {0};
    struct HksBlob smallHandle = { 2, smallData };

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &smallHandle);
    ASSERT_EQ(operation, nullptr);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteSmallHandleSizeTest001, TestSize.Level0)
{
    uint8_t smallData[2] = {0};
    struct HksBlob smallHandle = { 2, smallData };

    HksDeleteSeOperation(&smallHandle);
}

}