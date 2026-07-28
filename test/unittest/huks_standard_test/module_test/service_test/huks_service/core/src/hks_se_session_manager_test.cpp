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
namespace Unittest::HksSeSessionManagerTest {

class HksSeSessionManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static void CleanUpSeOperations();
};

void HksSeSessionManagerTest::SetUpTestCase(void) {}

void HksSeSessionManagerTest::TearDownTestCase(void) {}

void HksSeSessionManagerTest::SetUp()
{
    CleanUpSeOperations();
}

void HksSeSessionManagerTest::TearDown()
{
    CleanUpSeOperations();
}

static uint64_t BuildSeHandle(uint64_t baseHandle)
{
    return baseHandle | (1ULL << HKS_SE_HANDLE_MASK_BIT);
}

static int32_t BuildParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramCount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    if (params != nullptr && paramCount > 0) {
        ret = HksAddParams(*paramSet, params, paramCount);
        if (ret != HKS_SUCCESS) {
            HksFreeParamSet(paramSet);
            return ret;
        }
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
    } else {
        processInfo->userId.size = 0;
    }
    processInfo->processName.size = sizeof(processNameData);
    processInfo->processName.data = (uint8_t *)HksMalloc(sizeof(processNameData));
    if (processInfo->processName.data != nullptr) {
        (void)memcpy_s(processInfo->processName.data, sizeof(processNameData), processNameData, sizeof(processNameData));
    } else {
        processInfo->processName.size = 0;
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

void HksSeSessionManagerTest::CleanUpSeOperations()
{
    uint64_t handle = BuildSeHandle(1);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handle };
    for (uint32_t i = 1; i <= 100; i++) {
        handle = BuildSeHandle(i);
        operationHandle.data = (uint8_t *)&handle;
        HksDeleteSeOperation(&operationHandle);
    }
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperation001, TestSize.Level0)
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
        EXPECT_EQ(operation->handle, handleValue);
        EXPECT_TRUE(operation->isInUse);
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationNullHandle, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    ret = HksCreateSeOperation(&processInfo, paramSet, nullptr);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationSmallHandleSize, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t smallData[4] = {0};
    struct HksBlob smallHandle = { 4, smallData };

    ret = HksCreateSeOperation(&processInfo, paramSet, &smallHandle);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationVerySmallHandleSize, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t smallData[2] = {0};
    struct HksBlob smallHandle = { 2, smallData };

    ret = HksCreateSeOperation(&processInfo, paramSet, &smallHandle);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationZeroHandleSize, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint8_t data[8] = {0};
    struct HksBlob zeroSizeHandle = { 0, data };

    ret = HksCreateSeOperation(&processInfo, paramSet, &zeroSizeHandle);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationNonSeHandle, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t nonSeHandle = 12345;
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&nonSeHandle };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationZeroBaseHandle, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = 0;
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationMaxHandle, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = UINT64_MAX;
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_NE(operation, nullptr);
    if (operation != nullptr) {
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationReachLimit, TestSize.Level0)
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
    EXPECT_EQ(ret, HKS_ERROR_SE_SESSION_EXCEED_LIMIT);

    HksDeleteSeOperation(&operationHandle1);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo1);
    FreeProcessInfo(&processInfo2);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationReachLimitSameProcess, TestSize.Level0)
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

    uint64_t handle2 = BuildSeHandle(22222);
    struct HksBlob operationHandle2 = { sizeof(uint64_t), (uint8_t *)&handle2 };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle2);
    EXPECT_EQ(ret, HKS_SUCCESS);

    HksDeleteSeOperation(&operationHandle1);
    HksDeleteSeOperation(&operationHandle2);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationReachLimitDeleteOtherProcessOp, TestSize.Level0)
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

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo1, &operationHandle1);
    ASSERT_NE(operation, nullptr);
    HksMarkSeOperationUnUse(operation);

    struct HksProcessInfo processInfo2;
    BuildProcessInfo(&processInfo2, 200, 300);

    uint64_t handle2 = BuildSeHandle(22222);
    struct HksBlob operationHandle2 = { sizeof(uint64_t), (uint8_t *)&handle2 };

    ret = HksCreateSeOperation(&processInfo2, paramSet, &operationHandle2);
    EXPECT_EQ(ret, HKS_ERROR_SE_SESSION_EXCEED_LIMIT);

    HksDeleteSeOperation(&operationHandle1);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo1);
    FreeProcessInfo(&processInfo2);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationCreateDeleteCreate, TestSize.Level0)
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

    HksDeleteSeOperation(&operationHandle1);

    uint64_t handle2 = BuildSeHandle(22222);
    struct HksBlob operationHandle2 = { sizeof(uint64_t), (uint8_t *)&handle2 };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle2);
    EXPECT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle2);
    EXPECT_NE(operation, nullptr);
    if (operation != nullptr) {
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle2);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationHandleDataNull, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksBlob operationHandle = { sizeof(uint64_t), nullptr };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    EXPECT_EQ(ret, HKS_ERROR_INSUFFICIENT_MEMORY);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperation001, TestSize.Level0)
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

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperationNullHandle, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, nullptr);
    EXPECT_EQ(operation, nullptr);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperationSmallHandleSize, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    uint8_t smallData[4] = {0};
    struct HksBlob smallHandle = { 4, smallData };

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &smallHandle);
    EXPECT_EQ(operation, nullptr);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperationVerySmallHandleSize, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    uint8_t smallData[2] = {0};
    struct HksBlob smallHandle = { 2, smallData };

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &smallHandle);
    EXPECT_EQ(operation, nullptr);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperationZeroHandleSize, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    uint8_t data[8] = {0};
    struct HksBlob zeroSizeHandle = { 0, data };

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &zeroSizeHandle);
    EXPECT_EQ(operation, nullptr);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperationNonSeHandle, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    uint64_t nonSeHandle = 12345;
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&nonSeHandle };

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_EQ(operation, nullptr);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperationZeroHandle, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    uint64_t handleValue = 0;
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_EQ(operation, nullptr);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperationHandleDataNull, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksBlob operationHandle = { sizeof(uint64_t), nullptr };

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_EQ(operation, nullptr);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperationNotExist, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    uint64_t handleValue = BuildSeHandle(99999);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_EQ(operation, nullptr);

    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperationProcessMismatch, TestSize.Level0)
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
    EXPECT_EQ(operation, nullptr);

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo1);
    FreeProcessInfo(&processInfo2);
}

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperationUidMismatch, TestSize.Level0)
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

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo2, &operationHandle);
    EXPECT_EQ(operation, nullptr);

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo1);
    FreeProcessInfo(&processInfo2);
}

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperationInUse, TestSize.Level0)
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
    EXPECT_EQ(operation2, nullptr);

    if (operation1 != nullptr) {
        HksMarkSeOperationUnUse(operation1);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksQuerySeOperationUnUseAndQueryAgain, TestSize.Level0)
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

HWTEST_F(HksSeSessionManagerTest, HksMarkSeOperationUnUse001, TestSize.Level0)
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
    EXPECT_FALSE(operation->isInUse);

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksMarkSeOperationUnUseNull, TestSize.Level0)
{
    HksMarkSeOperationUnUse(nullptr);
}

HWTEST_F(HksSeSessionManagerTest, HksMarkSeOperationUnUseTwice, TestSize.Level0)
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
    EXPECT_FALSE(operation->isInUse);

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeOperation001, TestSize.Level0)
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
    EXPECT_EQ(operation, nullptr);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeOperationNullHandle, TestSize.Level0)
{
    HksDeleteSeOperation(nullptr);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeOperationSmallHandleSize, TestSize.Level0)
{
    uint8_t smallData[4] = {0};
    struct HksBlob smallHandle = { 4, smallData };

    HksDeleteSeOperation(&smallHandle);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeOperationVerySmallHandleSize, TestSize.Level0)
{
    uint8_t smallData[2] = {0};
    struct HksBlob smallHandle = { 2, smallData };

    HksDeleteSeOperation(&smallHandle);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeOperationZeroHandleSize, TestSize.Level0)
{
    uint8_t data[8] = {0};
    struct HksBlob zeroSizeHandle = { 0, data };

    HksDeleteSeOperation(&zeroSizeHandle);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeOperationNonSeHandle, TestSize.Level0)
{
    uint64_t nonSeHandle = 12345;
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&nonSeHandle };

    HksDeleteSeOperation(&operationHandle);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeOperationZeroHandle, TestSize.Level0)
{
    uint64_t handleValue = 0;
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    HksDeleteSeOperation(&operationHandle);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeOperationHandleDataNull, TestSize.Level0)
{
    struct HksBlob operationHandle = { sizeof(uint64_t), nullptr };

    HksDeleteSeOperation(&operationHandle);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeOperationNotExist, TestSize.Level0)
{
    uint64_t handleValue = BuildSeHandle(99999);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    HksDeleteSeOperation(&operationHandle);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeOperationInUse, TestSize.Level0)
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
    if (operationAfterDelete != nullptr) {
        HksMarkSeOperationUnUse(operationAfterDelete);
    }

    HksMarkSeOperationUnUse(operation);
    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeOperationTwice, TestSize.Level0)
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

    HksDeleteSeOperation(&operationHandle);

    HksDeleteSeOperation(&operationHandle);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeSessionByProcessInfo001, TestSize.Level0)
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
    EXPECT_EQ(operation, nullptr);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeSessionByProcessInfoNotExist, TestSize.Level0)
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

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeSessionByProcessInfoUidMismatch, TestSize.Level0)
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

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeSessionByProcessInfoUserIdMismatch, TestSize.Level0)
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

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeSessionByProcessInfoInUse, TestSize.Level0)
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
    if (operationAfterDelete != nullptr) {
        HksMarkSeOperationUnUse(operationAfterDelete);
    }

    HksMarkSeOperationUnUse(operation);
    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksDeleteSeSessionByProcessInfoMultipleOperations, TestSize.Level0)
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

    HksDeleteSeOperation(&operationHandle1);

    uint64_t handle2 = BuildSeHandle(22222);
    struct HksBlob operationHandle2 = { sizeof(uint64_t), (uint8_t *)&handle2 };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle2);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksDeleteSeSessionByProcessInfo(&processInfo);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle2);
    EXPECT_EQ(operation, nullptr);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionLifeCycle001, TestSize.Level0)
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

HWTEST_F(HksSeSessionManagerTest, HksSeSessionLifeCycleWithProcessInfoDelete, TestSize.Level0)
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

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerConcurrentCreate001, TestSize.Level0)
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

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerConcurrentSameHandle, TestSize.Level0)
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

    EXPECT_LE(successCount, CONCURRENT_THREAD_NUM);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerConcurrentQuery, TestSize.Level0)
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

    std::mutex mtx;
    std::condition_variable cv;
    bool ready = false;
    int32_t querySuccessCount = 0;

    std::thread threads[CONCURRENT_THREAD_NUM];
    for (uint32_t i = 0; i < CONCURRENT_THREAD_NUM; ++i) {
        threads[i] = std::thread([&]() {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [&]() { return ready; });
            lock.unlock();

            struct HksSeOperation *op = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
            if (op != nullptr) {
                querySuccessCount++;
                HksMarkSeOperationUnUse(op);
            }
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

    EXPECT_EQ(querySuccessCount, CONCURRENT_THREAD_NUM);

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerConcurrentDeleteByProcessInfo, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    for (uint32_t i = 0; i < CONCURRENT_THREAD_NUM; ++i) {
        uint64_t handleValue = BuildSeHandle(10000 + i);
        struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };
        ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
        if (ret == HKS_SUCCESS) {
            struct HksSeOperation *op = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
            if (op != nullptr) {
                HksMarkSeOperationUnUse(op);
            }
            HksDeleteSeOperation(&operationHandle);
        }
    }

    HksDeleteSeSessionByProcessInfo(&processInfo);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerEmptyUserIdProcessName, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    processInfo.userIdInt = 100;
    processInfo.uidInt = 200;
    processInfo.userId.size = 0;
    processInfo.userId.data = nullptr;
    processInfo.processName.size = 0;
    processInfo.processName.data = nullptr;
    processInfo.accessTokenId = 0;
    processInfo.pid = 0;

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(12345);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    if (ret == HKS_SUCCESS) {
        struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
        if (operation != nullptr) {
            HksMarkSeOperationUnUse(operation);
        }
        HksDeleteSeOperation(&operationHandle);
    }

    HksFreeParamSet(&paramSet);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerHandleMinValidSeHandle, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = BuildSeHandle(1);
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_NE(operation, nullptr);
    if (operation != nullptr) {
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerHandleJustAboveZero, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = 1ULL << HKS_SE_HANDLE_MASK_BIT;
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
    EXPECT_NE(operation, nullptr);
    if (operation != nullptr) {
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerHandleJustBelowThreshold, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handleValue = (1ULL << HKS_SE_HANDLE_MASK_BIT) - 1;
    struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
    EXPECT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerProcessInfoBoundaryUserIdInt, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, UINT32_MAX, 200);

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
        EXPECT_EQ(operation->processInfo.userIdInt, UINT32_MAX);
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerProcessInfoBoundaryUidInt, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, UINT32_MAX);

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
        EXPECT_EQ(operation->processInfo.uidInt, UINT32_MAX);
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerProcessInfoZeroUserIdUid, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 0, 0);

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
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerCreateTimeStored, TestSize.Level0)
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
        EXPECT_GT(operation->startTime, 0ULL);
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerQueryVerifyProcessInfoCopy, TestSize.Level0)
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
        EXPECT_EQ(operation->processInfo.userIdInt, processInfo.userIdInt);
        EXPECT_EQ(operation->processInfo.uidInt, processInfo.uidInt);
        EXPECT_NE(operation->processInfo.userId.data, nullptr);
        EXPECT_NE(operation->processInfo.processName.data, nullptr);
        EXPECT_EQ(operation->processInfo.userId.size, processInfo.userId.size);
        EXPECT_EQ(operation->processInfo.processName.size, processInfo.processName.size);
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteInUseThenMarkUnUse, TestSize.Level0)
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

    HksMarkSeOperationUnUse(operation);

    HksDeleteSeOperation(&operationHandle);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerDeleteByProcessInfoInUseThenMarkUnUse, TestSize.Level0)
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

    HksMarkSeOperationUnUse(operation);

    HksDeleteSeOperation(&operationHandle);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerMultipleCreateDeleteSameProcess, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    for (uint32_t round = 0; round < 5; ++round) {
        uint64_t handleValue = BuildSeHandle(10000 + round);
        struct HksBlob operationHandle = { sizeof(uint64_t), (uint8_t *)&handleValue };

        ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandle);
        ASSERT_EQ(ret, HKS_SUCCESS);

        struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandle);
        EXPECT_NE(operation, nullptr);
        if (operation != nullptr) {
            HksMarkSeOperationUnUse(operation);
        }

        HksDeleteSeOperation(&operationHandle);
    }

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerQueryAfterDeleteByDifferentProcess, TestSize.Level0)
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

    struct HksSeOperation *operation = HksQuerySeOperationAndMarkInUse(&processInfo1, &operationHandle);
    ASSERT_NE(operation, nullptr);
    HksMarkSeOperationUnUse(operation);

    struct HksProcessInfo processInfo2;
    BuildProcessInfo(&processInfo2, 200, 300);
    HksDeleteSeSessionByProcessInfo(&processInfo2);

    operation = HksQuerySeOperationAndMarkInUse(&processInfo1, &operationHandle);
    EXPECT_NE(operation, nullptr);
    if (operation != nullptr) {
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo1);
    FreeProcessInfo(&processInfo2);
}

HWTEST_F(HksSeSessionManagerTest, HksSeSessionManagerMultipleHandlesSameProcess, TestSize.Level0)
{
    struct HksProcessInfo processInfo;
    BuildProcessInfo(&processInfo, 100, 200);

    struct HksParamSet *paramSet = nullptr;
    int32_t ret = BuildParamSet(&paramSet, nullptr, 0);
    ASSERT_EQ(ret, HKS_SUCCESS);

    uint64_t handles[] = { BuildSeHandle(11111), BuildSeHandle(22222), BuildSeHandle(33333) };
    struct HksBlob operationHandles[3];
    for (int i = 0; i < 3; i++) {
        operationHandles[i].size = sizeof(uint64_t);
        operationHandles[i].data = (uint8_t *)&handles[i];
    }

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandles[0]);
    ASSERT_EQ(ret, HKS_SUCCESS);

    HksDeleteSeOperation(&operationHandles[0]);

    ret = HksCreateSeOperation(&processInfo, paramSet, &operationHandles[1]);
    ASSERT_EQ(ret, HKS_SUCCESS);

    struct HksSeOperation *operation1 = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandles[1]);
    EXPECT_NE(operation1, nullptr);

    struct HksSeOperation *operation2 = HksQuerySeOperationAndMarkInUse(&processInfo, &operationHandles[1]);
    EXPECT_EQ(operation2, nullptr);

    if (operation1 != nullptr) {
        HksMarkSeOperationUnUse(operation1);
    }
    HksDeleteSeOperation(&operationHandles[1]);

    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksCreateSeOperationEventInfoAndErrMsgBlobInit, TestSize.Level0)
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
        EXPECT_EQ(operation->errMsgBlob.size, 0);
        EXPECT_EQ(operation->errMsgBlob.data, nullptr);
        EXPECT_EQ(operation->eventInfo.common.eventId, 0);
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

HWTEST_F(HksSeSessionManagerTest, HksSeOperationErrMsgBlobWriteAndFree, TestSize.Level0)
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
        operation->errMsgBlob.data = (uint8_t *)HksMalloc(4);
        operation->errMsgBlob.size = 4;
        if (operation->errMsgBlob.data != nullptr) {
            (void)memcpy_s(operation->errMsgBlob.data, 4, "test", 4);
        }
        HksMarkSeOperationUnUse(operation);
    }

    HksDeleteSeOperation(&operationHandle);
    HksFreeParamSet(&paramSet);
    FreeProcessInfo(&processInfo);
}

}
