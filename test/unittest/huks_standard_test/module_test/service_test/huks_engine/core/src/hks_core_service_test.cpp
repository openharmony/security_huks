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

#include "hks_core_service_test.h"

#include <gtest/gtest.h>
#include <string>

#include "hks_core_service.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksCoreServiceTest {
class HksCoreServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksCoreServiceTest::SetUpTestCase(void)
{
}

void HksCoreServiceTest::TearDownTestCase(void)
{
}

void HksCoreServiceTest::SetUp()
{
}

void HksCoreServiceTest::TearDown()
{
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest001
 * @tc.desc: tdd HksCoreAbort, expect ret == HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest001");
    int32_t ret = HksCoreAbort(nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest002
 * @tc.desc: tdd HksCoreAbort, expect ret == HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest002");
    struct HksBlob handle = { .size = sizeof(uint64_t) * 2, .data = nullptr };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCoreAbort(&handle, paramSet);
    ASSERT_TRUE(ret == HKS_ERROR_INSUFFICIENT_MEMORY);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest003
 * @tc.desc: tdd HksCoreFinish, expect ret == HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest003");
    int32_t ret = HksCoreFinish(nullptr, nullptr, nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest004
 * @tc.desc: tdd HksCoreFinish, expect ret == HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest004, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest004");
    struct HksBlob handle = { .size = sizeof(uint64_t) * 2, .data = nullptr };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksBlob inData = { 0 };
    ret = HksCoreFinish(&handle, paramSet, &inData, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INSUFFICIENT_MEMORY);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest005
 * @tc.desc: tdd HksCoreFinish, expect ret == HKS_ERROR_BAD_STATE
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest005, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest005");
    uint64_t handleData = 0;
    struct HksBlob handle = { .size = sizeof(uint64_t), .data = (uint8_t *)&handleData };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksBlob inData = { 0 };
    ret = HksCoreFinish(&handle, paramSet, &inData, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_BAD_STATE);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest006
 * @tc.desc: tdd HksCoreUpdate, expect ret == HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest006, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest006");
    int32_t ret = HksCoreUpdate(nullptr, nullptr, nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest007
 * @tc.desc: tdd HksCoreUpdate, expect ret == HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest007, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest007");
    uint64_t handleData = 0;
    struct HksBlob handle = { .size = sizeof(uint64_t) * 2, .data = (uint8_t *)&handleData };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    struct HksBlob inData = { 0 };
    ret = HksCoreUpdate(&handle, paramSet, &inData, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_INSUFFICIENT_MEMORY);
    HksFreeParamSet(&paramSet);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest008
 * @tc.desc: tdd HksCoreInit, expect ret == HKS_ERROR_NULL_POINTER
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest008, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest008");
    int32_t ret = HksCoreInit(nullptr, nullptr, nullptr, nullptr);
    ASSERT_TRUE(ret == HKS_ERROR_NULL_POINTER);
}

/**
 * @tc.name: HksCoreServiceTest.HksCoreServiceTest009
 * @tc.desc: tdd HksCoreInit, expect ret == HKS_ERROR_INSUFFICIENT_MEMORY
 * @tc.type: FUNC
 */
HWTEST_F(HksCoreServiceTest, HksCoreServiceTest009, TestSize.Level0)
{
    HKS_LOG_I("enter HksCoreServiceTest009");
    uint64_t handleData = 0;
    struct HksBlob handle = { .size = sizeof(uint32_t), .data = (uint8_t *)&handleData };
    struct HksBlob token = { 0 };
    struct HksBlob key = { 0 };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_TRUE(ret == HKS_SUCCESS);
    ret = HksCoreInit(&key, paramSet, &handle, &token);
    ASSERT_TRUE(ret == HKS_ERROR_INSUFFICIENT_MEMORY);
    HksFreeParamSet(&paramSet);
}
}
