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

#include "hks_keyblob_test.h"

#include <gtest/gtest.h>
#include <string>

#include "base/security/huks/services/huks_standard/huks_engine/main/core/src/hks_keyblob.c"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksKeyBlobTest {
class HksKeyBlobTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksKeyBlobTest::SetUpTestCase(void)
{
}

void HksKeyBlobTest::TearDownTestCase(void)
{
}

void HksKeyBlobTest::SetUp()
{
}

void HksKeyBlobTest::TearDown()
{
}

#ifdef HKS_ENABLE_UPGRADE_KEY
/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest001
 * @tc.desc: tdd HksBuildKeyBlobWithOutAddKeyParam, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest001");
    uint32_t exceedCnt = HKS_DEFAULT_PARAM_CNT + 1;
    struct HksParamSet paramSet = { .paramSetSize = 0, .paramsCnt = exceedCnt, .params = {} };
    int32_t ret = HksBuildKeyBlobWithOutAddKeyParam(&paramSet, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest002
 * @tc.desc: tdd HksBuildKeyBlob2, expect HKS_ERROR_INVALID_ARGUMENT
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest002");
    int32_t ret = HksBuildKeyBlob2(nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: HksKeyBlobTest.HksKeyBlobTest003
 * @tc.desc: tdd HksBuildKeyBlob2, expect HKS_ERROR_INVALID_KEY_INFO
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyBlobTest, HksKeyBlobTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyBlobTest003");
    uint8_t blobArray[] = { 0 };
    struct HksParam keyParam = { .tag = HKS_TAG_KEY, .blob = { .size = HKS_ARRAY_SIZE(blobArray), .data = blobArray } };
    struct HksParamSet *paramSet = nullptr;
    int32_t ret = HksInitParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksAddParams(paramSet, &keyParam, 1);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildParamSet(&paramSet);
    ASSERT_EQ(ret, HKS_SUCCESS);
    ret = HksBuildKeyBlob2(paramSet, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO);
}
#endif
}