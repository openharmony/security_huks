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

#include "hks_attestkey_test.h"

#include <gtest/gtest.h>

#include "hks_attest.h"

#include "hks_log.h"
#include "hks_mem.h"
#include "hks_cmd_id.h"
#include "hks_type.h"

#include <cstring>

using namespace testing::ext;
namespace Unittest::HksServiceKeyAttestationTest {
class HksKeyAttestationTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksKeyAttestationTest::SetUpTestCase(void)
{
}

void HksKeyAttestationTest::TearDownTestCase(void)
{
}

void HksKeyAttestationTest::SetUp()
{
}

void HksKeyAttestationTest::TearDown()
{
}

/**
 * @tc.name: HksKeyAttestationTest.HksKeyAttest001
 * @tc.desc: test HksSoftAttestKey
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyAttestationTest, HksKeyAttest001, TestSize.Level0)
{
    // invalid certchain size
    uint8_t buffer[HKS_ATTEST_CERT_SIZE - 1] = {0};
    struct HksBlob blob = { HKS_ATTEST_CERT_SIZE - 1, buffer };
    int32_t ret = HksSoftAttestKey(&blob, nullptr, &blob);
    ASSERT_NE(ret, HKS_SUCCESS) << "HksSoftAttestKey success" << ret;
}

/**
 * @tc.name: HksKeyAttestationTest.HksKeyAttest002
 * @tc.desc: test HksSoftAttestKey
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyAttestationTest, HksKeyAttest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyAttest002");
    int32_t ret = HksSoftAttestKey(nullptr, nullptr, nullptr);
    ASSERT_NE(ret, HKS_SUCCESS) << "HksSoftAttestKey success" << ret;
}

/**
 * @tc.name: HksKeyAttestationTest.HksKeyAttest003
 * @tc.desc: test HksSoftAttestKey
 * @tc.type: FUNC
 */
HWTEST_F(HksKeyAttestationTest, HksKeyAttest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksKeyAttest003");
    // invalid paramSet
    uint8_t buffer[HKS_ATTEST_CERT_SIZE] = {0};
    struct HksBlob blob = {HKS_ATTEST_CERT_SIZE, buffer};
    int32_t ret = HksSoftAttestKey(&blob, nullptr, &blob);
    ASSERT_NE(ret, HKS_SUCCESS) << "HksSoftAttestKey not null pointer" << ret;
}
}
