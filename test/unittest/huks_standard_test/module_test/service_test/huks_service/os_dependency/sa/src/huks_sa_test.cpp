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

#include "hks_log.h"
#include "hks_sa.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::Hks;
namespace Unittest::HksSaTest {
class HksSaTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksSaTest::SetUpTestCase(void)
{
}

void HksSaTest::TearDownTestCase(void)
{
}

void HksSaTest::SetUp()
{
}

void HksSaTest::TearDown()
{
}

/**
 * @tc.name: HksSaTest.HksSaTest001
 * @tc.desc: tdd HksService::OnRemoteRequest HKS_MSG_GEN_KEY, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSaTest, HksSaTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest001");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    hksService.OnRemoteRequest(HKS_MSG_GEN_KEY, data, reply, option);
}

/**
 * @tc.name: HksSaTest.HksSaTest002
 * @tc.desc: tdd HksService::OnRemoteRequest HKS_MSG_ATTEST_KEY, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSaTest, HksSaTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest002");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    hksService.OnRemoteRequest(HKS_MSG_ATTEST_KEY, data, reply, option);
}

/**
 * @tc.name: HksSaTest.HksSaTest003
 * @tc.desc: tdd HksService::OnRemoteRequest HKS_MSG_ATTEST_KEY_ASYNC_REPLY, expect HKS_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HksSaTest, HksSaTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksSaTest003");
    HksService hksService(0, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    hksService.OnRemoteRequest(HKS_MSG_ATTEST_KEY_ASYNC_REPLY, data, reply, option);
}
}
