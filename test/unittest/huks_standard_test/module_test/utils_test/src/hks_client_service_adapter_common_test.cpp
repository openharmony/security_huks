/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "hks_client_service_adapter_common_test.h"

#include <gtest/gtest.h>
#include <string>

#include "base/security/huks/utils/crypto_adapter/hks_client_service_adapter_common.c"
#include "file_ex.h"
#include "hks_log.h"
#include "hks_mem.h"
#include "hks_param.h"
#include "hks_three_stage_test_common.h"
#include "hks_type_inner.h"

using namespace testing::ext;
namespace Unittest::HksClientServiceAdapterCommonTest {
class HksClientServiceAdapterCommonTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HksClientServiceAdapterCommonTest::SetUpTestCase(void)
{
}

void HksClientServiceAdapterCommonTest::TearDownTestCase(void)
{
}

void HksClientServiceAdapterCommonTest::SetUp()
{
}

void HksClientServiceAdapterCommonTest::TearDown()
{
}

/**
 * @tc.name: HksClientServiceAdapterCommonTest.HksClientServiceAdapterCommonTest001
 * @tc.desc: tdd HksClientServiceAdapterCommonTest001, function is CopyToInnerKey
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceAdapterCommonTest, HksClientServiceAdapterCommonTest001, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceAdapterCommonTest001");
    HksBlob key = {
        .size = 0,
        .data = nullptr,
    };
    int32_t ret = CopyToInnerKey(&key, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterCommonTest001 failed, ret = " << ret;

    key.size = MAX_KEY_SIZE + 1;
    ret = CopyToInnerKey(&key, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterCommonTest001 failed, ret = " << ret;
}

/**
 * @tc.name: HksClientServiceAdapterCommonTest.HksClientServiceAdapterCommonTest002
 * @tc.desc: tdd HksClientServiceAdapterCommonTest002, function is TranslateToInnerCurve25519Format
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceAdapterCommonTest, HksClientServiceAdapterCommonTest002, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceAdapterCommonTest002");
    HksBlob key = {
        .size = 0,
        .data = nullptr,
    };
    int32_t ret = TranslateToInnerCurve25519Format(HKS_ALG_RSA, &key, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_KEY_INFO) << "HksClientServiceAdapterCommonTest002 failed, ret = " << ret;
}

/**
 * @tc.name: HksClientServiceAdapterCommonTest.HksClientServiceAdapterCommonTest003
 * @tc.desc: tdd HksClientServiceAdapterCommonTest003, function is GetHksPubKeyInnerFormat
 * @tc.type: FUNC
 */
HWTEST_F(HksClientServiceAdapterCommonTest, HksClientServiceAdapterCommonTest003, TestSize.Level0)
{
    HKS_LOG_I("enter HksClientServiceAdapterCommonTest003");
    int32_t ret = GetHksPubKeyInnerFormat(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterCommonTest003 failed, ret = " << ret;
    HksBlob key = {
        .size = sizeof(HksBlob),
        .data = reinterpret_cast<uint8_t *>(HksMalloc(sizeof(HksBlob))),
    };
    ret = GetHksPubKeyInnerFormat(nullptr, &key, nullptr);
    ASSERT_EQ(ret, HKS_ERROR_INVALID_ARGUMENT) << "HksClientServiceAdapterCommonTest003 failed, ret = " << ret;
    HKS_FREE(key.data);
}
}